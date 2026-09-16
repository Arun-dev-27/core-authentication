import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AuditService } from '@core/audit/audit.service';
import { AssertionService } from '@modules/assertions/services/assertion.service';
import { AuthzClient } from '@modules/authorization-client/services/authz-client.service';
import { ClientRegistry } from '@modules/clients/services/client-registry.service';
import { FederationSessionService } from '@modules/sessions/services/federation-session.service';

const ATTEMPTS = 3;
const TIMEOUT_MS = 5000;

type RevokedSession = { sid: string; its_id: string; clients: string[] };

/**
 * Federation-wide logout: revoke the central session, then notify every application that
 * received an assertion for that `sid` via a signed back-channel logout token.
 * Each application then destroys its own local sessions for the sid.
 */
@Injectable()
export class LogoutService {
  private readonly logger = new Logger(LogoutService.name);
  private readonly inFlight = new Set<Promise<void>>();

  constructor(
    private readonly sessions: FederationSessionService,
    private readonly registry: ClientRegistry,
    private readonly assertions: AssertionService,
    private readonly audit: AuditService,
    private readonly authz: AuthzClient,
    @InjectDataSource() private readonly db: DataSource,
  ) {}

  async logoutSession(sid: string, reason: string, meta: { ip?: string } = {}): Promise<RevokedSession | null> {
    const revoked = await this.sessions.revoke(sid, reason);
    if (!revoked) return null;
    await this.audit.record({ eventType: 'FEDERATION_LOGOUT', outcome: 'SUCCESS', itsId: revoked.its_id, sid, ip: meta.ip, metadata: { reason, clients: revoked.clients } });
    // Refuse this session's access tokens in the Authorization service as well, not only its cookie here.
    this.track(this.authz.revokeSession(sid));
    this.track(this.fanOut(revoked));
    return revoked;
  }

  async logoutUser(itsId: string, reason: string): Promise<RevokedSession[]> {
    const revoked = await this.sessions.revokeAllForUser(itsId, reason);
    for (const session of revoked) {
      await this.audit.record({ eventType: 'FEDERATION_LOGOUT', outcome: 'SUCCESS', itsId, sid: session.sid, metadata: { reason, clients: session.clients } });
      this.track(this.authz.revokeSession(session.sid));
      this.track(this.fanOut(session));
    }
    return revoked;
  }

  /** Waits for pending back-channel deliveries (graceful shutdown, tests). */
  async drain(): Promise<void> {
    await Promise.allSettled([...this.inFlight]);
  }

  private track(promise: Promise<void>) {
    this.inFlight.add(promise);
    void promise.finally(() => this.inFlight.delete(promise));
  }

  private async fanOut(session: RevokedSession): Promise<void> {
    await Promise.allSettled(session.clients.map((clientId) => this.notifyClient(session, clientId)));
  }

  private async notifyClient(session: RevokedSession, clientId: string): Promise<void> {
    let status: 'SUCCEEDED' | 'FAILED' | 'NO_ENDPOINT' = 'FAILED';
    let detail: string | undefined;
    try {
      const client = await this.registry.get(clientId);
      if (!client.back_channel_logout_uri || client.status === 'RETIRED') {
        status = 'NO_ENDPOINT';
      } else {
        const { token, jti } = await this.assertions.issueLogoutToken({ itsId: session.its_id, clientId, sid: session.sid });
        for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
          try {
            const res = await fetch(client.back_channel_logout_uri, {
              method: 'POST',
              headers: { 'content-type': 'application/x-www-form-urlencoded', 'cache-control': 'no-store' },
              body: new URLSearchParams({ logout_token: token }).toString(),
              redirect: 'manual',
              signal: AbortSignal.timeout(TIMEOUT_MS),
            });
            if (res.ok) {
              status = 'SUCCEEDED';
              detail = `jti:${jti}`;
              break;
            }
            detail = `http_${res.status}`;
            if (res.status >= 400 && res.status < 500) break; // client rejected the token; retrying will not help
          } catch (error) {
            detail = error instanceof Error ? error.name : 'error';
          }
          if (attempt < ATTEMPTS) await new Promise((r) => setTimeout(r, 250 * 2 ** attempt));
        }
      }
    } catch (error) {
      detail = error instanceof Error ? error.message : 'error';
    }

    await this.db
      .query(`UPDATE auth_session_clients SET logout_status = $3, logout_at = now() WHERE sid = $1 AND client_id = $2`, [session.sid, clientId, status])
      .catch(() => undefined);
    await this.audit.record({
      eventType: 'BACKCHANNEL_LOGOUT',
      outcome: status === 'FAILED' ? 'FAILURE' : status === 'SUCCEEDED' ? 'SUCCESS' : 'INFO',
      itsId: session.its_id,
      sid: session.sid,
      clientId,
      metadata: { status, detail },
    });
    if (status === 'FAILED') this.logger.warn({ msg: 'back-channel logout failed', client_id: clientId, sid: session.sid, detail });
  }
}
