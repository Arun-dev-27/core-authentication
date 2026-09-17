import { Injectable } from '@nestjs/common';
import { AppConfig } from '@config/config.module';
import { DomainError, Errors } from '@common/errors/domain-error';
import { safeEqual } from '@common/utils/crypto.util';
import { canonicalOrigin } from '@common/utils/origin.util';
import { AuditService } from '@core/audit/audit.service';
import { AssertionService } from '@modules/assertions/services/assertion.service';
import { assertClientCanAuthenticate } from '@modules/clients/services/client-policy';
import { ClientRegistry } from '@modules/clients/services/client-registry.service';
import { CredentialService, identifierHash } from '@modules/credentials/services/credential.service';
import { LogoutService } from '@modules/federation/services/logout.service';
import { LoginThrottleService } from '@modules/rate-limit/services/login-throttle.service';
import { FederationSessionService } from '@modules/sessions/services/federation-session.service';
import { TransactionService } from '@modules/transactions/services/transaction.service';
import { AuthenticatedUser, IdentityType } from '@shared/types/auth.types';
import { RequestMeta } from '@shared/types/request-meta.types';
import { FederationSession } from '@shared/types/session.types';
import { LoginTransaction } from '@shared/types/transaction.types';

export interface PasswordLoginInput {
  transactionId: string;
  clientId: string | null;
  identifier: string;
  identityType: IdentityType;
  password: string;
}

export interface AssertionDelivery {
  type: 'MIQAAT_AUTH_SUCCESS';
  transaction_id: string;
  state: string;
  /** Complete compact JWS (header.payload.signature) - forwarded unchanged to the BU backend. */
  core_assertion: string;
  delivery: 'post_message' | 'form_post';
  target_origin?: string;
  callback_uri?: string;
}

export interface LoginOutcome {
  session: FederationSession;
  /** Present when a new cookie handle must be set. */
  handle?: string;
  cookieMaxAge: number;
  delivery?: AssertionDelivery;
}

@Injectable()
export class LoginService {
  constructor(
    private readonly transactions: TransactionService,
    private readonly registry: ClientRegistry,
    private readonly credentials: CredentialService,
    private readonly throttle: LoginThrottleService,
    private readonly sessions: FederationSessionService,
    private readonly assertions: AssertionService,
    private readonly logout: LogoutService,
    private readonly audit: AuditService,
    private readonly config: AppConfig,
  ) {}

  /** POST /embed/login and POST /portal/login */
  async loginWithPassword(input: PasswordLoginInput, meta: RequestMeta): Promise<LoginOutcome> {
    this.assertSameOrigin(meta);
    const txn = await this.transactions.requirePending(input.transactionId, input.clientId);
    if (!safeEqual(meta.csrf, txn.csrf)) throw Errors.csrf(meta.csrf ? 'CSRF_TOKEN_MISMATCH' : 'CSRF_TOKEN_MISSING');
    if ((input.clientId === null) !== (txn.display === 'portal')) throw Errors.transactionInvalid();
    if (input.clientId) await this.revalidateClient(txn);

    const idHash = identifierHash(input.identifier, input.identityType);
    await this.throttle.assertAllowed(meta.ip, idHash);

    let user: AuthenticatedUser;
    try {
      // input.clientId is set exactly for the flows that end in an RS256 assertion for a
      // client (the Embedded Login); portal login passes null and keeps its existing behaviour.
      user = await this.credentials.verify(
        input.identifier,
        input.identityType,
        input.password,
        { ip: meta.ip, clientId: input.clientId },
        input.clientId !== null
          ? { requireMhpEligibility: true, passwordSource: this.config.env.EMBEDDED_LOGIN_PASSWORD_SOURCE }
          : { requireMhpEligibility: false, passwordSource: 'scrypt' },
      );
    } catch (error) {
      if (error instanceof DomainError && error.code === 'INVALID_CREDENTIALS') await this.throttle.recordFailure(idHash);
      await this.audit.record({
        eventType: 'LOGIN_FAILED',
        outcome: 'FAILURE',
        clientId: input.clientId,
        ip: meta.ip,
        userAgent: meta.userAgent,
        metadata: { reason: error instanceof DomainError ? error.code : 'ERROR', identity_type: input.identityType },
      });
      throw error;
    }
    await this.throttle.recordSuccess(idHash);

    const { session, handle, cookieMaxAge } = await this.establishSession(user, meta);
    await this.audit.record({ eventType: 'LOGIN_SUCCEEDED', outcome: 'SUCCESS', itsId: user.itsId, sid: session.sid, clientId: input.clientId, ip: meta.ip, userAgent: meta.userAgent });

    if (!input.clientId) {
      await this.transactions.complete(txn.transaction_id);
      await this.transactions.bindToSession(txn.transaction_id, session, true);
      return { session, handle, cookieMaxAge };
    }
    const delivery = await this.issueForTransaction(txn, session, 'password');
    return { session, handle, cookieMaxAge, delivery };
  }

  /** POST /embed/continue - SSO using the existing central federation session (no password). */
  async continueWithSession(input: { transactionId: string; clientId: string }, meta: RequestMeta): Promise<LoginOutcome> {
    this.assertSameOrigin(meta);
    const txn = await this.transactions.requirePending(input.transactionId, input.clientId);
    if (!safeEqual(meta.csrf, txn.csrf)) throw Errors.csrf(meta.csrf ? 'CSRF_TOKEN_MISMATCH' : 'CSRF_TOKEN_MISSING');
    await this.revalidateClient(txn);

    const session = await this.sessions.getByHandle(meta.sessionHandle, { ip: meta.ip, userAgent: meta.userAgent ?? null });
    if (!session) throw Errors.sessionRequired();
    const user = await this.credentials.getActiveUser(session.its_id);
    if (!user) {
      await this.logout.logoutSession(session.sid, 'USER_NO_LONGER_ACTIVE', { ip: meta.ip });
      throw Errors.sessionRequired();
    }
    const cookieMaxAge = await this.sessions.touch(session);
    const delivery = await this.issueForTransaction(txn, session, 'sso');
    return { session, cookieMaxAge, delivery };
  }

  /** POST /embed/logout and portal "use a different account": ends the central session in this browser only. */
  async endBrowserSession(transactionId: string, meta: RequestMeta): Promise<void> {
    this.assertSameOrigin(meta);
    const txn = await this.transactions.get(transactionId);
    if (!txn || !safeEqual(meta.csrf, txn.csrf)) throw Errors.csrf(meta.csrf ? 'CSRF_TOKEN_MISMATCH' : 'CSRF_TOKEN_MISSING');
    const session = await this.sessions.getByHandle(meta.sessionHandle, { ip: meta.ip, userAgent: meta.userAgent ?? null });
    if (!session) return;
    await this.sessions.revoke(session.sid, 'BROWSER_SESSION_ENDED');
    await this.audit.record({ eventType: 'SESSION_ENDED', outcome: 'SUCCESS', itsId: session.its_id, sid: session.sid, clientId: txn.client_id, ip: meta.ip });
  }

  /** CSRF defence in depth: state-changing calls must come from pages served by this origin. */
  private assertSameOrigin(meta: RequestMeta) {
    if (canonicalOrigin(meta.origin) !== this.config.issuerOrigin) throw Errors.csrf('ORIGIN_HEADER_MISMATCH');
  }

  /** Client may have been suspended or reconfigured since the transaction started. */
  private async revalidateClient(txn: LoginTransaction) {
    const client = await this.registry.getFresh(txn.client_id);
    assertClientCanAuthenticate(client, txn.display === 'page' ? 'page' : 'embed');
    if (txn.embed_origin && !client.allowed_embed_origins.includes(txn.embed_origin)) throw Errors.originNotAllowed();
    if (txn.callback_uri && !client.callback_uris.includes(txn.callback_uri)) throw Errors.callbackNotAllowed();
  }

  /**
   * Password sign-in always rotates the cookie handle (session-fixation defence).
   * Same user: keep the sid (applications stay correlated) with a fresh handle and auth_time.
   * Different user in the same browser: the previous user's federation session is logged out everywhere.
   */
  private async establishSession(user: AuthenticatedUser, meta: RequestMeta) {
    const existing = await this.sessions.getByHandle(meta.sessionHandle, { ip: meta.ip, userAgent: meta.userAgent ?? null });
    if (existing) {
      await this.logout.logoutSession(existing.sid, existing.its_id === user.itsId ? 'REAUTHENTICATED' : 'USER_SWITCHED', { ip: meta.ip });
    }
    const { session, handle } = await this.sessions.create(user, { ip: meta.ip, userAgent: meta.userAgent, authMethod: 'password' });
    return { session, handle, cookieMaxAge: this.config.env.SESSION_IDLE_TTL_SECONDS };
  }

  private async issueForTransaction(txn: LoginTransaction, session: FederationSession, method: 'password' | 'sso'): Promise<AssertionDelivery> {
    const completed = await this.transactions.complete(txn.transaction_id);
    const issued = await this.assertions.issue({
      itsId: session.its_id,
      clientId: completed.client_id!,
      sid: session.sid,
      transactionId: completed.transaction_id,
      authTime: session.auth_time,
    });
    await this.sessions.addClient(session, completed.client_id!);
    await this.audit.record({
      eventType: 'ASSERTION_ISSUED',
      outcome: 'SUCCESS',
      itsId: session.its_id,
      sid: session.sid,
      clientId: completed.client_id,
      jti: issued.jti,
      metadata: { method, display: completed.display, exp: issued.exp },
    });

    const base = { type: 'MIQAAT_AUTH_SUCCESS' as const, transaction_id: completed.transaction_id, state: completed.state!, core_assertion: issued.assertion };
    return completed.display === 'page'
      ? { ...base, delivery: 'form_post', callback_uri: completed.callback_uri! }
      : { ...base, delivery: 'post_message', target_origin: completed.embed_origin! };
  }
}
