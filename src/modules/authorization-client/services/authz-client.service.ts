import { Injectable, Logger } from '@nestjs/common';
import { AppConfig } from '@config/config.module';
import { Errors } from '@common/errors/domain-error';
import { currentCorrelationId } from '@common/logging/request-context';
import { AssertionService } from '@modules/assertions/services/assertion.service';
import {
  ActiveScopeClaim,
  FederationClientConfig,
  LaunchableApplication,
  ResolvedWorkspace,
  UserProfileSync,
  WorkspaceList,
} from '@shared/types/federation-client.types';

/** One signed-in session, as recorded in the Authorization service. `session_token` is a hash, never a token. */
export interface RecordedSessionInput extends ActiveScopeClaim {
  its_id: string;
  core_sid: string;
  aud: string;
  session_token: string;
  expires_at: string;
  ip_address?: string | null;
  user_agent?: string | null;
}

/**
 * HTTP client for the Authorization service. Every request carries a freshly minted, single-use RS256
 * service token (verified there against our JWKS) - there is no API key.
 * Identity Federation asks for client configuration, workspaces (role × scope) and profile sync - never decisions
 * on business requests.
 */
@Injectable()
export class AuthzClient {
  private readonly logger = new Logger(AuthzClient.name);

  constructor(
    private readonly config: AppConfig,
    private readonly assertions: AssertionService,
  ) {}

  /** Returns null when the client does not exist. Throws DEPENDENCY_UNAVAILABLE on outage (fail closed). */
  async getClient(clientId: string): Promise<FederationClientConfig | null> {
    const res = await this.request('GET', `/internal/federation/clients/${encodeURIComponent(clientId)}`);
    if (res.status === 404) return null;
    return this.json<FederationClientConfig>(res);
  }

  async launchableApplications(itsId: string, environment: string): Promise<LaunchableApplication[]> {
    const res = await this.request('GET', `/internal/federation/users/${encodeURIComponent(itsId)}/applications?environment=${encodeURIComponent(environment)}`);
    return this.json<LaunchableApplication[]>(res);
  }

  /** All workspaces of a user for POST /login. */
  async getAssignments(itsId: string): Promise<WorkspaceList> {
    const res = await this.request('GET', `/internal/federation/users/${encodeURIComponent(itsId)}/assignments`);
    return this.json<WorkspaceList>(res);
  }

  /** Validates that the user holds this workspace now; null when it is not assigned. */
  async resolveAssignment(itsId: string, scope: ActiveScopeClaim): Promise<ResolvedWorkspace | null> {
    const res = await this.request('POST', '/internal/federation/assignments/resolve', { its_id: itsId, ...scope });
    if (res.status === 404) return null;
    return this.json<ResolvedWorkspace>(res);
  }

  async syncUser(profile: UserProfileSync): Promise<void> {
    const res = await this.request('POST', '/users/sync', profile);
    await this.json(res);
  }

  /**
   * Records a signed-in session (workspace selected) in the Authorization service's Control Panel model.
   * Best effort by design: signing in must succeed even when that write cannot be made. The session itself
   * stays owned by this service - what travels is the sid, the audience and a hash of the issued token.
   */
  async recordSession(session: RecordedSessionInput): Promise<void> {
    try {
      const res = await this.request('POST', '/internal/federation/sessions', session);
      if (!res.ok) this.logger.warn({ msg: 'authorization service refused the session record', sid: session.core_sid, status: res.status });
    } catch (error) {
      this.logger.warn({ msg: 'authorization service unreachable for session recording', sid: session.core_sid, err: error instanceof Error ? error.message : String(error) });
    }
  }

  /**
   * Tells the Authorization service that a session ended, so access tokens carrying its `sid` are refused there too.
   * Best effort by design: signing out must succeed even when the Authorization service is unavailable.
   */
  async revokeSession(sid: string): Promise<void> {
    try {
      const res = await this.request('POST', `/internal/federation/sessions/${encodeURIComponent(sid)}/revoke`);
      if (!res.ok) this.logger.warn({ msg: 'authorization service refused the session revocation', sid, status: res.status });
    } catch (error) {
      this.logger.warn({ msg: 'authorization service unreachable for session revocation', sid, err: error instanceof Error ? error.message : String(error) });
    }
  }

  private async request(method: string, path: string, body?: unknown): Promise<Response> {
    let token: string;
    try {
      token = await this.assertions.issueServiceToken();
    } catch (error) {
      this.logger.error({ msg: 'cannot sign service token', err: error instanceof Error ? error.message : String(error) });
      throw Errors.dependencyUnavailable();
    }
    try {
      return await fetch(`${this.config.env.AUTHZ_BASE_URL}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          'x-request-id': currentCorrelationId() ?? '',
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(3000),
      });
    } catch (error) {
      this.logger.error({ msg: 'authorization service unreachable', path: path.split('?')[0], err: error instanceof Error ? error.message : String(error) });
      throw Errors.dependencyUnavailable();
    }
  }

  private async json<T>(res: Response): Promise<T> {
    if (!res.ok) {
      this.logger.error({ msg: 'authorization service error', status: res.status });
      throw Errors.dependencyUnavailable();
    }
    return (await res.json()) as T;
  }
}
