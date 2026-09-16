import { Injectable, Logger } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { DomainError, Errors } from '@common/errors/domain-error';
import { randomToken, safeEqual } from '@common/utils/crypto.util';
import { canonicalOrigin } from '@common/utils/origin.util';
import { AuditService } from '@core/audit/audit.service';
import { AuthzClient } from '@modules/authorization-client/services/authz-client.service';
import { assertClientCanAuthenticate } from '@modules/clients/services/client-policy';
import { ClientRegistry } from '@modules/clients/services/client-registry.service';
import { FederationSessionService } from '@modules/sessions/services/federation-session.service';
import { readSessionHandle } from '@modules/sessions/services/session-cookie';
import { TransactionService } from '@modules/transactions/services/transaction.service';
import { ActiveScopeClaim, ResolvedWorkspace, WorkspaceAssignment } from '@shared/types/federation-client.types';
import { FederationSession } from '@shared/types/session.types';

export interface SelectWorkspaceInput extends ActiveScopeClaim {
  transaction_id: string;
  client_id: string;
}

export interface SelectedWorkspace {
  session: FederationSession;
  resolved: ResolvedWorkspace;
  client_id: string;
}

/**
 * Embedded login, step 2 - workspace selection.
 *
 * Step 1 (POST /embed/login, POST /embed/continue) authenticates the person and hands the application a
 * one-time core_assertion carrying identity only. It creates no local session, because
 * miqaat_core.user_sessions.role_id is NOT NULL and no role has been chosen yet.
 *
 * This step chooses the role. It is authenticated by the federation session cookie (never by anything the
 * page posts), and authorised by the transaction's CSRF token - the transaction is bound to the session at
 * sign-in, so it stays usable for exactly as long as the session does. Only after the Authorization service
 * confirms the workspace is really assigned is the local session recorded, with an opaque random token.
 *
 * Nothing from the browser is trusted: its_id comes from the session cookie, and role_id / scope are only
 * ever used as a lookup key that the Authorization service must confirm against the database.
 */
@Injectable()
export class EmbedWorkspaceService {
  private readonly logger = new Logger(EmbedWorkspaceService.name);

  constructor(
    private readonly transactions: TransactionService,
    private readonly sessions: FederationSessionService,
    private readonly registry: ClientRegistry,
    private readonly authz: AuthzClient,
    private readonly audit: AuditService,
    private readonly config: AppConfig,
  ) {}

  /** Workspaces of the signed-in embedded session, for the "select workspace" screen. */
  async assignments(input: { transaction_id: string; client_id: string }, csrf: string | undefined, req: FastifyRequest) {
    const { session } = await this.authenticate(input, csrf, req);
    const workspaces = await this.authz.getAssignments(session.its_id);
    return { ...workspaces, requires_scope_selection: workspaces.assignments.length > 1 };
  }

  /**
   * Validates the chosen workspace server-side and records the local session.
   * Returns the resolved workspace (role + permission map) for the login envelope.
   */
  async select(input: SelectWorkspaceInput, csrf: string | undefined, req: FastifyRequest): Promise<SelectedWorkspace> {
    const { session, clientId } = await this.authenticate(input, csrf, req);
    const claim: ActiveScopeClaim = { role_id: input.role_id, scope_type: input.scope_type, scope_id: input.scope_id ?? null };
    const resolved = await this.resolve(session, claim, clientId, req.ip);
    await this.recordLocalSession(session, resolved.active_scope, clientId, req);
    return { session, resolved, client_id: clientId };
  }

  /**
   * Automatic selection, allowed only when the user holds exactly one workspace (FR: a single valid
   * tenant-role combination may be selected for the user; several must be chosen explicitly).
   */
  async autoSelect(session: FederationSession, clientId: string, req: FastifyRequest, assignments: WorkspaceAssignment[]): Promise<ResolvedWorkspace | null> {
    if (assignments.length !== 1) return null;
    const only = assignments[0];
    const resolved = await this.resolve(session, { role_id: only.role_id, scope_type: only.scope_type, scope_id: only.scope_id ?? null }, clientId, req.ip, false);
    if (!resolved) return null;
    await this.recordLocalSession(session, resolved.active_scope, clientId, req);
    return resolved;
  }

  /**
   * The session comes from the HttpOnly cookie and the client from the registry - never from the request body
   * beyond naming which client to look up. The transaction's CSRF token proves the call came from the page
   * this transaction rendered.
   */
  private async authenticate(input: { transaction_id: string; client_id: string }, csrf: string | undefined, req: FastifyRequest) {
    if (canonicalOrigin(req.headers.origin) !== this.config.issuerOrigin) throw Errors.csrf('ORIGIN_HEADER_MISMATCH');

    const txn = await this.transactions.get(input.transaction_id);
    if (!txn || txn.client_id !== input.client_id) throw Errors.transactionInvalid();
    if (!safeEqual(csrf, txn.csrf)) throw Errors.csrf(csrf ? 'CSRF_TOKEN_MISMATCH' : 'CSRF_TOKEN_MISSING');

    const session = await this.sessions.getByHandle(readSessionHandle(req, this.config));
    if (!session) throw Errors.sessionRequired();
    // The transaction must belong to this very session, or a stolen transaction id would be usable in another browser.
    if (txn.sid !== session.sid) {
      throw new DomainError('TRANSACTION_SESSION_MISMATCH', 'This sign-in request does not belong to your session. Please start again.', 403);
    }

    // Re-read the client: it may have been suspended or reconfigured since sign-in.
    const client = await this.registry.getFresh(input.client_id);
    assertClientCanAuthenticate(client, txn.display === 'page' ? 'page' : 'embed');
    return { session, clientId: client.client_id };
  }

  /** Deny by default: only a workspace the Authorization service confirms is assigned may be selected. */
  private async resolve(session: FederationSession, claim: ActiveScopeClaim, clientId: string, ip: string, throwOnMissing = true): Promise<ResolvedWorkspace> {
    const resolved = await this.authz.resolveAssignment(session.its_id, claim);
    if (!resolved) {
      await this.audit.record({
        eventType: 'SCOPE_SELECTION_REJECTED',
        outcome: 'FAILURE',
        itsId: session.its_id,
        sid: session.sid,
        clientId,
        ip,
        metadata: { ...claim, reason: 'ASSIGNMENT_NOT_FOUND' },
      });
      if (throwOnMissing) throw new DomainError('SCOPE_NOT_ASSIGNED', 'This workspace is not assigned to you', 403);
    }
    return resolved as ResolvedWorkspace;
  }

  /** aud is the validated client_id, and the token is opaque - never the assertion or any JWT. */
  private async recordLocalSession(session: FederationSession, scope: WorkspaceAssignment, clientId: string, req: FastifyRequest): Promise<void> {
    const userAgent = req.headers['user-agent'];
    await this.authz.recordSession({
      its_id: session.its_id,
      role_id: scope.role_id,
      scope_type: scope.scope_type,
      scope_id: scope.scope_id ?? null,
      core_sid: session.sid,
      aud: clientId,
      session_token: randomToken(32),
      expires_at: session.absolute_expires_at,
      ip_address: req.ip,
      user_agent: typeof userAgent === 'string' ? userAgent : null,
    });
    await this.audit.record({
      eventType: 'SCOPE_SELECTED',
      outcome: 'SUCCESS',
      itsId: session.its_id,
      sid: session.sid,
      clientId,
      ip: req.ip,
      metadata: { role_id: scope.role_id, scope_type: scope.scope_type, scope_id: scope.scope_id, role_name: scope.role_name, flow: 'embed' },
    });
    this.logger.log({ msg: 'embedded workspace selected', sid: session.sid, client_id: clientId, role_id: scope.role_id });
  }
}
