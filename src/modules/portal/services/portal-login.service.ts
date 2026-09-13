import { Injectable } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { DomainError, Errors } from '@common/errors/domain-error';
import { safeEqual } from '@common/utils/crypto.util';
import { canonicalOrigin } from '@common/utils/origin.util';
import { AuditService } from '@core/audit/audit.service';
import { AssertionService } from '@modules/assertions/services/assertion.service';
import { AuthzClient } from '@modules/authorization-client/services/authz-client.service';
import { LoginService } from '@modules/embed/services/login.service';
import { requestMeta } from '@modules/embed/services/request-meta.util';
import { FederationSessionService } from '@modules/sessions/services/federation-session.service';
import { readSessionHandle, setSessionCookie } from '@modules/sessions/services/session-cookie';
import { TransactionService } from '@modules/transactions/services/transaction.service';
import { ActiveScopeClaim, WorkspaceAssignment } from '@shared/types/federation-client.types';
import { FederationSession } from '@shared/types/session.types';

export interface PortalLoginInput {
  transaction_id: string;
  identity_type?: 'ITS' | 'NON_ITS';
  its_id?: string;
  identifier?: string;
  password: string;
}

export interface SelectScopeInput extends Omit<ActiveScopeClaim, 'scope_id'> {
  scope_id?: string | null;
  transaction_id: string;
  audience?: 'authorization' | 'identity';
}

/**
 * Core login with workspace selection:
 *  POST /login          -> credentials; returns every role × scope assignment. One assignment: it is activated
 *                          immediately (scoped token). Several: requires_scope_selection = true + an unscoped token.
 *  POST /select-scope   -> validates the chosen assignment with the Authorization service and returns a token
 *                          carrying only the active scope (role_id, scope_type, scope_id). Also used to switch.
 *  GET  /me/permissions -> (Authorization service) resolves permissions for the token's active scope.
 */
@Injectable()
export class PortalLoginService {
  constructor(
    private readonly transactions: TransactionService,
    private readonly sessions: FederationSessionService,
    private readonly login: LoginService,
    private readonly authz: AuthzClient,
    private readonly assertions: AssertionService,
    private readonly audit: AuditService,
    private readonly config: AppConfig,
  ) {}

  async signIn(input: PortalLoginInput, csrf: string, req: FastifyRequest, reply: FastifyReply) {
    const identityType = input.identity_type ?? 'ITS';
    const outcome = await this.login.loginWithPassword(
      { transactionId: input.transaction_id, clientId: null, identityType, identifier: identityType === 'ITS' ? input.its_id! : input.identifier!, password: input.password },
      requestMeta(req, this.config, csrf),
    );
    if (outcome.handle) setSessionCookie(reply, this.config, outcome.handle, outcome.cookieMaxAge);

    const session = outcome.session;
    const workspaces = await this.authz.getAssignments(session.its_id);
    const base = {
      its_id: session.its_id,
      name: workspaces.name ?? session.display_name,
      requires_scope_selection: workspaces.assignments.length > 1,
      assignments: workspaces.assignments,
    };
    if (workspaces.assignments.length === 1) {
      const selected = await this.activate(session, workspaces.assignments[0], 'authorization', req.ip);
      return { ...base, ...selected };
    }
    const unscoped = await this.assertions.issueAccessToken({ itsId: session.its_id, sid: session.sid, audience: this.config.env.AUTHZ_AUDIENCE });
    return { ...base, token: unscoped.token, token_type: 'Bearer', expires_in: unscoped.expiresIn, active_scope: null };
  }

  /** Workspaces of the signed-in browser session (page reload, "Switch Workspace"). */
  async assignments(req: FastifyRequest) {
    if (canonicalOrigin(req.headers.origin ?? this.config.issuerOrigin) !== this.config.issuerOrigin) throw Errors.csrf('ORIGIN_HEADER_MISMATCH');
    const session = await this.sessions.getByHandle(readSessionHandle(req, this.config));
    if (!session) throw Errors.sessionRequired();
    const workspaces = await this.authz.getAssignments(session.its_id);
    return { ...workspaces, name: workspaces.name ?? session.display_name, requires_scope_selection: workspaces.assignments.length > 1 };
  }

  async selectScope(input: SelectScopeInput, csrf: string, req: FastifyRequest) {
    if (canonicalOrigin(req.headers.origin) !== this.config.issuerOrigin) throw Errors.csrf('ORIGIN_HEADER_MISMATCH');
    const txn = await this.transactions.get(input.transaction_id);
    if (!txn || txn.display !== 'portal' || !safeEqual(csrf, txn.csrf)) throw Errors.csrf();
    const session = await this.sessions.getByHandle(readSessionHandle(req, this.config));
    if (!session) throw Errors.sessionRequired();
    if (!(await this.transactions.bindToSession(txn.transaction_id, session))) throw Errors.csrf();
    return this.activate(session, { role_id: input.role_id, scope_type: input.scope_type, scope_id: input.scope_id ?? null }, input.audience ?? 'authorization', req.ip);
  }

  private async activate(session: FederationSession, scope: ActiveScopeClaim | WorkspaceAssignment, audienceName: 'authorization' | 'identity', ip: string) {
    const claim: ActiveScopeClaim = { role_id: scope.role_id, scope_type: scope.scope_type, scope_id: scope.scope_id ?? null };
    const resolved = await this.authz.resolveAssignment(session.its_id, claim);
    if (!resolved) {
      await this.audit.record({ eventType: 'SCOPE_SELECTION_REJECTED', outcome: 'FAILURE', itsId: session.its_id, sid: session.sid, ip, metadata: { ...claim } });
      throw new DomainError('SCOPE_NOT_ASSIGNED', 'This workspace is not assigned to you', 403);
    }
    const audience = audienceName === 'identity' ? this.config.issuer : this.config.env.AUTHZ_AUDIENCE;
    const issued = await this.assertions.issueAccessToken({ itsId: session.its_id, sid: session.sid, audience, scope: claim });
    await this.audit.record({
      eventType: 'SCOPE_SELECTED',
      outcome: 'SUCCESS',
      itsId: session.its_id,
      sid: session.sid,
      jti: issued.jti,
      ip,
      metadata: { ...claim, role_name: resolved.active_scope.role_name, audience: audienceName },
    });
    return {
      active_scope: resolved.active_scope,
      token: issued.token,
      token_type: 'Bearer',
      expires_in: issued.expiresIn,
      audience,
      permissions: resolved.permissions,
    };
  }
}
