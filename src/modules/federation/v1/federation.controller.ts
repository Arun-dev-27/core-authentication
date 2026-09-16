import { Body, Controller, HttpCode, Param, Post, Req, Res } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { CLIENT_ID_PATTERN } from '@common/constants/validation.constants';
import { DomainError, Errors } from '@common/errors/domain-error';
import { safeEqual } from '@common/utils/crypto.util';
import { canonicalOrigin, matchRegisteredOrigin } from '@common/utils/origin.util';
import { AuditService } from '@core/audit/audit.service';
import { AccessTokenVerifier } from '@modules/assertions/services/access-token.verifier';
import { AuthzClient } from '@modules/authorization-client/services/authz-client.service';
import { resolvePostLogoutRedirect } from '@modules/clients/services/client-policy';
import { ClientRegistry } from '@modules/clients/services/client-registry.service';
import { FederationSessionService } from '@modules/sessions/services/federation-session.service';
import { clearSessionCookie, readSessionHandle } from '@modules/sessions/services/session-cookie';
import { LogoutService } from '../services/logout.service';
import { FederationLogoutDto } from './dto/federation-logout.dto';
import { bindingContextOf } from '@common/security/session-binding';

@ApiTags('federation')
@Controller({ path: 'federation', version: API_V1 })
export class FederationController {
  constructor(
    private readonly logout: LogoutService,
    private readonly sessions: FederationSessionService,
    private readonly registry: ClientRegistry,
    private readonly accessTokens: AccessTokenVerifier,
    private readonly authz: AuthzClient,
    private readonly config: AppConfig,
    private readonly audit: AuditService,
  ) {}

  /**
   * Federation-wide logout.
   *  - Administrator-initiated (Authorization: Bearer <access token, aud = this issuer>): revoke by its_id or sid
   *    (disabled users, security incidents). The token is verified via JWKS; the caller must hold a CORE workspace with
   *    USER_MGMT edit, checked live in the Authorization service. No shared admin key exists.
   *  - Browser-initiated (top-level form POST from a registered application origin, with the
   *    federation cookie): requires client_id + logout_hint(sid); redirects to a registered URI.
   */
  @Post('logout')
  @HttpCode(200)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Federation-wide logout with back-channel notification of every participating application' })
  async federationLogout(@Body() dto: FederationLogoutDto, @Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    if (req.headers.authorization) {
      const admin = await this.requireCoreAdmin(req.headers.authorization, 'USER_MGMT', 'edit');
      const reason = `ADMIN_FORCE_LOGOUT:${admin.itsId}`;
      if (dto.its_id) {
        const revoked = await this.logout.logoutUser(dto.its_id, reason);
        return reply.send({ revoked_sessions: revoked.length, clients_notified: revoked.flatMap((r) => r.clients) });
      }
      if (dto.sid) {
        const revoked = await this.logout.logoutSession(dto.sid, reason);
        return reply.send({ revoked_sessions: revoked ? 1 : 0, clients_notified: revoked?.clients ?? [] });
      }
      throw Errors.invalidRequest('its_id or sid is required');
    }

    const requestOrigin = canonicalOrigin(req.headers.origin);
    const sameOrigin = requestOrigin === this.config.issuerOrigin;
    const client = dto.client_id ? await this.registry.get(dto.client_id) : null;
    if (!sameOrigin) {
      if (!client) throw Errors.invalidRequest('client_id is required');
      if (!matchRegisteredOrigin(requestOrigin, client.allowed_embed_origins)) throw Errors.originNotAllowed();
    }

    const session = await this.sessions.getByHandle(readSessionHandle(req, this.config), bindingContextOf(req));
    let loggedOut = false;
    if (session) {
      if (!sameOrigin && (!dto.logout_hint || !safeEqual(dto.logout_hint, session.sid))) {
        throw new DomainError('LOGOUT_HINT_MISMATCH', 'Logout request does not match the current session', 403);
      }
      await this.logout.logoutSession(session.sid, sameOrigin ? 'USER_LOGOUT' : `CLIENT_LOGOUT:${client?.client_id}`, { ip: req.ip });
      loggedOut = true;
    }
    clearSessionCookie(reply, this.config);

    const redirect = client ? resolvePostLogoutRedirect(client, dto.post_logout_redirect_uri) : null;
    if (dto.post_logout_redirect_uri && !redirect) throw Errors.callbackNotAllowed();

    const isForm = (req.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded');
    if (isForm && redirect) {
      const target = new URL(redirect);
      if (dto.state) target.searchParams.set('state', dto.state);
      return reply.status(303).header('location', target.toString()).send();
    }
    return reply.send({ logged_out: loggedOut, redirect_to: redirect });
  }

  /**
   * Reloads one client's configuration (embed origins, callbacks, status) from the Authorization service now
   * instead of after CLIENT_CACHE_TTL_SECONDS. Call it right after adding or removing an origin / callback or
   * suspending a client. Bearer access token (aud = this issuer, typ at+jwt, verified via JWKS) of a CORE workspace
   * holding CONFIGURATION edit.
   */
  @Post('clients/:clientId/refresh')
  @HttpCode(200)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Apply client configuration changes (origins, callbacks, status) immediately' })
  async refreshClient(@Param('clientId') clientId: string, @Req() req: FastifyRequest) {
    const admin = await this.requireCoreAdmin(req.headers.authorization, 'CONFIGURATION', 'edit');
    if (!CLIENT_ID_PATTERN.test(clientId)) throw Errors.clientNotFound();
    await this.registry.invalidate(clientId);
    const client = await this.registry.get(clientId);
    await this.audit.record({
      eventType: 'CLIENT_CONFIG_REFRESHED',
      outcome: 'SUCCESS',
      itsId: admin.itsId,
      clientId,
      ip: req.ip,
      metadata: { config_version: client.config_version, origins: client.allowed_embed_origins.length },
    });
    return {
      client_id: client.client_id,
      status: client.status,
      authentication_mode: client.authentication_mode,
      allowed_embed_origins: client.allowed_embed_origins,
      callback_uris: client.callback_uris,
      back_channel_logout_uri: client.back_channel_logout_uri,
      post_logout_redirect_uris: client.post_logout_redirect_uris,
      config_version: client.config_version,
      refreshed_at: new Date().toISOString(),
    };
  }

  /** Access token (aud = this issuer) whose active workspace is CORE and holds module:action, re-checked live. */
  private async requireCoreAdmin(authorization: string | undefined, module: string, action: string) {
    const admin = await this.accessTokens.verify(authorization);
    if (!admin.scope) throw new DomainError('SCOPE_SELECTION_REQUIRED', 'Select a workspace before calling this endpoint', 403);
    const workspace = await this.authz.resolveAssignment(admin.itsId, admin.scope);
    if (!workspace || workspace.active_scope.scope_type !== 'CORE' || !workspace.permissions[module]?.includes(action)) {
      throw new DomainError('ADMIN_PERMISSION_DENIED', 'You do not have permission to perform this action', 403);
    }
    return admin;
  }
}
