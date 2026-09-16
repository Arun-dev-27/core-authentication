import { Body, Controller, Get, Headers, HttpCode, Post, Req, Res, UseFilters } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { Errors } from '@common/errors/domain-error';
import { safeEqual } from '@common/utils/crypto.util';
import { canonicalOrigin } from '@common/utils/origin.util';
import { AuthzClient } from '@modules/authorization-client/services/authz-client.service';
import { buildCsp, renderLoginPage, sendHtml } from '@modules/embed/services/login-views';
import { LoginService } from '@modules/embed/services/login.service';
import { requestMeta } from '@modules/embed/services/request-meta.util';
import { LogoutService } from '@modules/federation/services/logout.service';
import { FederationSessionService } from '@modules/sessions/services/federation-session.service';
import { clearSessionCookie, readSessionHandle } from '@modules/sessions/services/session-cookie';
import { TransactionService } from '@modules/transactions/services/transaction.service';
import { PortalLoginService } from '../services/portal-login.service';
import { PortalLoginDto } from './dto/portal-login.dto';
import { PortalLogoutDto } from './dto/portal-logout.dto';
import { SelectScopeDto } from './dto/select-scope.dto';
import { LoginEnvelopeFilter } from './login-envelope.filter';
import { bindingContextOf } from '@common/security/session-binding';

/**
 * Core Portal: sign in once, select a workspace (role × scope), then launch an application the user is entitled to
 * (the application completes sign-in silently via SSO).
 */
@ApiTags('portal')
@Controller({ path: 'portal', version: API_V1 })
export class PortalController {
  constructor(
    private readonly transactions: TransactionService,
    private readonly sessions: FederationSessionService,
    private readonly login: LoginService,
    private readonly portalLogin: PortalLoginService,
    private readonly logout: LogoutService,
    private readonly authz: AuthzClient,
    private readonly config: AppConfig,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Core Portal sign-in, workspace selection and application launcher page' })
  async page(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const txn = await this.transactions.create({
      transaction_id: TransactionService.generateId(),
      client_id: null,
      state: null,
      display: 'portal',
      embed_origin: null,
      callback_uri: null,
    });
    const session = await this.sessions.getByHandle(readSessionHandle(req, this.config), bindingContextOf(req));
    if (session) await this.transactions.bindToSession(txn.transaction_id, session, true);
    const html = renderLoginPage({
      mode: 'portal',
      transaction_id: txn.transaction_id,
      csrf: txn.csrf,
      client_id: null,
      state: null,
      target_origin: null,
      callback_uri: null,
      application: null,
      session: session ? { its_id: session.its_id, display_name: session.display_name } : null,
      auto_continue: false,
    });
    return sendHtml(reply, 200, html, buildCsp({ frameAncestors: null }));
  }

  @Post('login')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true })
  @UseFilters(LoginEnvelopeFilter)
  @ApiOperation({ summary: 'Sign in; login envelope with session.role_type (SINGLE | MULTI | NONE), roles[], active_role, modules, permissions' })
  signIn(@Body() dto: PortalLoginDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    return this.portalLogin.signIn(dto, csrf, req, reply);
  }

  @Get('assignments')
  @ApiOperation({ summary: 'Workspaces of the signed-in session (page reload / Switch Workspace)' })
  assignments(@Req() req: FastifyRequest) {
    return this.portalLogin.assignments(req);
  }

  @Post('select-scope')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true })
  @UseFilters(LoginEnvelopeFilter)
  @ApiOperation({ summary: 'Activate a role (switch without logging out); login envelope with the active_role, its modules, permissions and scoped token' })
  selectScope(@Body() dto: SelectScopeDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest) {
    return this.portalLogin.selectScope(dto, csrf, req);
  }

  @Get('applications')
  @ApiOperation({ summary: 'Applications the signed-in user may launch (from the Authorization service)' })
  async applications(@Req() req: FastifyRequest) {
    if (canonicalOrigin(req.headers.origin ?? this.config.issuerOrigin) !== this.config.issuerOrigin) throw Errors.csrf('ORIGIN_HEADER_MISMATCH');
    const session = await this.sessions.getByHandle(readSessionHandle(req, this.config), bindingContextOf(req));
    if (!session) throw Errors.sessionRequired();
    const apps = await this.authz.launchableApplications(session.its_id, this.config.env.PORTAL_ENVIRONMENT);
    return { its_id: session.its_id, display_name: session.display_name, environment: this.config.env.PORTAL_ENVIRONMENT, applications: apps };
  }

  @Post('logout')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true })
  async signOut(@Body() dto: PortalLogoutDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    const meta = requestMeta(req, this.config, csrf);
    if ((dto.scope ?? 'session') === 'session') {
      await this.login.endBrowserSession(dto.transaction_id, meta);
    } else {
      if (canonicalOrigin(meta.origin) !== this.config.issuerOrigin) throw Errors.csrf('ORIGIN_HEADER_MISMATCH');
      const txn = await this.transactions.get(dto.transaction_id);
      if (!txn || !safeEqual(csrf, txn.csrf)) throw Errors.csrf();
      const session = await this.sessions.getByHandle(meta.sessionHandle, { ip: meta.ip, userAgent: meta.userAgent ?? null });
      if (session) await this.logout.logoutSession(session.sid, 'PORTAL_SIGN_OUT_EVERYWHERE', { ip: meta.ip });
    }
    clearSessionCookie(reply, this.config);
    return { logged_out: true };
  }
}

/** The Role & Permission Module contract paths: POST /login and POST /select-scope (same handlers as /portal/*). */
@ApiTags('core-login')
@Controller({ version: API_V1 })
export class CoreLoginController {
  constructor(private readonly portalLogin: PortalLoginService) {}

  @Post('login')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true })
  @UseFilters(LoginEnvelopeFilter)
  @ApiOperation({ summary: 'POST /login - credentials; login envelope with session.role_type (SINGLE | MULTI | NONE), roles[], active_role, modules, permissions' })
  signIn(@Body() dto: PortalLoginDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    return this.portalLogin.signIn(dto, csrf, req, reply);
  }

  @Post('select-scope')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true })
  @UseFilters(LoginEnvelopeFilter)
  @ApiOperation({ summary: 'POST /select-scope - { role_id, scope_type, scope_id } -> login envelope for the chosen role' })
  selectScope(@Body() dto: SelectScopeDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest) {
    return this.portalLogin.selectScope(dto, csrf, req);
  }
}
