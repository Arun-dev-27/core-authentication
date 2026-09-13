import { Body, Controller, Get, Headers, HttpCode, Logger, Post, Query, Req, Res } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { CLIENT_ID_PATTERN, STATE_PATTERN, TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';
import { DomainError, Errors } from '@common/errors/domain-error';
import { canonicalOrigin, originOfReferer } from '@common/utils/origin.util';
import { AuditService } from '@core/audit/audit.service';
import { DisplayMode, assertClientCanAuthenticate, resolveCallback, resolveEmbedOrigin } from '@modules/clients/services/client-policy';
import { ClientRegistry } from '@modules/clients/services/client-registry.service';
import { FederationSessionService } from '@modules/sessions/services/federation-session.service';
import { clearSessionCookie, readSessionHandle, setSessionCookie } from '@modules/sessions/services/session-cookie';
import { TransactionService } from '@modules/transactions/services/transaction.service';
import { ErrorPageExtras, buildCsp, renderErrorPage, renderLoginPage, sendHtml } from '../services/login-views';
import { LoginService } from '../services/login.service';
import { requestMeta } from '../services/request-meta.util';
import { EmbedLoginDto } from './dto/embed-login.dto';
import { EmbedLogoutDto } from './dto/embed-logout.dto';
import { TransactionRefDto } from './dto/transaction-ref.dto';

interface FailureContext {
  /** registered embed origin, set once client + origin + fetch-metadata checks passed */
  framedBy: string | null;
  /** registered embed origin of a link that was opened as a top-level page */
  openedTopLevelFor: string | null;
  query: Record<string, string | undefined>;
}

@ApiTags('embed')
@Controller({ path: 'embed', version: API_V1 })
export class EmbedController {
  private readonly logger = new Logger(EmbedController.name);

  constructor(
    private readonly registry: ClientRegistry,
    private readonly transactions: TransactionService,
    private readonly sessions: FederationSessionService,
    private readonly login: LoginService,
    private readonly audit: AuditService,
    private readonly config: AppConfig,
  ) {}

  @Get('login')
  @ApiOperation({ summary: 'Core-controlled login page (iframe, or top-level with display=page)' })
  @ApiQuery({ name: 'client_id', required: true })
  @ApiQuery({ name: 'transaction_id', required: true })
  @ApiQuery({ name: 'state', required: true })
  @ApiQuery({ name: 'origin', required: false, description: 'Parent origin (exact registered value)' })
  @ApiQuery({ name: 'redirect_uri', required: false, description: 'Selects a registered callback' })
  @ApiQuery({ name: 'display', required: false, enum: ['embed', 'page'] })
  @ApiQuery({ name: 'prompt', required: false, enum: ['login', 'auto'] })
  async page(@Query() query: Record<string, string | undefined>, @Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const display: DisplayMode = query.display === 'page' ? 'page' : 'embed';
    const failure: FailureContext = { framedBy: null, openedTopLevelFor: null, query };
    try {
      const client = await this.registry.get(query.client_id);
      assertClientCanAuthenticate(client, display);
      const embedOrigin = display === 'embed' ? resolveEmbedOrigin(client, query.origin) : null;
      const callback = resolveCallback(client, query.redirect_uri);
      try {
        this.assertFetchMetadata(req, display, embedOrigin, callback);
      } catch (error) {
        // Embed link pasted into a tab: the origin is registered for this client, so point the user to that application.
        if (error instanceof DomainError && error.code === 'EMBED_CONTEXT_REQUIRED' && embedOrigin) failure.openedTopLevelFor = embedOrigin;
        throw error;
      }
      // From here on the request comes from (or is framed by) the registered origin: errors may be shown in its frame.
      failure.framedBy = embedOrigin;
      if (!query.transaction_id) throw Errors.invalidRequest('transaction_id is required');

      const txn = await this.transactions.create({
        transaction_id: query.transaction_id,
        client_id: client.client_id,
        state: query.state ?? null,
        display,
        embed_origin: embedOrigin,
        callback_uri: callback,
      });

      const session = query.prompt === 'login' ? null : await this.sessions.getByHandle(readSessionHandle(req, this.config));
      await this.audit.record({ eventType: 'EMBED_LOGIN_RENDERED', outcome: 'INFO', clientId: client.client_id, ip: req.ip, metadata: { display, sso_available: Boolean(session) } });

      const html = renderLoginPage({
        mode: display,
        transaction_id: txn.transaction_id,
        csrf: txn.csrf,
        client_id: client.client_id,
        state: txn.state,
        target_origin: embedOrigin,
        callback_uri: display === 'page' ? callback : null,
        application: { name: client.application_name, business_unit: client.business_unit, utility: client.utility, environment: client.environment },
        session: session ? { its_id: session.its_id, display_name: session.display_name } : null,
        auto_continue: Boolean(session) && query.prompt === 'auto',
      });
      // frame-ancestors is the exact origin this transaction will postMessage to - never a list, never a wildcard.
      return sendHtml(reply, 200, html, buildCsp({ frameAncestors: embedOrigin, formActionOrigin: display === 'page' ? new URL(callback).origin : null }));
    } catch (error) {
      return this.renderFailure(reply, req, error, query.client_id, failure);
    }
  }

  @Post('login')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true, description: 'Token from the rendered login page' })
  @ApiOperation({ summary: 'Authenticate and return the complete RS256 compact assertion for postMessage/form_post delivery' })
  async authenticate(@Body() dto: EmbedLoginDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    const identityType = dto.identity_type ?? 'ITS';
    const outcome = await this.login.loginWithPassword(
      {
        transactionId: dto.transaction_id,
        clientId: dto.client_id,
        identityType,
        identifier: identityType === 'ITS' ? dto.its_id! : dto.identifier!,
        password: dto.password,
      },
      requestMeta(req, this.config, csrf),
    );
    if (outcome.handle) setSessionCookie(reply, this.config, outcome.handle, outcome.cookieMaxAge);
    return outcome.delivery;
  }

  @Post('continue')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true })
  @ApiOperation({ summary: 'SSO: issue an assertion for this client from the existing federation session' })
  async continueSession(@Body() dto: TransactionRefDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    try {
      const outcome = await this.login.continueWithSession({ transactionId: dto.transaction_id, clientId: dto.client_id }, requestMeta(req, this.config, csrf));
      const handle = readSessionHandle(req, this.config);
      if (handle) setSessionCookie(reply, this.config, handle, outcome.cookieMaxAge);
      return outcome.delivery;
    } catch (error) {
      if (error instanceof DomainError && error.code === 'SESSION_REQUIRED') clearSessionCookie(reply, this.config);
      throw error;
    }
  }

  @Post('logout')
  @HttpCode(200)
  @ApiHeader({ name: 'x-csrf-token', required: true })
  @ApiOperation({ summary: 'End the central federation session in this browser ("use a different account"); no application fan-out' })
  async logout(@Body() dto: EmbedLogoutDto, @Headers('x-csrf-token') csrf: string, @Req() req: FastifyRequest, @Res({ passthrough: true }) reply: FastifyReply) {
    await this.login.endBrowserSession(dto.transaction_id, requestMeta(req, this.config, csrf));
    clearSessionCookie(reply, this.config);
    return { logged_out: true };
  }

  /**
   * Fetch-metadata and Referer checks (enforced only when the browser sends them).
   * The authoritative control is CSP frame-ancestors + exact postMessage target origin.
   */
  private assertFetchMetadata(req: FastifyRequest, display: DisplayMode, embedOrigin: string | null, callback: string) {
    const dest = req.headers['sec-fetch-dest'];
    if (typeof dest === 'string') {
      if (display === 'embed' && dest !== 'iframe' && dest !== 'frame') throw new DomainError('EMBED_CONTEXT_REQUIRED', 'This page must be opened inside the application', 400);
      if (display === 'page' && dest !== 'document') throw new DomainError('TOP_LEVEL_REQUIRED', 'This page cannot be framed', 400);
    }
    const refererOrigin = originOfReferer(req.headers.referer);
    if (refererOrigin && refererOrigin !== this.config.issuerOrigin) {
      const expected = display === 'embed' ? embedOrigin : new URL(callback).origin;
      if (canonicalOrigin(refererOrigin) !== expected) throw Errors.originNotAllowed();
    }
  }

  private async renderFailure(reply: FastifyReply, req: FastifyRequest, error: unknown, clientId: string | undefined, context?: FailureContext) {
    const domain = error instanceof DomainError ? error : null;
    if (!domain) this.logger.error(error instanceof Error ? error : String(error));
    await this.audit.record({
      eventType: 'EMBED_LOGIN_REJECTED',
      outcome: 'FAILURE',
      clientId: typeof clientId === 'string' && CLIENT_ID_PATTERN.test(clientId) ? clientId : null,
      ip: req.ip,
      metadata: { reason: domain?.code ?? 'INTERNAL_ERROR' },
    });
    const status = domain?.status ?? 500;
    const message = domain?.message ?? 'Sign-in is temporarily unavailable.';

    if (context?.openedTopLevelFor) {
      const appOrigin = context.openedTopLevelFor;
      const loginUrl = `${this.config.issuerOrigin}${req.url}`;
      const extras: ErrorPageExtras = {
        action: {
          label: `Open ${appOrigin}`,
          href: `${appOrigin}/?login_url=${encodeURIComponent(loginUrl)}`,
          hint: 'This link belongs to the sign-in panel inside that application. Start sign-in from the application, or open it with this link.',
        },
      };
      return sendHtml(
        reply,
        status,
        renderErrorPage('Open this sign-in inside the application', 'This sign-in link cannot be used in a browser tab on its own.', req.id, extras),
        buildCsp({ frameAncestors: null }),
      );
    }

    if (context?.framedBy) {
      // Client, exact origin and fetch metadata were validated: let that origin show the error and tell it what happened.
      const code = domain?.code ?? 'INTERNAL_ERROR';
      const restartable = ['TRANSACTION_ALREADY_USED', 'TRANSACTION_INVALID', 'TRANSACTION_CONFLICT'].includes(code);
      const extras: ErrorPageExtras = {
        embedError: {
          target_origin: context.framedBy,
          transaction_id: typeof context.query.transaction_id === 'string' && TRANSACTION_ID_PATTERN.test(context.query.transaction_id) ? context.query.transaction_id : null,
          state: typeof context.query.state === 'string' && STATE_PATTERN.test(context.query.state) ? context.query.state : null,
          error: restartable ? 'TRANSACTION_EXPIRED' : 'LOGIN_FAILED',
          code,
        },
      };
      const text = restartable ? `${message} Please start sign-in again from the application.` : message;
      return sendHtml(reply, status, renderErrorPage('Unable to start sign-in', text, req.id, extras), buildCsp({ frameAncestors: context.framedBy }));
    }

    // Anything else is never frameable: an unregistered parent learns nothing and cannot overlay it.
    return sendHtml(reply, status, renderErrorPage('Unable to start sign-in', message, req.id), buildCsp({ frameAncestors: null }));
  }
}
