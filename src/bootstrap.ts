import { join } from 'node:path';
import fastifyCookie from '@fastify/cookie';
import helmet from '@fastify/helmet';
import { ValidationPipe, VERSION_NEUTRAL, VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Env, loadEnv } from '@config/configuration';
import { GlobalExceptionFilter } from '@common/filters/http-exception.filter';
import { PinoNestLogger, createLogger, genRequestId } from '@common/logging/logger';
import { requestContext } from '@common/logging/request-context';
import { LogoutService } from '@modules/federation/services/logout.service';
import { AppModule } from './app.module';
import { configureClientIpHeader } from '@common/security/session-binding';

export function buildOpenApiConfig() {
  return new DocumentBuilder()
    .setTitle('Miqaat Identity Federation Service')
    .setDescription(
      'Central embedded login, federation sessions, RS256 assertions (JWKS), SSO and federation logout. Authentication only - authorization decisions live in the Core Identity Authorization Service.',
    )
    .setVersion('1.0.0')
    .addBearerAuth()
    .build();
}

const DEFAULT_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

export async function createApp(env: Env = loadEnv()): Promise<NestFastifyApplication> {
  const logger = createLogger(env.LOG_LEVEL);
  const adapter = new FastifyAdapter({
    loggerInstance: logger,
    trustProxy: env.TRUST_PROXY,
    genReqId: genRequestId,
    requestIdHeader: false,
    bodyLimit: 64 * 1024,
  });

  // Set before any request is served, so session binding reads the same source everywhere.

  configureClientIpHeader(env.CLIENT_IP_HEADER ?? null);

  const app = await NestFactory.create<NestFastifyApplication>(AppModule, adapter, { bufferLogs: true });
  app.useLogger(new PinoNestLogger(logger));

  const fastify = app.getHttpAdapter().getInstance();
  fastify.addHook('onRequest', (request, reply, done) => {
    void reply.header('x-request-id', request.id);
    requestContext.run({ correlationId: request.id }, done);
  });

  // POST /auth/transaction (and its GET status check) is called directly from a Business Unit's browser
  // code (core-embed-react), not only server-to-server. It carries no cookie/credential, and the real
  // trust decision - is this origin registered for this client_id? - is enforced inside the route handler
  // regardless of CORS: an unregistered origin still gets ORIGIN_NOT_ALLOWED. Reflecting the caller's
  // Origin here only lets the browser read a response it was always allowed to obtain another way
  // (e.g. a server-to-server call). No other route gets this treatment.
  fastify.addHook('onRequest', (request, reply, done) => {
    const path = request.url.split('?')[0];
    const isTransactionEndpoint = path === '/auth/transaction' || path.startsWith('/auth/transaction/') || path === '/v1/auth/transaction' || path.startsWith('/v1/auth/transaction/');
    const origin = request.headers.origin;
    if (isTransactionEndpoint && typeof origin === 'string') {
      void reply.header('access-control-allow-origin', origin);
      void reply.header('vary', 'origin');
      if (request.method === 'OPTIONS') {
        reply
          .header('access-control-allow-methods', 'GET, POST, OPTIONS')
          .header('access-control-allow-headers', 'content-type')
          .header('access-control-max-age', '600')
          .code(204)
          .send();
        return;
      }
    }
    done();
  });

  await app.register(fastifyCookie as never);
  // application/x-www-form-urlencoded (federation logout form posts) is parsed by Nest's Fastify adapter itself.
  await app.register(helmet as never, {
    contentSecurityPolicy: false, // set per response: login pages need a dynamic frame-ancestors
    frameguard: false, // X-Frame-Options cannot express an allow-list; CSP frame-ancestors is authoritative
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true, preload: false } : false,
  });

  fastify.addHook('onSend', (request, reply, _payload, done) => {
    const path = request.url.split('?')[0];
    if (!reply.hasHeader('content-security-policy') && !path.startsWith('/docs') && !path.startsWith('/assets/')) {
      void reply.header('content-security-policy', DEFAULT_CSP);
      void reply.header('x-frame-options', 'DENY');
    }
    if (!reply.hasHeader('cache-control')) void reply.header('cache-control', path.startsWith('/assets/') ? 'public, max-age=3600' : 'no-store');
    done();
  });

  app.useStaticAssets({ root: join(__dirname, '..', 'public'), prefix: '/assets/', decorateReply: false, index: false, dotfiles: 'deny' });
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: VERSION_NEUTRAL });
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
  app.useGlobalFilters(new GlobalExceptionFilter());
  app.enableShutdownHooks();

  const logout = app.get(LogoutService);
  fastify.addHook('onClose', async () => logout.drain());

  if (env.SWAGGER_ENABLED) {
    SwaggerModule.setup('docs', app, () => SwaggerModule.createDocument(app, buildOpenApiConfig()));
  }
  return app;
}
