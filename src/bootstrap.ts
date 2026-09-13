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

  const app = await NestFactory.create<NestFastifyApplication>(AppModule, adapter, { bufferLogs: true });
  app.useLogger(new PinoNestLogger(logger));

  const fastify = app.getHttpAdapter().getInstance();
  fastify.addHook('onRequest', (request, reply, done) => {
    void reply.header('x-request-id', request.id);
    requestContext.run({ correlationId: request.id }, done);
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
