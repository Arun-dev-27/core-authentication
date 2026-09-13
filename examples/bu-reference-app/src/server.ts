/**
 * Reference Business Unit application (backend + minimal frontend).
 * One codebase, configured per application through env files:
 *
 *   npm run example:rms   -> http://localhost:4001  (client rms-web-dev)
 *   npm run example:ams   -> http://localhost:4002  (client ams-web-dev)
 *   npm run example:vms   -> http://localhost:4003  (client vms-web-dev)
 *
 * Demonstrates: embedded login iframe, postMessage validation, callback verification (JWKS, RS256,
 * iss/aud/exp/iat/txn/sid/jti replay), Core authorization check, local session, local logout,
 * federation logout and back-channel logout.
 */
import { randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import fastifyCookie from '@fastify/cookie';
import fastifyFormbody from '@fastify/formbody';
import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import Redis from 'ioredis';
import { AuthorizationClient } from './authorization-client';
import { AssertionVerificationError, CoreAssertionVerifier, RedisReplayStore } from './core-assertion-verifier';
import { LocalSessionStore } from './local-session-store';
import { ServiceCredentials } from './service-credentials';

const { values } = parseArgs({ options: { env: { type: 'string' } } });
if (values.env) process.loadEnvFile(values.env);

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const config = {
  appName: required('APP_NAME'),
  clientId: required('CLIENT_ID'),
  port: Number(required('PORT')),
  appOrigin: new URL(required('APP_ORIGIN')).origin,
  identityOrigin: new URL(required('IDENTITY_BASE_URL')).origin,
  issuer: new URL(required('IDENTITY_ISSUER')).origin,
  authzBaseUrl: required('AUTHZ_BASE_URL'),
  servicePrincipalId: required('SERVICE_PRINCIPAL_ID'),
  authzAudience: process.env.AUTHZ_AUDIENCE ?? 'miqaat-core-authorization',
  serviceKeyFile: process.env.SERVICE_KEY_FILE ?? '',
  redisUrl: required('REDIS_URL'),
  sessionCookie: required('SESSION_COOKIE_NAME'),
  demoModule: required('DEMO_MODULE'),
  demoActions: (process.env.DEMO_ACTIONS ?? 'view,create,update,delete').split(',').map((a) => a.trim()),
  cookieSecure: process.env.COOKIE_SECURE !== 'false',
  otherApps: (process.env.OTHER_APPS ?? '')
    .split(',')
    .filter(Boolean)
    .map((entry) => {
      const [name, url] = entry.split('|');
      return { name, url };
    }),
};
const loginCookie = `${config.sessionCookie.replace(/_session$/, '')}_login_txn`;

const redis = new Redis(config.redisUrl);
const sessions = new LocalSessionStore(redis, config.clientId);
// This backend's service-principal key (no API key): private key stays here, public key served at /.well-known/jwks.json.
const credentials = ServiceCredentials.load(config.servicePrincipalId, config.serviceKeyFile || join(__dirname, '..', '.keys', `${config.servicePrincipalId}.pem`));
const authz = new AuthorizationClient(config.authzBaseUrl, credentials, config.authzAudience, config.clientId, redis);
const verifier = new CoreAssertionVerifier({
  issuer: config.issuer,
  clientId: config.clientId,
  jwksUri: `${config.identityOrigin}/.well-known/jwks.json`,
  replayStore: new RedisReplayStore(redis, `bu:${config.clientId}:jti`),
});

const publicDir = join(__dirname, '..', 'public');
const indexTemplate = readFileSync(join(publicDir, 'index.html'), 'utf8');

const app = Fastify({ logger: { level: 'info', redact: ['req.headers.cookie', 'req.headers.authorization', '*.core_assertion', '*.logout_token'] }, bodyLimit: 32 * 1024 });
void app.register(fastifyCookie);
void app.register(fastifyFormbody);

/** Public JWKS of this backend's service key; the Authorization service verifies our service tokens with it. */
app.get('/.well-known/jwks.json', async (_req, reply) => reply.header('cache-control', 'public, max-age=300').send((await credentials).jwks()));

app.addHook('onSend', async (_req, reply) => {
  reply.header('x-content-type-options', 'nosniff');
  reply.header('referrer-policy', 'strict-origin-when-cross-origin');
  if (!reply.hasHeader('cache-control')) reply.header('cache-control', 'no-store');
  if (!reply.hasHeader('content-security-policy')) {
    reply.header(
      'content-security-policy',
      `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src ${config.identityOrigin}; form-action 'self' ${config.identityOrigin}; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`,
    );
  }
});

const cookieBase = { httpOnly: true, secure: config.cookieSecure, path: '/' };

function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb) && a.length === b.length;
}

async function currentSession(req: FastifyRequest) {
  return sessions.get(req.cookies[config.sessionCookie]);
}

function fail(reply: FastifyReply, status: number, error: string, form: boolean) {
  if (form) return reply.redirect(`/?error=${encodeURIComponent(error)}`, 303);
  return reply.status(status).send({ error });
}

// ---------------------------------------------------------------- frontend
app.get('/', async (_req, reply) => {
  const boot = JSON.stringify({
    appName: config.appName,
    clientId: config.clientId,
    identityOrigin: config.identityOrigin,
    module: config.demoModule,
    actions: config.demoActions,
    otherApps: config.otherApps,
  }).replace(/</g, '\\u003c');
  return reply.type('text/html; charset=utf-8').send(indexTemplate.replaceAll('{{APP_NAME}}', config.appName).replace('{{BOOT_JSON}}', boot));
});
for (const file of ['app.js', 'app.css']) {
  app.get(`/${file}`, async (_req, reply) =>
    reply.type(file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8').header('cache-control', 'no-cache').send(readFileSync(join(publicDir, file))),
  );
}

// ------------------------------------------------------------ login start
app.post<{ Body: { display?: string; prompt?: string } }>('/auth/core/start', async (req, reply) => {
  const display = req.body?.display === 'page' ? 'page' : 'embed';
  const transactionId = `txn_${randomBytes(18).toString('base64url')}`;
  const state = randomBytes(24).toString('base64url');
  await redis.set(`bu:${config.clientId}:login:${transactionId}`, JSON.stringify({ state, display }), 'EX', 300);

  // Binds the transaction to THIS browser. SameSite=None so it also survives the top-level form_post fallback.
  reply.setCookie(loginCookie, transactionId, { ...cookieBase, sameSite: 'none', secure: true, path: '/auth/core', maxAge: 300 });

  const params = new URLSearchParams({ client_id: config.clientId, transaction_id: transactionId, state });
  if (display === 'embed') params.set('origin', config.appOrigin);
  else params.set('display', 'page');
  if (req.body?.prompt === 'auto' || req.body?.prompt === 'login') params.set('prompt', req.body.prompt);
  return { transaction_id: transactionId, state, login_url: `${config.identityOrigin}/embed/login?${params.toString()}` };
});

/** initiate_login_uri used by the Core Portal launcher: start a silent SSO attempt. */
app.get('/auth/core/login', async (_req, reply) => reply.redirect('/?sso=auto', 302));

// --------------------------------------------------------------- callback
app.post<{ Body: { transaction_id?: unknown; state?: unknown; core_assertion?: unknown } }>('/auth/core/callback', async (req, reply) => {
  const form = (req.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded');
  const { transaction_id: transactionId, state, core_assertion: assertion } = req.body ?? {};
  if (typeof transactionId !== 'string' || typeof state !== 'string' || typeof assertion !== 'string') {
    return fail(reply, 400, 'INVALID_CALLBACK', form);
  }

  // 1-2. transaction + state (single use, bound to this browser)
  const cookieTxn = req.cookies[loginCookie];
  if (!cookieTxn || !safeEqual(cookieTxn, transactionId)) return fail(reply, 400, 'LOGIN_TRANSACTION_MISMATCH', form);
  const pendingRaw = await redis.getdel(`bu:${config.clientId}:login:${transactionId}`);
  reply.clearCookie(loginCookie, { ...cookieBase, sameSite: 'none', secure: true, path: '/auth/core' });
  if (!pendingRaw) return fail(reply, 400, 'LOGIN_TRANSACTION_EXPIRED', form);
  const pending = JSON.parse(pendingRaw) as { state: string };
  if (!safeEqual(pending.state, state)) return fail(reply, 400, 'STATE_MISMATCH', form);

  // 3-15. header/kid/JWKS/RS256/iss/aud/exp/iat/txn/sid/jti
  let verified;
  try {
    verified = await verifier.verifyLoginAssertion(assertion, { transactionId });
  } catch (error) {
    const code = error instanceof AssertionVerificationError ? error.code : 'VERIFICATION_ERROR';
    req.log.warn({ code, client_id: config.clientId }, 'core assertion rejected');
    return fail(reply, 401, code, form);
  }

  // 16-17. sub is trusted only now; map + authorize via Core Authorization (server-side)
  let effective;
  try {
    effective = await authz.effective(verified.itsId);
  } catch {
    return fail(reply, 503, 'AUTHORIZATION_UNAVAILABLE', form);
  }
  if (effective.access !== 'GRANTED') {
    req.log.info({ its_id: verified.itsId, reason: effective.reason }, 'application access denied');
    return fail(reply, 403, `ACCESS_DENIED:${effective.reason ?? 'UNKNOWN'}`, form);
  }

  // 18. local application session (independent of federation_session)
  const localId = await sessions.create({ its_id: verified.itsId, sid: verified.sid, auth_time: verified.authTime });
  reply.setCookie(config.sessionCookie, localId, { ...cookieBase, sameSite: 'lax', maxAge: 8 * 3600 });
  req.log.info({ its_id: verified.itsId, sid: verified.sid }, 'local session created');

  // 19. redirect into the application
  return form ? reply.redirect('/', 303) : reply.send({ redirect: '/' });
});

// ----------------------------------------------------------- app APIs
app.get('/api/me', async (req, reply) => {
  const session = await currentSession(req);
  if (!session) return reply.status(401).send({ error: 'NOT_AUTHENTICATED' });
  const effective = await authz.effective(session.its_id).catch(() => null);
  return { its_id: session.its_id, sid: session.sid, auth_time: session.auth_time, client_id: config.clientId, app_name: config.appName, effective };
});

/** Protected business API: every call enforces a permission server-side (never trusts the browser). */
app.get<{ Params: { action: string } }>('/api/demo/:action', async (req, reply) => {
  const session = await currentSession(req);
  if (!session) return reply.status(401).send({ error: 'NOT_AUTHENTICATED' });
  if (!/^[a-z0-9_-]{1,32}$/.test(req.params.action)) return reply.status(400).send({ error: 'INVALID_ACTION' });
  const permission = `${config.demoModule}_${req.params.action.toUpperCase()}`;
  const decision = await authz.check(session.its_id, permission, config.demoModule);
  if (!decision.allowed) return reply.status(403).send({ allowed: false, permission, reason: decision.reason });
  return { allowed: true, permission, data: { message: `${config.appName}: '${req.params.action}' on ${config.demoModule} succeeded`, at: new Date().toISOString() } };
});

// ----------------------------------------------------------------- logout
app.post('/auth/logout', async (req, reply) => {
  await sessions.destroy(req.cookies[config.sessionCookie]);
  reply.clearCookie(config.sessionCookie, { ...cookieBase, sameSite: 'lax' });
  return { logged_out: true, scope: 'application' };
});

/** Ends the local session and returns the form the browser must POST (top-level) to Identity Federation. */
app.post('/auth/logout/federated', async (req, reply) => {
  const session = await sessions.destroy(req.cookies[config.sessionCookie]);
  reply.clearCookie(config.sessionCookie, { ...cookieBase, sameSite: 'lax' });
  return {
    action: `${config.identityOrigin}/federation/logout`,
    fields: {
      client_id: config.clientId,
      logout_hint: session?.sid ?? '',
      post_logout_redirect_uri: `${config.appOrigin}/logout/callback`,
      state: randomBytes(16).toString('base64url'),
    },
  };
});

/** Back-channel logout endpoint called server-to-server by Identity Federation. */
app.post<{ Body: { logout_token?: unknown } }>('/auth/core/logout', async (req, reply) => {
  reply.header('cache-control', 'no-store');
  try {
    const token = await verifier.verifyLogoutToken(req.body?.logout_token);
    const destroyed = await sessions.destroyBySid(token.sid);
    if (token.itsId) await authz.forget(token.itsId);
    req.log.info({ sid: token.sid, destroyed }, 'back-channel logout processed');
    return reply.status(200).send();
  } catch (error) {
    const code = error instanceof AssertionVerificationError ? error.code : 'INVALID_LOGOUT_TOKEN';
    req.log.warn({ code }, 'back-channel logout rejected');
    return reply.status(400).send({ error: code });
  }
});

app.get('/logout/callback', async (_req, reply) => reply.redirect('/?logged_out=1', 302));

app.listen({ port: config.port, host: '127.0.0.1' }).then(() => {
  app.log.info(`${config.appName} (${config.clientId}) listening on ${config.appOrigin}`);
});
