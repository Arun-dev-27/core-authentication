/**
 * Miqaat Login Page - a separate application (http://localhost:3100, client login-web-dev) that signs users in with
 * EMBEDDED login and verifies the two halves of a sign-in separately, each with the keys of the service that signed it:
 *
 *   1. Authentication  core_assertion       signed by Identity       -> Identity JWKS       (:3001/.well-known/jwks.json)
 *   2. Authorization   authorization_token  signed by Authorization  -> Authorization JWKS  (:3002/.well-known/jwks.json)
 *
 * Then it creates its own session. Also: sign out, sign out everywhere, back-channel logout, administrator force logout.
 *
 *   (core-authorization)  npm run seed && npm run seed:access   # registers client login-web-dev + service principal login-backend
 *   (core-authentication) npm run example:login                 # http://localhost:3100
 *
 * Reference implementation for local development: sessions are kept in memory.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import fastifyCookie from '@fastify/cookie';
import fastifyFormbody from '@fastify/formbody';
import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import { createRemoteJWKSet, decodeProtectedHeader, errors, JWTPayload, jwtVerify } from 'jose';
import { AssertionVerificationError, CoreAssertionVerifier, MemoryReplayStore } from '../bu-reference-app/src/core-assertion-verifier';
import { ServiceCredentials } from '../bu-reference-app/src/service-credentials';

const setting = (name: string, fallback: string) => process.env[name] || fallback;
const config = {
  appName: 'Miqaat Login Page',
  port: Number(setting('LOGIN_PAGE_PORT', '3100')),
  clientId: setting('LOGIN_PAGE_CLIENT_ID', 'login-web-dev'),
  principalId: setting('LOGIN_PAGE_SERVICE_PRINCIPAL', 'login-backend'),
  identityOrigin: new URL(setting('IDENTITY_BASE_URL', 'http://localhost:3001')).origin,
  identityIssuer: new URL(setting('IDENTITY_ISSUER', 'http://localhost:3001')).origin,
  authzBaseUrl: setting('AUTHZ_BASE_URL', 'http://localhost:3002').replace(/\/+$/, ''),
  authzIssuer: setting('AUTHZ_ISSUER', 'http://localhost:3002').replace(/\/+$/, ''),
  authzAudience: setting('AUTHZ_AUDIENCE', 'miqaat-core-authorization'),
  sessionTtlSeconds: Number(setting('LOGIN_PAGE_SESSION_TTL_SECONDS', '28800')),
  cookieSecure: process.env.COOKIE_SECURE !== 'false',
};
const APP_ORIGIN = new URL(setting('LOGIN_PAGE_ORIGIN', `http://localhost:${config.port}`)).origin;
// JWKS locations come from configuration only - never from a token or a response.
const IDENTITY_JWKS_URI = `${config.identityOrigin}/.well-known/jwks.json`;
const AUTHZ_JWKS_URI = `${config.authzBaseUrl}/.well-known/jwks.json`;
const AUTHORIZATION_TOKEN_TYP = 'authz+jwt';
const TXN_COOKIE = 'login_txn';
const SESSION_COOKIE = 'login_session';
const ITS_ID = /^[A-Za-z0-9._-]{1,64}$/;
const SID = /^[A-Za-z0-9._~-]{8,128}$/;
const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

interface VerificationResult {
  verified: true;
  signed_by: string;
  issuer: string;
  jwks_uri: string;
  kid: string;
  alg: string;
  typ: string;
  checks: string[];
  claims: JWTPayload;
}
interface AuthorizationResult extends VerificationResult {
  access: 'GRANTED' | 'DENIED';
  reason?: string;
  roles: { role_name?: string; scope_type?: string; scope_id?: string | null }[];
  modules: string[];
  permissions: string[];
}
interface Session {
  id: string;
  itsId: string;
  sid: string;
  createdAt: number;
  expiresAt: number;
  authentication: VerificationResult;
  authorization: AuthorizationResult;
}

class StepError extends Error {
  constructor(
    readonly step: 'authentication' | 'authorization',
    readonly code: string,
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const pendingLogins = new Map<string, { state: string; expires: number }>();
const sessions = new Map<string, Session>();
const endedSessions = new Map<string, { reason: string; at: string }>();

// 1. Authentication: Identity's keys only.
const authnVerifier = new CoreAssertionVerifier({ issuer: config.identityIssuer, clientId: config.clientId, jwksUri: IDENTITY_JWKS_URI, replayStore: new MemoryReplayStore() });
// 2. Authorization: the Authorization service's own keys only.
const authzKeys = createRemoteJWKSet(new URL(AUTHZ_JWKS_URI), { cacheMaxAge: 10 * 60_000, cooldownDuration: 30_000, timeoutDuration: 5_000 });
const authzReplay = new MemoryReplayStore();
// This backend's service key: signs the service token it presents to Authorization (public key at /.well-known/jwks.json).
const credentials = ServiceCredentials.load(config.principalId, process.env.SERVICE_KEY_FILE || join(__dirname, '.keys', `${config.principalId}.pem`));

const publicDir = join(__dirname, 'public');
const app = Fastify({
  logger: { level: 'info', redact: ['req.headers.cookie', 'req.headers.authorization', '*.core_assertion', '*.logout_token', '*.admin_token', '*.authorization_token'] },
  bodyLimit: 32 * 1024,
});
void app.register(fastifyCookie);
void app.register(fastifyFormbody);

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

const cookieBase = { httpOnly: true, secure: config.cookieSecure, path: '/', sameSite: 'lax' as const };

function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb) && a.length === b.length;
}

function currentSession(req: FastifyRequest): Session | null {
  const id = req.cookies[SESSION_COOKIE];
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(session.id);
    return null;
  }
  return session;
}

function endSession(id: string, reason: string | null) {
  sessions.delete(id);
  if (reason) endedSessions.set(id, { reason, at: new Date().toISOString() });
}

function joseCode(error: unknown): string {
  if (error instanceof errors.JWTExpired) return 'EXPIRED';
  if (error instanceof errors.JWTClaimValidationFailed) return `CLAIM_INVALID_${String(error.claim).toUpperCase()}`;
  if (error instanceof errors.JWKSNoMatchingKey) return 'UNKNOWN_KID';
  if (error instanceof errors.JWSSignatureVerificationFailed) return 'SIGNATURE_INVALID';
  if (error instanceof errors.JOSEAlgNotAllowed) return 'ALG_NOT_ALLOWED';
  if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return 'JWKS_UNAVAILABLE';
  return 'INVALID_TOKEN';
}

// ------------------------------------------------------------------ 1. authentication (Identity JWKS)
async function verifyAuthentication(assertion: string, transactionId: string) {
  let verified;
  try {
    verified = await authnVerifier.verifyLoginAssertion(assertion, { transactionId });
  } catch (error) {
    const code = error instanceof AssertionVerificationError ? error.code : 'VERIFICATION_ERROR';
    throw new StepError('authentication', code, 401, 'core_assertion could not be verified with the Identity JWKS');
  }
  const header = decodeProtectedHeader(assertion);
  const result: VerificationResult = {
    verified: true,
    signed_by: 'Miqaat Identity (authentication)',
    issuer: verified.issuer,
    jwks_uri: IDENTITY_JWKS_URI,
    kid: String(header.kid),
    alg: String(header.alg),
    typ: String(header.typ),
    checks: [
      `RS256 signature verified with key ${String(header.kid)} from the Identity JWKS`,
      `iss is ${config.identityIssuer}`,
      `aud is exactly ${config.clientId}`,
      'not expired, issued in the past, short lifetime (60 s)',
      'txn is the transaction this browser started',
      'jti used only once (replay blocked)',
    ],
    claims: { iss: verified.issuer, sub: verified.itsId, aud: verified.audience, sid: verified.sid, txn: verified.transactionId, jti: verified.jti, auth_time: verified.authTime, iat: verified.issuedAt, exp: verified.expiresAt },
  };
  return { itsId: verified.itsId, sid: verified.sid, result };
}

// ------------------------------------------------------------------ 2. authorization (Authorization JWKS)
async function fetchAuthorization(itsId: string): Promise<AuthorizationResult> {
  let res: Response;
  try {
    res = await fetch(`${config.authzBaseUrl}/authorization/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${await (await credentials).mint(config.authzAudience)}` },
      body: JSON.stringify({ its_id: itsId, client_id: config.clientId }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    throw new StepError('authorization', 'AUTHORIZATION_UNAVAILABLE', 503, 'The Authorization service did not answer');
  }
  const body = (await res.json().catch(() => ({}))) as { authorization_token?: unknown; error?: string; message?: string };
  if (!res.ok || typeof body.authorization_token !== 'string') {
    const hint = body.error === 'UNAUTHENTICATED' ? ' (is the login-backend service principal registered? run npm run seed in core-authorization)' : '';
    throw new StepError('authorization', body.error ?? 'AUTHORIZATION_UNAVAILABLE', 502, `${body.message ?? `Authorization responded ${res.status}`}${hint}`);
  }
  return verifyAuthorizationToken(body.authorization_token, itsId);
}

async function verifyAuthorizationToken(token: string, itsId: string): Promise<AuthorizationResult> {
  const fail = (code: string, message: string) => new StepError('authorization', code, 502, message);
  if (token.length > 16_384 || !JWS.test(token)) throw fail('MALFORMED', 'authorization_token is not a compact JWS');
  const header = decodeProtectedHeader(token);
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.typ !== AUTHORIZATION_TOKEN_TYP) {
    throw fail('HEADER_INVALID', `authorization_token must be RS256, carry a kid and typ ${AUTHORIZATION_TOKEN_TYP}`);
  }
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, authzKeys, {
      issuer: config.authzIssuer,
      audience: config.clientId,
      algorithms: ['RS256'],
      typ: AUTHORIZATION_TOKEN_TYP,
      clockTolerance: 5,
      maxTokenAge: '900s',
      requiredClaims: ['sub', 'jti', 'iat', 'exp', 'access'],
    }));
  } catch (error) {
    throw fail(joseCode(error), 'authorization_token could not be verified with the Authorization JWKS');
  }
  if (payload.aud !== config.clientId) throw fail('AUDIENCE_MISMATCH', 'aud must equal this client_id exactly');
  if (payload.sub !== itsId) throw fail('SUBJECT_MISMATCH', 'authorization_token is for a different user than the core_assertion');
  const ttl = Math.max(1, (payload.exp as number) - Math.floor(Date.now() / 1000) + 5);
  if (typeof payload.jti !== 'string' || !(await authzReplay.claim(payload.jti, ttl))) throw fail('REPLAYED', 'authorization_token already used');

  const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
  return {
    verified: true,
    signed_by: 'Miqaat Authorization (authorization)',
    issuer: String(payload.iss),
    jwks_uri: AUTHZ_JWKS_URI,
    kid: header.kid,
    alg: header.alg,
    typ: header.typ,
    checks: [
      `RS256 signature verified with key ${header.kid} from the Authorization JWKS`,
      `iss is ${config.authzIssuer}`,
      `aud is exactly ${config.clientId}`,
      'sub is the same ITS ID as the verified core_assertion',
      'not expired, jti used only once',
    ],
    access: payload.access === 'GRANTED' ? 'GRANTED' : 'DENIED',
    reason: typeof payload.reason === 'string' ? payload.reason : undefined,
    roles: Array.isArray(payload.roles) ? (payload.roles as AuthorizationResult['roles']) : [],
    modules: strings(payload.modules),
    permissions: strings(payload.permissions),
    claims: payload,
  };
}

// ------------------------------------------------------------------ static + config
app.get('/', async (_req, reply) => reply.type('text/html; charset=utf-8').send(readFileSync(join(publicDir, 'index.html'))));
for (const file of ['app.js', 'app.css']) {
  app.get(`/${file}`, async (_req, reply) =>
    reply.type(file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8').header('cache-control', 'no-cache').send(readFileSync(join(publicDir, file))),
  );
}

app.get('/api/config', async () => ({
  app_name: config.appName,
  app_origin: APP_ORIGIN,
  client_id: config.clientId,
  identity_origin: config.identityOrigin,
  authentication_jwks_uri: IDENTITY_JWKS_URI,
  authorization_jwks_uri: AUTHZ_JWKS_URI,
}));

/** Both key sets, fetched live, so the page can show that authentication and authorization use different keys. */
app.get('/api/jwks', async () => {
  const load = async (uri: string, signedBy: string) => {
    try {
      const res = await fetch(uri, { signal: AbortSignal.timeout(4000) });
      const body = (await res.json()) as { keys?: { kid?: string; alg?: string; kty?: string; use?: string }[] };
      return { signed_by: signedBy, jwks_uri: uri, status: res.status, keys: (body.keys ?? []).map((k) => ({ kid: k.kid, alg: k.alg, kty: k.kty, use: k.use })) };
    } catch {
      return { signed_by: signedBy, jwks_uri: uri, status: 0, keys: [], error: 'not reachable' };
    }
  };
  const [authentication, authorization] = await Promise.all([load(IDENTITY_JWKS_URI, 'Miqaat Identity'), load(AUTHZ_JWKS_URI, 'Miqaat Authorization')]);
  return { authentication, authorization };
});

/** Public key of this backend's service principal (login-backend); Authorization verifies our service tokens with it. */
app.get('/.well-known/jwks.json', async (_req, reply) => reply.header('cache-control', 'public, max-age=300').send((await credentials).jwks()));

// ------------------------------------------------------------------ embedded login
app.post<{ Body: { display?: string } }>('/auth/core/start', async (req, reply) => {
  const display = req.body?.display === 'page' ? 'page' : 'embed';
  const state = randomBytes(24).toString('base64url');
  const request =
    display === 'embed'
      ? { client_id: config.clientId, state, origin: APP_ORIGIN, display }
      : { client_id: config.clientId, state, redirect_uri: `${APP_ORIGIN}/auth/core/callback`, display };
  let res: Response;
  try {
    res = await fetch(`${config.identityOrigin}/auth/transaction`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request), signal: AbortSignal.timeout(5000) });
  } catch {
    return reply.status(503).send({ error: 'IDENTITY_UNAVAILABLE', message: 'Miqaat Identity did not answer' });
  }
  const body = (await res.json().catch(() => ({}))) as { transaction_id?: string; login_url?: string; expires_in?: number; error?: string; message?: string };
  if (!res.ok || !body.transaction_id || !body.login_url) {
    const hint = body.error === 'CLIENT_NOT_FOUND' ? 'Register the client: npm run seed (core-authorization)' : undefined;
    return reply.status(res.ok ? 502 : res.status).send({ error: body.error ?? 'TRANSACTION_FAILED', message: body.message, hint });
  }
  pendingLogins.set(body.transaction_id, { state, expires: Date.now() + (body.expires_in ?? 300) * 1000 });
  reply.setCookie(TXN_COOKIE, body.transaction_id, { ...cookieBase, path: '/auth/core', maxAge: 300 });
  return { transaction_id: body.transaction_id, state, login_url: body.login_url, display, expires_in: body.expires_in ?? 300 };
});

function finish(reply: FastifyReply, form: boolean, status: number, body: Record<string, unknown>) {
  if (form) return reply.redirect(status === 200 ? '/' : `/?error=${encodeURIComponent(String(body.error ?? status))}`, 303);
  return reply.status(status).send(body);
}

app.post<{ Body: { transaction_id?: unknown; state?: unknown; core_assertion?: unknown } }>('/auth/core/callback', async (req, reply) => {
  const form = (req.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded');
  const { transaction_id: transactionId, state, core_assertion: assertion } = req.body ?? {};
  if (typeof transactionId !== 'string' || typeof state !== 'string' || typeof assertion !== 'string') {
    return finish(reply, form, 400, { signed_in: false, step: 'callback', error: 'INVALID_CALLBACK' });
  }

  // the transaction was started by THIS browser, once, and the state matches
  const cookieTxn = req.cookies[TXN_COOKIE];
  const pending = pendingLogins.get(transactionId);
  pendingLogins.delete(transactionId);
  reply.clearCookie(TXN_COOKIE, { ...cookieBase, path: '/auth/core' });
  if (!cookieTxn || !safeEqual(cookieTxn, transactionId)) return finish(reply, form, 400, { signed_in: false, step: 'callback', error: 'LOGIN_TRANSACTION_MISMATCH' });
  if (!pending || pending.expires <= Date.now()) return finish(reply, form, 400, { signed_in: false, step: 'callback', error: 'LOGIN_TRANSACTION_EXPIRED' });
  if (!safeEqual(pending.state, state)) return finish(reply, form, 400, { signed_in: false, step: 'callback', error: 'STATE_MISMATCH' });

  // 1. authentication - Identity JWKS
  let authn;
  try {
    authn = await verifyAuthentication(assertion, transactionId);
  } catch (error) {
    const e = error as StepError;
    req.log.warn({ step: e.step, code: e.code }, 'sign-in rejected');
    return finish(reply, form, e.status, { signed_in: false, step: e.step, error: e.code, message: e.message });
  }

  // 2. authorization - Authorization JWKS
  let authorization: AuthorizationResult;
  try {
    authorization = await fetchAuthorization(authn.itsId);
  } catch (error) {
    const e = error instanceof StepError ? error : new StepError('authorization', 'AUTHORIZATION_ERROR', 502, 'authorization failed');
    req.log.warn({ step: e.step, code: e.code, its_id: authn.itsId }, 'sign-in rejected');
    return finish(reply, form, e.status, { signed_in: false, step: e.step, error: e.code, message: e.message, authentication: authn.result });
  }
  if (authorization.access !== 'GRANTED') {
    req.log.info({ its_id: authn.itsId, reason: authorization.reason }, 'authenticated but not authorized');
    return finish(reply, form, 403, { signed_in: false, step: 'authorization', error: 'ACCESS_DENIED', reason: authorization.reason, authentication: authn.result, authorization });
  }

  // 3. this application's own session
  const id = randomBytes(32).toString('base64url');
  const now = Date.now();
  sessions.set(id, { id, itsId: authn.itsId, sid: authn.sid, createdAt: now, expiresAt: now + config.sessionTtlSeconds * 1000, authentication: authn.result, authorization });
  reply.setCookie(SESSION_COOKIE, id, { ...cookieBase, maxAge: config.sessionTtlSeconds });
  req.log.info({ its_id: authn.itsId, sid: authn.sid }, 'signed in');
  return finish(reply, form, 200, { signed_in: true, authentication: authn.result, authorization });
});

/** initiate_login_uri: the Core Portal launcher opens the page, which starts the embedded login (SSO if a session exists). */
app.get('/auth/core/login', async (_req, reply) => reply.redirect('/', 302));

// ------------------------------------------------------------------ session
app.get('/api/me', async (req, reply) => {
  const session = currentSession(req);
  if (session) {
    return {
      signed_in: true,
      its_id: session.itsId,
      sid: session.sid,
      client_id: config.clientId,
      created_at: new Date(session.createdAt).toISOString(),
      expires_at: new Date(session.expiresAt).toISOString(),
      authentication: session.authentication,
      authorization: session.authorization,
    };
  }
  const id = req.cookies[SESSION_COOKIE];
  const ended = id ? endedSessions.get(id) : undefined;
  if (id) {
    endedSessions.delete(id);
    reply.clearCookie(SESSION_COOKIE, cookieBase);
  }
  return reply.status(401).send({ signed_in: false, error: 'NOT_AUTHENTICATED', ...(ended ? { ended } : {}) });
});

/** Ask Authorization again (e.g. after a role change); a user who lost access is signed out of this page. */
app.post('/api/authorization/refresh', async (req, reply) => {
  const session = currentSession(req);
  if (!session) return reply.status(401).send({ error: 'NOT_AUTHENTICATED' });
  try {
    const authorization = await fetchAuthorization(session.itsId);
    if (authorization.access !== 'GRANTED') {
      endSession(session.id, `Access to this page was removed (${authorization.reason ?? 'DENIED'}).`);
      return reply.status(403).send({ error: 'ACCESS_DENIED', reason: authorization.reason, authorization });
    }
    session.authorization = authorization;
    return { refreshed: true, authorization };
  } catch (error) {
    const e = error instanceof StepError ? error : new StepError('authorization', 'AUTHORIZATION_ERROR', 502, 'authorization failed');
    return reply.status(e.status).send({ error: e.code, message: e.message });
  }
});

app.post('/auth/logout', async (req, reply) => {
  const session = currentSession(req);
  if (session) endSession(session.id, null);
  reply.clearCookie(SESSION_COOKIE, cookieBase);
  return { logged_out: true, scope: 'application' };
});

/** Ends this page's session and returns the form the browser posts top-level to Identity /federation/logout. */
app.post('/auth/logout/federated', async (req, reply) => {
  const session = currentSession(req);
  if (!session) return reply.status(401).send({ error: 'NOT_AUTHENTICATED' });
  endSession(session.id, null);
  reply.clearCookie(SESSION_COOKIE, cookieBase);
  return {
    action: `${config.identityOrigin}/federation/logout`,
    fields: { client_id: config.clientId, logout_hint: session.sid, post_logout_redirect_uri: `${APP_ORIGIN}/logout/callback`, state: randomBytes(16).toString('base64url') },
  };
});

/** Back-channel logout: Identity calls this (server to server) on sign out everywhere and on administrator force logout. */
app.post<{ Body: { logout_token?: unknown } }>('/auth/core/logout', async (req, reply) => {
  reply.header('cache-control', 'no-store');
  try {
    const token = await authnVerifier.verifyLogoutToken(req.body?.logout_token);
    let ended = 0;
    for (const session of [...sessions.values()]) {
      if (session.sid === token.sid) {
        endSession(session.id, 'Your Miqaat session was ended by Miqaat Identity (sign out everywhere, or an administrator force logout).');
        ended++;
      }
    }
    req.log.info({ sid: token.sid, ended }, 'back-channel logout processed');
    return reply.status(200).send();
  } catch (error) {
    const code = error instanceof AssertionVerificationError ? error.code : 'INVALID_LOGOUT_TOKEN';
    req.log.warn({ code }, 'back-channel logout rejected');
    return reply.status(400).send({ error: code });
  }
});

app.get('/logout/callback', async (_req, reply) => reply.redirect('/?signed_out=everywhere', 302));

// ------------------------------------------------------------------ administrator force logout
/**
 * Development tool: forwards an administrator's Identity access token (audience identity, CORE workspace with
 * USER_MGMT edit, from POST /select-scope) to Identity POST /federation/logout. The token is not stored or logged.
 */
app.post<{ Body: { admin_token?: unknown; its_id?: unknown; sid?: unknown } }>('/api/admin/force-logout', async (req, reply) => {
  const { admin_token: adminToken, its_id: itsId, sid } = req.body ?? {};
  if (typeof adminToken !== 'string' || adminToken.length > 8192 || !JWS.test(adminToken.trim())) {
    return reply.status(400).send({ error: 'INVALID_ADMIN_TOKEN', message: 'Paste the administrator access token (audience identity) returned by POST /select-scope.' });
  }
  const hasIts = typeof itsId === 'string' && itsId.trim() !== '';
  const hasSid = typeof sid === 'string' && sid.trim() !== '';
  if (hasIts === hasSid) return reply.status(400).send({ error: 'INVALID_TARGET', message: 'Give either an ITS ID (all sessions of the user) or a sid (one session).' });
  const value = ((hasIts ? itsId : sid) as string).trim();
  if (!(hasIts ? ITS_ID : SID).test(value)) return reply.status(400).send({ error: 'INVALID_TARGET', message: hasIts ? 'ITS ID format is invalid.' : 'sid format is invalid.' });
  const target = hasIts ? { its_id: value } : { sid: value };

  let res: Response;
  try {
    res = await fetch(`${config.identityOrigin}/federation/logout`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${adminToken.trim()}` },
      body: JSON.stringify(target),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return reply.status(503).send({ error: 'IDENTITY_UNAVAILABLE', message: 'Miqaat Identity did not answer' });
  }
  const body = await res.json().catch(() => ({}));
  req.log.info({ target, status: res.status }, 'administrator force logout forwarded');
  return reply.status(res.status).send({ target, identity_status: res.status, identity_response: body });
});

// ------------------------------------------------------------------ housekeeping
setInterval(() => {
  const now = Date.now();
  for (const [id, p] of pendingLogins) if (p.expires <= now) pendingLogins.delete(id);
  for (const [id, s] of sessions) if (s.expiresAt <= now) sessions.delete(id);
  for (const [id, e] of endedSessions) if (Date.parse(e.at) < now - 3600_000) endedSessions.delete(id);
}, 60_000).unref();

app.listen({ port: config.port, host: '127.0.0.1' }).then(() => app.log.info(`${config.appName} on ${APP_ORIGIN} (client ${config.clientId})`));
