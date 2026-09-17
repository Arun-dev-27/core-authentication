import { Server, createServer } from 'node:http';
import { AddressInfo } from 'node:net';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import Redis from 'ioredis';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { DataSource } from 'typeorm';
import { loadEnv } from '@config/configuration';
import { buildDataSourceOptions } from '@core/database/data-source-options';
import { AssertionService } from '@modules/assertions/services/assertion.service';
import { AuthzClient } from '@modules/authorization-client/services/authz-client.service';
import { ClientsStoreService } from '@modules/clients/services/clients-store.service';
import { LogoutService } from '@modules/federation/services/logout.service';
import { TransactionService } from '@modules/transactions/services/transaction.service';
import { FileKeyProvider } from '@modules/keys/services/key-providers';
import { KeyStore } from '@modules/keys/services/key-store.service';
import { rotateKeyset } from '@modules/keys/services/keyset';
import { FederationClientConfig } from '@shared/types/federation-client.types';
import { AssertionVerificationError, CoreAssertionVerifier, MemoryReplayStore } from '../../examples/bu-reference-app/src/core-assertion-verifier';
import { createApp } from '../../src/bootstrap';

/**
 * End-to-end federation flow against an EXISTING identity_db (schema, synced tables and the 8 auth tables must
 * already exist) and Redis. The test creates, alters and deletes nothing in the database: it signs in as users
 * that already exist, given in .env.test (scenarios whose variables are unset are skipped):
 *
 *   E2E_ITS_ID / E2E_PASSWORD                              active, eligible, login allowed   (required)
 *   E2E_LOCK_ITS_ID / E2E_LOCK_PASSWORD                    any valid user; LOCKED for LOGIN_ACCOUNT_LOCK_SECONDS by the test
 *   E2E_INELIGIBLE_ITS_ID / E2E_INELIGIBLE_PASSWORD        not in user_eligible
 *   E2E_INACTIVE_ITS_ID / E2E_INACTIVE_PASSWORD            mumin_master.status_id <> 3
 *   E2E_NOT_ALLOWED_ITS_ID / E2E_NOT_ALLOWED_PASSWORD      users.allow_login = false
 *   E2E_FLUSH_REDIS=true                                   flush REDIS_URL's db first (only a private test Redis db)
 * The Authorization service is replaced by an in-memory client registry; back-channel logout
 * endpoints are a local HTTP server. Run: docker compose up -d && npm run test:e2e
 */

const env = loadEnv();
const ISSUER = new URL(env.ISSUER).origin;
const RMS = 'https://rms.example.test';
const AMS = 'https://ams.example.test';
const need = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set in .env.test to an existing identity_db user`);
  return value;
};
const MEMBER = need('E2E_ITS_ID');
const PASSWORD = need('E2E_PASSWORD');
const optionalUser = (prefix: string) => {
  const itsId = process.env[`${prefix}_ITS_ID`];
  const password = process.env[`${prefix}_PASSWORD`];
  return itsId && password ? { itsId, password } : null;
};
const LOCK = optionalUser('E2E_LOCK');
const INELIGIBLE = optionalUser('E2E_INELIGIBLE');
const INACTIVE = optionalUser('E2E_INACTIVE');
const NOT_ALLOWED = optionalUser('E2E_NOT_ALLOWED');
const itWith = <T>(user: T | null) => (user ? it : it.skip);

let app: NestFastifyApplication;
let db: DataSource;
let redis: Redis;
let backchannel: Server;
let backchannelBase = '';
const receivedLogoutTokens: { path: string; token: string }[] = [];
const keyProvider = new FileKeyProvider(env.SIGNING_KEYS_FILE);

function client(id: string, origin: string, overrides: Partial<FederationClientConfig> = {}): FederationClientConfig {
  return {
    client_id: id,
    name: id,
    application_code: id.split('-')[0],
    application_name: `${id.split('-')[0].toUpperCase()} Web`,
    business_unit: 'TEST',
    utility: null,
    environment: 'TEST',
    client_type: 'WEB',
    authentication_mode: 'EMBEDDED_OR_REDIRECT',
    status: 'ACTIVE',
    allowed_embed_origins: [origin],
    callback_uri: `${origin}/auth/core/callback`,
    callback_uris: [`${origin}/auth/core/callback`],
    back_channel_logout_uri: `${backchannelBase}/${id}`,
    post_logout_redirect_uri: `${origin}/logout/callback`,
    post_logout_redirect_uris: [`${origin}/logout/callback`],
    initiate_login_uri: `${origin}/auth/core/login`,
    config_version: 'test',
    ...overrides,
  };
}

function registry(): Record<string, FederationClientConfig> {
  return {
    'rms-web-test': client('rms-web-test', RMS),
    'ams-web-test': client('ams-web-test', AMS),
    'vms-web-suspended': client('vms-web-suspended', 'https://vms.example.test', { status: 'SUSPENDED' }),
    'legacy-redirect-only': client('legacy-redirect-only', 'https://legacy.example.test', { authentication_mode: 'REDIRECT' }),
  };
}

function bootOf(html: string) {
  const match = /<script type="application\/json" id="miqaat-boot">(.*?)<\/script>/s.exec(html);
  if (!match) throw new Error('boot block not found');
  return JSON.parse(match[1]) as { transaction_id: string; csrf: string; state: string; target_origin: string; session: { its_id: string } | null };
}

let txnCounter = 0;
async function openLogin(clientId: string, opts: { origin?: string; cookie?: string; query?: Record<string, string> } = {}) {
  const txn = `txn-e2e-${Date.now()}-${txnCounter++}`;
  const query = new URLSearchParams({ client_id: clientId, transaction_id: txn, state: `state-${txn}`, ...(opts.origin ? { origin: opts.origin } : {}), ...(opts.query ?? {}) });
  const res = await app.inject({ method: 'GET', url: `/embed/login?${query.toString()}`, headers: opts.cookie ? { cookie: opts.cookie } : {} });
  return { res, boot: res.statusCode === 200 ? bootOf(res.body) : null, txn, state: `state-${txn}` };
}

async function postLogin(boot: { transaction_id: string; csrf: string }, clientId: string, body: Record<string, string>, headers: Record<string, string> = {}) {
  return app.inject({
    method: 'POST',
    url: '/embed/login',
    headers: { origin: ISSUER, 'x-csrf-token': boot.csrf, 'content-type': 'application/json', ...headers },
    payload: { transaction_id: boot.transaction_id, client_id: clientId, ...body },
  });
}

function sessionCookie(res: { cookies: { name: string; value: string }[] }) {
  const cookie = res.cookies.find((c) => c.name === env.SESSION_COOKIE_NAME);
  return cookie ? `${cookie.name}=${cookie.value}` : '';
}

async function verifierFor(clientId: string, store = new MemoryReplayStore()) {
  const jwks = (await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json();
  return new CoreAssertionVerifier({ issuer: ISSUER, clientId, jwksUri: 'unused', replayStore: store, keyResolver: createLocalJWKSet(jwks) });
}

beforeAll(async () => {
  // fresh 2048-bit test keyset (fast) with exactly one ACTIVE key
  await keyProvider.save(rotateKeyset([], 'generate', { bits: 2048 }));

  backchannel = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      receivedLogoutTokens.push({ path: req.url ?? '', token: new URLSearchParams(body).get('logout_token') ?? '' });
      res.writeHead(200).end();
    });
  });
  await new Promise<void>((resolve) => backchannel.listen(0, '127.0.0.1', resolve));
  backchannelBase = `http://127.0.0.1:${(backchannel.address() as AddressInfo).port}`;

  db = new DataSource(buildDataSourceOptions(env));
  await db.initialize();

  redis = new Redis(env.REDIS_URL);
  if (process.env.E2E_FLUSH_REDIS === 'true') await redis.flushdb();

  app = await createApp(env);
  const authz = app.get(AuthzClient);
  jest.spyOn(app.get(ClientsStoreService), 'findByClientId').mockImplementation(async (id: string) => registry()[id] ?? null);
  jest.spyOn(authz, 'launchableApplications').mockResolvedValue([]);
  jest.spyOn(authz, 'syncUser').mockResolvedValue();
  jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Test Member', requires_scope_selection: false, assignments: [] });
  jest.spyOn(authz, 'resolveAssignment').mockResolvedValue(null);
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
});

afterAll(async () => {
  await app?.close();
  await redis?.quit();
  await db?.destroy();
  await new Promise((resolve) => backchannel?.close(resolve));
});

describe('discovery', () => {
  it('publishes only public RSA parameters in JWKS', async () => {
    const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['cache-control']).toContain('max-age=300');
    const { keys } = res.json();
    expect(keys).toHaveLength(1);
    expect(Object.keys(keys[0]).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);
  });

  it('serves health and readiness', async () => {
    expect((await app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
    const ready = await app.inject({ method: 'GET', url: '/health/ready' });
    expect(ready.json().checks).toMatchObject({ database: 'up', redis: 'up', signing_keys: 'up' });
  });
});

describe('embedded login page validation', () => {
  it('renders for an ACTIVE client with exact frame-ancestors and no wildcard', async () => {
    const { res, boot } = await openLogin('rms-web-test', { origin: RMS });
    expect(res.statusCode).toBe(200);
    const csp = res.headers['content-security-policy'] as string;
    expect(csp).toContain(`frame-ancestors ${RMS};`);
    expect(csp).not.toContain('*');
    expect(res.headers['x-frame-options']).toBeUndefined();
    expect(res.headers['cache-control']).toBe('no-store');
    expect(boot!.target_origin).toBe(RMS);
    expect(boot!.csrf).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('rejects an unregistered parent origin with a non-frameable error page', async () => {
    const { res } = await openLogin('rms-web-test', { origin: 'https://evil.example.test' });
    expect(res.statusCode).toBe(403);
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
  });

  it('rejects look-alike origins and unregistered callbacks', async () => {
    expect((await openLogin('rms-web-test', { origin: `${RMS}.evil.test` })).res.statusCode).toBe(403);
    expect((await openLogin('rms-web-test', { origin: RMS, query: { redirect_uri: 'https://evil.example.test/cb' } })).res.statusCode).toBe(400);
  });

  it('rejects unknown, suspended and redirect-only (for embed) clients', async () => {
    expect((await openLogin('does-not-exist')).res.statusCode).toBe(400);
    expect((await openLogin('vms-web-suspended')).res.statusCode).toBe(403);
    expect((await openLogin('legacy-redirect-only')).res.statusCode).toBe(403);
  });

  it('refuses to reuse a transaction id with different parameters', async () => {
    const first = await openLogin('rms-web-test', { origin: RMS });
    const res = await app.inject({ method: 'GET', url: `/embed/login?client_id=ams-web-test&transaction_id=${first.txn}&state=${first.state}` });
    expect(res.statusCode).toBe(409);
  });

  it('explains an embed link opened in a browser tab and links to the registered application', async () => {
    const txn = `txn-e2e-top-${Date.now()}`;
    const url = `/embed/login?client_id=rms-web-test&transaction_id=${txn}&state=state-${txn}&origin=${encodeURIComponent(RMS)}`;
    const tab = await app.inject({ method: 'GET', url, headers: { 'sec-fetch-dest': 'document' } });
    expect(tab.statusCode).toBe(400);
    expect(tab.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(tab.body).toContain('Open this sign-in inside the application');
    expect(tab.body).toContain(`href="${RMS}/?login_url=${encodeURIComponent(`${ISSUER}${url}`)}"`);
    expect(tab.body).not.toContain('miqaat-error');
    // the same link works inside the application's iframe
    expect((await app.inject({ method: 'GET', url, headers: { 'sec-fetch-dest': 'iframe', referer: `${RMS}/` } })).statusCode).toBe(200);
    // an unregistered origin gets no link
    const evilTab = await app.inject({ method: 'GET', url: url.replace(encodeURIComponent(RMS), encodeURIComponent('https://evil.example.test')), headers: { 'sec-fetch-dest': 'document' } });
    expect(evilTab.statusCode).toBe(403);
    expect(evilTab.body).not.toContain('error-action');
  });

  it('shows a used transaction error inside the registered frame and notifies the parent (never for other parents)', async () => {
    const { txn, state } = await openLogin('rms-web-test', { origin: RMS });
    await app.get(TransactionService).complete(txn);
    const url = `/embed/login?client_id=rms-web-test&transaction_id=${txn}&state=${state}&origin=${encodeURIComponent(RMS)}`;

    const framed = await app.inject({ method: 'GET', url, headers: { 'sec-fetch-dest': 'iframe', referer: `${RMS}/` } });
    expect(framed.statusCode).toBe(409);
    expect(framed.headers['content-security-policy']).toContain(`frame-ancestors ${RMS};`);
    expect(framed.body).toContain('This sign-in request was already completed');
    const data = JSON.parse(/<script type="application\/json" id="miqaat-error">(.*?)<\/script>/s.exec(framed.body)![1]);
    expect(data).toEqual({ target_origin: RMS, transaction_id: txn, state, error: 'TRANSACTION_EXPIRED', code: 'TRANSACTION_ALREADY_USED' });
    expect(framed.body).toContain('<script src="/assets/embed-error.js" defer></script>');
    expect((await app.inject({ method: 'GET', url: '/assets/embed-error.js' })).statusCode).toBe(200);

    const otherParent = await app.inject({ method: 'GET', url, headers: { 'sec-fetch-dest': 'iframe', referer: 'https://evil.example.test/' } });
    expect(otherParent.statusCode).toBe(403);
    expect(otherParent.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(otherParent.body).not.toContain('miqaat-error');
  });
});

describe('authentication, assertion and SSO', () => {
  let rmsAssertion = '';
  let cookie = '';
  let sid = '';

  it('requires CSRF token and same-origin request', async () => {
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    const noCsrf = await postLogin({ ...boot!, csrf: 'wrong' }, 'rms-web-test', { its_id: MEMBER, password: PASSWORD });
    expect(noCsrf.json()).toMatchObject({ success: false, session: null, error: { code: 'CSRF_VALIDATION_FAILED', details: { reason: 'CSRF_TOKEN_MISMATCH' } } });
    const crossOrigin = await postLogin(boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD }, { origin: RMS });
    expect(crossOrigin.json()).toMatchObject({ success: false, error: { code: 'CSRF_VALIDATION_FAILED', details: { reason: 'ORIGIN_HEADER_MISMATCH' } } });
    const missing = await app.inject({
      method: 'POST',
      url: '/embed/login',
      headers: { origin: ISSUER, 'content-type': 'application/json' },
      payload: { transaction_id: boot!.transaction_id, client_id: 'rms-web-test', its_id: MEMBER, password: PASSWORD },
    });
    expect(missing.json()).toMatchObject({ success: false, error: { code: 'CSRF_VALIDATION_FAILED', details: { reason: 'CSRF_TOKEN_MISSING' } } });
  });

  it('returns the same error for wrong password and unknown user', async () => {
    const a = await openLogin('rms-web-test', { origin: RMS });
    const wrong = await postLogin(a.boot!, 'rms-web-test', { its_id: MEMBER, password: 'nope' });
    const b = await openLogin('rms-web-test', { origin: RMS });
    const unknown = await postLogin(b.boot!, 'rms-web-test', { its_id: '999999999', password: 'nope' });
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(wrong.json().error.code).toBe('INVALID_CREDENTIALS');
    expect(wrong.json().error).toEqual(unknown.json().error);
  });

  it('authenticates and returns a complete RS256 compact assertion with minimal claims', async () => {
    const { boot, txn, state } = await openLogin('rms-web-test', { origin: RMS });
    const res = await postLogin(boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({
      success: true,
      error: null,
      scope: null,
      request_id: expect.any(String),
      timestamp: expect.any(String),
      session: {
        token_type: 'CoreAssertion',
        audience: 'rms-web-test',
        expires_in: env.ASSERTION_TTL_SECONDS,
        user: { id: MEMBER, its_id: MEMBER, status: 'ACTIVE' },
        role_type: 'NONE',
        active_role: null,
        roles: [],
        modules: [],
        permissions: {},
        onboarding_required: false,
        delivery: { type: 'MIQAAT_AUTH_SUCCESS', transaction_id: txn, state, delivery: 'post_message', target_origin: RMS },
      },
    });
    expect(body.session.delivery).not.toHaveProperty('core_assertion');
    const assertion = body.session.token as string;
    expect(assertion.split('.')).toHaveLength(3);

    const header = decodeProtectedHeader(assertion);
    expect(header).toMatchObject({ alg: 'RS256', typ: 'JWT' });
    const claims = decodeJwt(assertion);
    expect(Object.keys(claims).sort()).toEqual(['aud', 'auth_time', 'exp', 'iat', 'iss', 'jti', 'sid', 'sub', 'txn']);
    expect(claims).toMatchObject({ iss: ISSUER, sub: MEMBER, aud: 'rms-web-test', txn });
    expect((claims.exp as number) - (claims.iat as number)).toBe(env.ASSERTION_TTL_SECONDS);

    const setCookie = res.cookies.find((c) => c.name === env.SESSION_COOKIE_NAME)!;
    expect(setCookie).toMatchObject({ httpOnly: true, secure: true, sameSite: 'None', path: '/' });
    expect(setCookie.value).not.toBe(claims.sid);
    expect(setCookie.value).toMatch(/^[A-Za-z0-9_-]{43}$/);

    rmsAssertion = assertion;
    cookie = sessionCookie(res);
    sid = claims.sid as string;

    const verified = await (await verifierFor('rms-web-test')).verifyLoginAssertion(rmsAssertion, { transactionId: txn });
    expect(verified.itsId).toBe(MEMBER);
  });

  it('cannot complete the same transaction twice', async () => {
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    expect((await postLogin(boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD })).statusCode).toBe(200);
    const again = await postLogin(boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ success: false, session: null, error: { code: 'TRANSACTION_ALREADY_USED' } });
  });

  it('BU verification rejects replay, other audiences and wrong transaction', async () => {
    const { boot, txn } = await openLogin('rms-web-test', { origin: RMS, cookie });
    // SSO continuation: fresh assertion for rms
    const res = await app.inject({ method: 'POST', url: '/embed/continue', headers: { origin: ISSUER, 'x-csrf-token': boot!.csrf, cookie }, payload: { transaction_id: txn, client_id: 'rms-web-test' } });
    const token = res.json().session.token as string;
    const store = new MemoryReplayStore();
    const rmsVerifier = await verifierFor('rms-web-test', store);
    await expect(rmsVerifier.verifyLoginAssertion(token, { transactionId: 'txn-other' })).rejects.toMatchObject({ code: 'TRANSACTION_MISMATCH' });
    await rmsVerifier.verifyLoginAssertion(token, { transactionId: txn });
    await expect(rmsVerifier.verifyLoginAssertion(token, { transactionId: txn })).rejects.toMatchObject({ code: 'REPLAYED' });
    await expect((await verifierFor('ams-web-test')).verifyLoginAssertion(token, { transactionId: txn })).rejects.toBeInstanceOf(AssertionVerificationError);
  });

  it('SSO: a second application gets its own assertion from the same federation session', async () => {
    const { boot, txn } = await openLogin('ams-web-test', { origin: AMS, cookie });
    expect(boot!.session).toMatchObject({ its_id: MEMBER });
    const res = await app.inject({ method: 'POST', url: '/embed/continue', headers: { origin: ISSUER, 'x-csrf-token': boot!.csrf, cookie }, payload: { transaction_id: txn, client_id: 'ams-web-test' } });
    expect(res.statusCode).toBe(200);
    const claims = decodeJwt(res.json().session.token);
    expect(claims).toMatchObject({ aud: 'ams-web-test', sid, sub: MEMBER });
    expect(res.json()).toMatchObject({ success: true, session: { token_type: 'CoreAssertion', audience: 'ams-web-test', delivery: { target_origin: AMS } } });

    const session = await app.inject({ method: 'GET', url: '/auth/session', headers: { cookie } });
    expect(session.json()).toMatchObject({ authenticated: true, its_id: MEMBER, clients: ['ams-web-test', 'rms-web-test'] });
  });

  it('browser federation logout requires a matching logout_hint from a registered origin', async () => {
    const evil = await app.inject({ method: 'POST', url: '/federation/logout', headers: { origin: 'https://evil.example.test', cookie }, payload: { client_id: 'rms-web-test', logout_hint: sid } });
    expect(evil.statusCode).toBe(403);
    const wrongHint = await app.inject({ method: 'POST', url: '/federation/logout', headers: { origin: RMS, cookie }, payload: { client_id: 'rms-web-test', logout_hint: 'sid_wrong_value_123' } });
    expect(wrongHint.json().error).toBe('LOGOUT_HINT_MISMATCH');
  });

  it('federation logout revokes the session and back-channel notifies every participating application', async () => {
    receivedLogoutTokens.length = 0;
    const res = await app.inject({
      method: 'POST',
      url: '/federation/logout',
      headers: { origin: RMS, cookie, 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ client_id: 'rms-web-test', logout_hint: sid, post_logout_redirect_uri: `${RMS}/logout/callback`, state: 'bye-state' }).toString(),
    });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${RMS}/logout/callback?state=bye-state`);

    await app.get(LogoutService).drain();
    expect(receivedLogoutTokens.map((t) => t.path).sort()).toEqual(['/ams-web-test', '/rms-web-test']);
    for (const { path, token } of receivedLogoutTokens) {
      const clientId = path.slice(1);
      await expect((await verifierFor(clientId)).verifyLogoutToken(token)).resolves.toMatchObject({ sid });
    }

    expect((await app.inject({ method: 'GET', url: '/auth/session', headers: { cookie } })).json()).toEqual({ authenticated: false });
    const { boot, txn } = await openLogin('rms-web-test', { origin: RMS, cookie });
    expect(boot!.session).toBeNull();
    const cont = await app.inject({ method: 'POST', url: '/embed/continue', headers: { origin: ISSUER, 'x-csrf-token': boot!.csrf, cookie }, payload: { transaction_id: txn, client_id: 'rms-web-test' } });
    expect(cont.json()).toMatchObject({ success: false, session: null, error: { code: 'SESSION_REQUIRED' } });
    expect(rmsAssertion).toBeTruthy();
  });
});

describe('account and brute-force protection', () => {
  itWith(NOT_ALLOWED)('reveals Allow_Login = false only after a correct password', async () => {
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    const res = await postLogin(boot!, 'rms-web-test', { its_id: NOT_ALLOWED!.itsId, password: NOT_ALLOWED!.password });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('ACCOUNT_UNAVAILABLE');
  });

  itWith(LOCK)('locks an identifier after repeated failures', async () => {
    const codes: number[] = [];
    for (let i = 0; i < env.LOGIN_MAX_FAILURES_PER_IDENTIFIER + 1; i++) {
      const { boot } = await openLogin('rms-web-test', { origin: RMS });
      codes.push((await postLogin(boot!, 'rms-web-test', { its_id: LOCK!.itsId, password: 'wrong' }, { 'x-forwarded-for': `10.0.0.${i}` })).statusCode);
    }
    expect(codes.slice(0, env.LOGIN_MAX_FAILURES_PER_IDENTIFIER)).toEqual(Array(env.LOGIN_MAX_FAILURES_PER_IDENTIFIER).fill(401));
    expect(codes.at(-1)).toBe(429);
    // even the correct password is refused while locked
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    const locked = await postLogin(boot!, 'rms-web-test', { its_id: LOCK!.itsId, password: LOCK!.password });
    expect(locked.statusCode).toBe(429);
    expect(locked.headers['retry-after']).toBeDefined();
  });

  itWith(INELIGIBLE)('shows the configured login restriction to a non-eligible user after a correct password only', async () => {
    const a = await openLogin('rms-web-test', { origin: RMS });
    const wrong = await postLogin(a.boot!, 'rms-web-test', { its_id: INELIGIBLE!.itsId, password: 'nope' });
    expect(wrong.json().error.code).toBe('INVALID_CREDENTIALS');
    const b = await openLogin('rms-web-test', { origin: RMS });
    const right = await postLogin(b.boot!, 'rms-web-test', { its_id: INELIGIBLE!.itsId, password: INELIGIBLE!.password });
    expect(right.statusCode).toBe(403);
    expect(right.json().error).toMatchObject({ code: 'LOGIN_RESTRICTED', message: env.LOGIN_RESTRICTION_MESSAGE });
  });

  itWith(INACTIVE)('rejects an account whose Status_ID is not active exactly like an unknown one', async () => {
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    const res = await postLogin(boot!, 'rms-web-test', { its_id: INACTIVE!.itsId, password: INACTIVE!.password });
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe('INVALID_CREDENTIALS');
  });

  it('rejects Non-ITS sign-in: identity_db holds ITS members only', async () => {
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    const res = await postLogin(boot!, 'rms-web-test', { identity_type: 'NON_ITS', identifier: 'Guest@Example.test', password: PASSWORD });
    expect(res.statusCode).toBe(401);
  });

  it('never writes to the synced identity tables', async () => {
    const snapshot = async () =>
      db.query(
        `SELECT (SELECT count(*) FROM users) AS users, (SELECT max(updated_at) FROM users) AS users_updated,
                (SELECT count(*) FROM user_eligible) AS eligible, (SELECT max(updated_at) FROM user_eligible) AS eligible_updated,
                (SELECT count(*) FROM mumin_master) AS mumin, (SELECT max(updated_at) FROM mumin_master) AS mumin_updated,
                (SELECT md5(string_agg(u::text, '|' ORDER BY u.id)) FROM users u WHERE u.mumin_id = $1::int) AS member_row`,
        [MEMBER],
      );
    const before = await snapshot();
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    expect((await postLogin(boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD })).statusCode).toBe(200);
    expect(await snapshot()).toEqual(before);
  });
});

describe('signing key rotation', () => {
  it('stages, promotes and keeps previously issued assertions verifiable', async () => {
    const keyStore = app.get(KeyStore);
    const { boot, txn } = await openLogin('rms-web-test', { origin: RMS });
    const before = (await postLogin(boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD })).json().session.token as string;
    const oldKid = decodeProtectedHeader(before).kid;

    await keyProvider.save(rotateKeyset(await keyProvider.load(), 'stage', { bits: 2048 }));
    await keyStore.reload();
    expect((await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json().keys).toHaveLength(2);

    await keyProvider.save(rotateKeyset(await keyProvider.load(), 'promote'));
    await keyStore.reload();

    const next = await openLogin('rms-web-test', { origin: RMS });
    const after = (await postLogin(next.boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD })).json().session.token as string;
    expect(decodeProtectedHeader(after).kid).not.toBe(oldKid);

    const verifier = await verifierFor('rms-web-test');
    await expect(verifier.verifyLoginAssertion(before, { transactionId: txn })).resolves.toMatchObject({ itsId: MEMBER });
    await expect(verifier.verifyLoginAssertion(after, { transactionId: next.txn })).resolves.toMatchObject({ itsId: MEMBER });
  });
});

describe('Core login with workspaces (POST /login, POST /select-scope) and JWKS tokens', () => {
  const ROLE_UTIL = '6b1f3c2e-8a3d-4a5b-9c1e-2d3f4a5b6c7d';
  const ROLE_BU = '7c2d4e3f-9b4e-4b6c-8d2f-3e4f5a6b7c8d';
  const ROLE_CORE = '8d3e5f40-ac5f-4c7d-9e30-4f5a6b7c8d9e';
  const UT_HELPDESK = '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d';
  const UT_ZONE = '1b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e';
  const BU_RMS = '2c3d4e5f-6071-4c8d-8e9f-1a2b3c4d5e6f';
  const WORKSPACES = [
    { role_id: ROLE_BU, role_name: 'Business Unit Admin', scope_type: 'BUSINESS_UNIT' as const, scope_id: BU_RMS, scope_name: 'RMS' },
    { role_id: ROLE_UTIL, role_name: 'Utility Admin', scope_type: 'UTILITY' as const, scope_id: UT_HELPDESK, scope_name: 'Helpdesk' },
    { role_id: ROLE_UTIL, role_name: 'Utility Admin', scope_type: 'UTILITY' as const, scope_id: UT_ZONE, scope_name: 'Zone Support' },
  ];
  const CORE_WS = { role_id: ROLE_CORE, role_name: 'Platform Administrator', scope_type: 'CORE' as const, scope_id: null, scope_name: 'Miqaat' };
  const UTIL_PERMS = { DASHBOARD: ['view'], ROLE_MGMT: ['view', 'create', 'edit'], USER_MGMT: ['view', 'create', 'edit'] };
  const CORE_PERMS = { DASHBOARD: ['view'], USER_MGMT: ['view', 'create', 'edit'], CONFIGURATION: ['view', 'edit'] };
  const jwksSet = async () => createLocalJWKSet((await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })).json());
  const claimsOf = async (token: string, audience = env.AUTHZ_AUDIENCE) =>
    (await jwtVerify(token, await jwksSet(), { issuer: ISSUER, audience, typ: 'at+jwt', algorithms: ['RS256'] })).payload;

  async function portalLogin(path = '/portal/login') {
    const page = await app.inject({ method: 'GET', url: '/portal' });
    const boot = bootOf(page.body);
    const login = await app.inject({
      method: 'POST',
      url: path,
      headers: { origin: ISSUER, 'x-csrf-token': boot.csrf, 'content-type': 'application/json' },
      payload: { transaction_id: boot.transaction_id, its_id: MEMBER, password: PASSWORD },
    });
    expect(login.statusCode).toBe(200);
    return { boot, cookie: sessionCookie(login), body: login.json() };
  }

  afterEach(() => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Test Member', requires_scope_selection: false, assignments: [] });
    jest.spyOn(authz, 'resolveAssignment').mockResolvedValue(null);
  });

  it('signs single-use service tokens for the Authorization service with the federation signing key', async () => {
    const token = await app.get(AssertionService).issueServiceToken();
    const { payload, protectedHeader } = await jwtVerify(token, await jwksSet(), {
      issuer: env.SERVICE_PRINCIPAL_ID,
      subject: env.SERVICE_PRINCIPAL_ID,
      audience: env.AUTHZ_AUDIENCE,
      typ: 'client-authentication+jwt',
      algorithms: ['RS256'],
    });
    expect(protectedHeader.kid).toEqual(expect.any(String));
    expect(Object.keys(payload).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'jti', 'sub']);
  });

  it('POST /login returns every assignment and an unscoped token when a workspace must be selected', async () => {
    jest.spyOn(app.get(AuthzClient), 'getAssignments').mockResolvedValueOnce({ its_id: MEMBER, name: 'Murtaza Saifuddin', requires_scope_selection: true, assignments: WORKSPACES });
    const { body } = await portalLogin('/login');
    expect(body).toMatchObject({
      success: true,
      error: null,
      scope: null,
      request_id: expect.any(String),
      session: {
        token_type: 'Bearer',
        user: { id: MEMBER, its_id: MEMBER, name: 'Murtaza Saifuddin', status: 'ACTIVE' },
        role_type: 'MULTI',
        active_role: null,
        modules: [],
        permissions: {},
        onboarding_required: false,
      },
    });
    expect(body.session.roles).toEqual([
      { role_id: ROLE_BU, role_name: 'Business Unit Admin', level: 'BUSINESS_UNIT_ADMIN', tenant_id: BU_RMS, tenant_name: 'RMS', scope_type: 'BUSINESS_UNIT', scope_id: BU_RMS },
      { role_id: ROLE_UTIL, role_name: 'Utility Admin', level: 'UTILITY_ADMIN', tenant_id: UT_HELPDESK, tenant_name: 'Helpdesk', scope_type: 'UTILITY', scope_id: UT_HELPDESK },
      { role_id: ROLE_UTIL, role_name: 'Utility Admin', level: 'UTILITY_ADMIN', tenant_id: UT_ZONE, tenant_name: 'Zone Support', scope_type: 'UTILITY', scope_id: UT_ZONE },
    ]);
    const claims = await claimsOf(body.session.token);
    expect(Object.keys(claims).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'jti', 'sid', 'sub', 'token_use']);
  });

  it('POST /login activates the only workspace automatically (token carries the scope, never permissions)', async () => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValueOnce({ its_id: MEMBER, name: 'Burhan', requires_scope_selection: false, assignments: [WORKSPACES[0]] });
    jest.spyOn(authz, 'resolveAssignment').mockResolvedValueOnce({ active_scope: WORKSPACES[0], permissions: UTIL_PERMS });
    const { body } = await portalLogin();
    expect(body).toMatchObject({
      success: true,
      scope: 'BUSINESS_UNIT',
      session: {
        role_type: 'SINGLE',
        active_role: { role_id: ROLE_BU, role_name: 'Business Unit Admin', level: 'BUSINESS_UNIT_ADMIN', tenant_id: BU_RMS, tenant_name: 'RMS' },
        roles: [expect.objectContaining({ role_id: ROLE_BU, scope_type: 'BUSINESS_UNIT' })],
        modules: ['dashboard', 'role-management', 'user-management'],
        permissions: {
          dashboard: { create: false, read: true, update: false, delete: false, approve: false, export: false },
          'role-management': { create: true, read: true, update: true, delete: false, approve: false, export: false },
          'user-management': { create: true, read: true, update: true, delete: false, approve: false, export: false },
        },
      },
    });
    const claims = await claimsOf(body.session.token);
    expect(claims).toMatchObject({ sub: MEMBER, role_id: ROLE_BU, scope_type: 'BUSINESS_UNIT', scope_id: BU_RMS });
    expect(Object.keys(claims)).not.toContain('permissions');
  });

  it('login errors use the envelope with the usual HTTP status', async () => {
    const page = await app.inject({ method: 'GET', url: '/portal' });
    const boot = bootOf(page.body);
    const res = await app.inject({
      method: 'POST',
      url: '/login',
      headers: { origin: ISSUER, 'x-csrf-token': boot.csrf, 'content-type': 'application/json' },
      payload: { transaction_id: boot.transaction_id, its_id: 'ITS77777', password: 'wrong-password' },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ success: false, session: null, scope: null, request_id: expect.any(String), timestamp: expect.any(String), error: { code: 'INVALID_CREDENTIALS', message: expect.any(String) } });
  });

  it('POST /select-scope issues a scoped token only for an assigned workspace, with session + CSRF', async () => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Murtaza Saifuddin', requires_scope_selection: true, assignments: WORKSPACES });
    const { boot, cookie } = await portalLogin();
    const choice = { transaction_id: boot.transaction_id, role_id: ROLE_UTIL, scope_type: 'UTILITY', scope_id: UT_HELPDESK };
    const select = (headers: Record<string, string>, payload: Record<string, unknown> = choice, url = '/select-scope') =>
      app.inject({ method: 'POST', url, headers: { origin: ISSUER, 'x-csrf-token': boot.csrf, cookie, ...headers }, payload });

    expect((await select({ cookie: '' })).json().error.code).toBe('SESSION_REQUIRED');
    expect((await select({ 'x-csrf-token': 'wrong' })).statusCode).toBe(403);
    expect((await select({ origin: RMS })).statusCode).toBe(403);
    expect((await select({}, { ...choice, scope_id: 'util-001' })).json().error.code).toBe('VALIDATION_ERROR');

    const resolve = jest.spyOn(authz, 'resolveAssignment').mockResolvedValueOnce(null);
    const rejected = await select({});
    expect(rejected.statusCode).toBe(403);
    expect(rejected.json()).toMatchObject({ success: false, session: null, error: { code: 'SCOPE_NOT_ASSIGNED' } });
    expect(resolve).toHaveBeenLastCalledWith(MEMBER, { role_id: ROLE_UTIL, scope_type: 'UTILITY', scope_id: UT_HELPDESK });

    resolve.mockResolvedValueOnce({ active_scope: WORKSPACES[1], permissions: UTIL_PERMS });
    const ok = await select({});
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toMatchObject({
      success: true,
      scope: 'UTILITY',
      session: {
        token_type: 'Bearer',
        audience: env.AUTHZ_AUDIENCE,
        role_type: 'MULTI',
        active_role: { role_id: ROLE_UTIL, level: 'UTILITY_ADMIN', tenant_id: UT_HELPDESK, tenant_name: 'Helpdesk', scope_type: 'UTILITY', scope_id: UT_HELPDESK },
        modules: ['dashboard', 'role-management', 'user-management'],
      },
    });
    expect(ok.json().session.roles).toHaveLength(3);
    expect(await claimsOf(ok.json().session.token)).toMatchObject({ role_id: ROLE_UTIL, scope_type: 'UTILITY', scope_id: UT_HELPDESK });

    // Switch Workspace without logging out, through the /portal alias
    resolve.mockResolvedValueOnce({ active_scope: WORKSPACES[2], permissions: UTIL_PERMS });
    const switched = await select({}, { ...choice, scope_id: UT_ZONE }, '/portal/select-scope');
    expect(await claimsOf(switched.json().session.token)).toMatchObject({ scope_id: UT_ZONE });
    expect(switched.json().session.active_role).toMatchObject({ tenant_id: UT_ZONE, tenant_name: 'Zone Support' });

    const listed = await app.inject({ method: 'GET', url: '/portal/assignments', headers: { cookie } });
    expect(listed.json()).toMatchObject({ its_id: MEMBER, requires_scope_selection: true, assignments: WORKSPACES });
  });

  it('portal CSRF token is bound to the signed-in session (outlives TRANSACTION_TTL_SECONDS, unusable by another session)', async () => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Murtaza Saifuddin', requires_scope_selection: true, assignments: WORKSPACES });
    const first = await portalLogin();
    const second = await portalLogin();
    const txn = await app.get(TransactionService).get(first.boot.transaction_id);
    expect(txn?.sid).toEqual(expect.any(String));

    const payload = { transaction_id: first.boot.transaction_id, role_id: ROLE_UTIL, scope_type: 'UTILITY', scope_id: UT_HELPDESK };
    const select = (cookie: string) =>
      app.inject({ method: 'POST', url: '/portal/select-scope', headers: { origin: ISSUER, 'x-csrf-token': first.boot.csrf, cookie }, payload });

    const foreign = await select(second.cookie);
    expect(foreign.json()).toMatchObject({ success: false, session: null, error: { code: 'CSRF_VALIDATION_FAILED', details: { reason: 'CSRF_TOKEN_MISMATCH' } } });
    jest.spyOn(authz, 'resolveAssignment').mockResolvedValueOnce({ active_scope: WORKSPACES[1], permissions: UTIL_PERMS });
    expect((await select(first.cookie)).statusCode).toBe(200);
  });

  it('administrator force-logout needs a CORE workspace with USER_MGMT edit, verified live', async () => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Platform Admin', requires_scope_selection: true, assignments: [CORE_WS, WORKSPACES[0]] });
    const { boot, cookie, body } = await portalLogin();
    const resolve = jest.spyOn(authz, 'resolveAssignment');
    const tokenFor = async (ws: typeof CORE_WS | (typeof WORKSPACES)[number], audience: string) => {
      resolve.mockResolvedValueOnce({ active_scope: ws, permissions: CORE_PERMS });
      const res = await app.inject({
        method: 'POST',
        url: '/portal/select-scope',
        headers: { origin: ISSUER, 'x-csrf-token': boot.csrf, cookie },
        payload: { transaction_id: boot.transaction_id, role_id: ws.role_id, scope_type: ws.scope_type, scope_id: ws.scope_id, audience },
      });
      return res.json().session.token as string;
    };
    const coreIdentityToken = await tokenFor(CORE_WS, 'identity');
    const coreAuthzToken = await tokenFor(CORE_WS, 'authorization');
    const buIdentityToken = await tokenFor(WORKSPACES[0], 'identity');
    const forceLogout = (token: string) => app.inject({ method: 'POST', url: '/federation/logout', headers: { authorization: `Bearer ${token}` }, payload: { its_id: MEMBER } });

    expect((await forceLogout('not-a-token')).statusCode).toBe(401);
    expect((await forceLogout(coreAuthzToken)).statusCode).toBe(401); // wrong audience
    expect((await forceLogout(body.session.token)).statusCode).toBe(401); // unscoped token has the authorization audience
    resolve.mockResolvedValueOnce({ active_scope: WORKSPACES[0], permissions: CORE_PERMS });
    expect((await forceLogout(buIdentityToken)).json().error).toBe('ADMIN_PERMISSION_DENIED');
    resolve.mockResolvedValueOnce(null);
    expect((await forceLogout(coreIdentityToken)).json().error).toBe('ADMIN_PERMISSION_DENIED'); // assignment revoked meanwhile
    resolve.mockResolvedValueOnce({ active_scope: CORE_WS, permissions: CORE_PERMS });
    const ok = await forceLogout(coreIdentityToken);
    expect(ok.statusCode).toBe(200);
    expect(ok.json().revoked_sessions).toBeGreaterThanOrEqual(1);
    await app.get(LogoutService).drain();
  });

  it('applies an added or removed embed origin at once (fresh read) and via POST /federation/clients/:id/refresh (CORE + CONFIGURATION edit)', async () => {
    const authz = app.get(AuthzClient);
    const NEW_ORIGIN = 'https://rms-admin.example.test';
    const createTxn = (origin: string) =>
      app.inject({ method: 'POST', url: '/auth/transaction', payload: { client_id: 'rms-web-test', state: 'refresh-state-abcdefghij12345', origin, display: 'embed' } });
    expect((await createTxn(NEW_ORIGIN)).json().error).toBe('ORIGIN_NOT_ALLOWED');

    // origin added in the registry
    const getClient = jest.spyOn(app.get(ClientsStoreService), 'findByClientId').mockImplementation(async (id: string) => {
      const all = registry();
      if (id === 'rms-web-test') all[id] = { ...all[id], allowed_embed_origins: [RMS, NEW_ORIGIN] };
      return all[id] ?? null;
    });
    // transaction creation reads the client configuration fresh: no refresh call needed
    expect((await createTxn(NEW_ORIGIN)).statusCode).toBe(201);

    jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Platform Admin', requires_scope_selection: true, assignments: [CORE_WS, WORKSPACES[0]] });
    const { boot, cookie } = await portalLogin();
    const resolve = jest.spyOn(authz, 'resolveAssignment');
    const identityToken = async (ws: typeof CORE_WS | (typeof WORKSPACES)[number]) => {
      resolve.mockResolvedValueOnce({ active_scope: ws, permissions: CORE_PERMS });
      const res = await app.inject({
        method: 'POST',
        url: '/portal/select-scope',
        headers: { origin: ISSUER, 'x-csrf-token': boot.csrf, cookie },
        payload: { transaction_id: boot.transaction_id, role_id: ws.role_id, scope_type: ws.scope_type, scope_id: ws.scope_id, audience: 'identity' },
      });
      return res.json().session.token as string;
    };
    const coreToken = await identityToken(CORE_WS);
    const buToken = await identityToken(WORKSPACES[0]);
    const refresh = (token?: string, clientId = 'rms-web-test') =>
      app.inject({ method: 'POST', url: `/federation/clients/${clientId}/refresh`, headers: token ? { authorization: `Bearer ${token}` } : {} });

    expect((await refresh()).statusCode).toBe(401);
    resolve.mockResolvedValueOnce({ active_scope: WORKSPACES[0], permissions: CORE_PERMS });
    expect((await refresh(buToken)).json().error).toBe('ADMIN_PERMISSION_DENIED');
    resolve.mockResolvedValueOnce({ active_scope: CORE_WS, permissions: { DASHBOARD: ['view'], CONFIGURATION: ['view'] } });
    expect((await refresh(coreToken)).json().error).toBe('ADMIN_PERMISSION_DENIED');

    resolve.mockResolvedValueOnce({ active_scope: CORE_WS, permissions: CORE_PERMS });
    const refreshed = await refresh(coreToken);
    expect(refreshed.statusCode).toBe(200);
    expect(refreshed.json()).toMatchObject({ client_id: 'rms-web-test', status: 'ACTIVE', allowed_embed_origins: [RMS, NEW_ORIGIN] });
    const created = await createTxn(NEW_ORIGIN);
    expect(created.statusCode).toBe(201);
    expect(created.json().login_url).toContain(`origin=${encodeURIComponent(NEW_ORIGIN)}`);

    // origin removed again: refused for the next transaction even before the refresh call
    getClient.mockImplementation(async (id: string) => registry()[id] ?? null);
    expect((await createTxn(NEW_ORIGIN)).json().error).toBe('ORIGIN_NOT_ALLOWED');
    resolve.mockResolvedValueOnce({ active_scope: CORE_WS, permissions: CORE_PERMS });
    expect((await refresh(coreToken)).json().allowed_embed_origins).toEqual([RMS]);
    expect((await createTxn(NEW_ORIGIN)).json().error).toBe('ORIGIN_NOT_ALLOWED');
    resolve.mockResolvedValueOnce({ active_scope: CORE_WS, permissions: CORE_PERMS });
    expect((await refresh(coreToken, 'unknown-client')).json().error).toBe('CLIENT_NOT_FOUND');
  });
});

describe('transaction API (POST /auth/transaction, GET /auth/transaction/:id)', () => {
  const create = (payload: Record<string, unknown>) => app.inject({ method: 'POST', url: '/auth/transaction', payload });

  it('returns login_url, bound origin and the CSRF token, which signs in without parsing the login page', async () => {
    const res = await create({ client_id: 'rms-web-test', state: 'api-state-abcdefghij12345', origin: RMS, display: 'embed' });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body).toMatchObject({ client_id: 'rms-web-test', display: 'embed', state: 'api-state-abcdefghij12345', status: 'PENDING', target_origin: RMS, csrf: expect.any(String), csrf_header: 'x-csrf-token', required_origin: ISSUER });

    // the login page resumes the same transaction and embeds the same token
    const page = await app.inject({ method: 'GET', url: body.login_url.slice(ISSUER.length) });
    expect(bootOf(page.body).csrf).toBe(body.csrf);

    const login = await postLogin({ transaction_id: body.transaction_id, csrf: body.csrf }, 'rms-web-test', { its_id: MEMBER, password: PASSWORD });
    expect(login.statusCode).toBe(200);
    expect(login.json()).toMatchObject({ success: true, session: { token_type: 'CoreAssertion', delivery: { type: 'MIQAAT_AUTH_SUCCESS', transaction_id: body.transaction_id, target_origin: RMS } } });

    const status = await app.inject({ method: 'GET', url: `/auth/transaction/${body.transaction_id}?client_id=rms-web-test` });
    expect(status.json()).toMatchObject({ transaction_id: body.transaction_id, status: 'COMPLETED', target_origin: RMS });
    expect(status.json()).not.toHaveProperty('csrf');
    expect((await app.inject({ method: 'GET', url: `/auth/transaction/${body.transaction_id}?client_id=ams-web-test` })).json().error).toBe('TRANSACTION_INVALID');
  });

  it('binds one of several registered origins and requires origin when there is more than one', async () => {
    const TWO = 'https://rms-admin.example.test';
    const getClient = jest.spyOn(app.get(ClientsStoreService), 'findByClientId').mockImplementation(async (id: string) => {
      const all = registry();
      all['rms-web-test'] = { ...all['rms-web-test'], allowed_embed_origins: [RMS, TWO] };
      return all[id] ?? null;
    });
    const chosen = await create({ client_id: 'rms-web-test', state: 'multi-state-abcdefghij-1', origin: TWO });
    expect(chosen.json().target_origin).toBe(TWO);
    expect(new URL(chosen.json().login_url).searchParams.get('origin')).toBe(TWO);
    expect((await create({ client_id: 'rms-web-test', state: 'multi-state-abcdefghij-2' })).json().error).toBe('ORIGIN_NOT_ALLOWED');
    expect((await create({ client_id: 'rms-web-test', state: 'multi-state-abcdefghij-3', origin: 'https://evil.example.test' })).json().error).toBe('ORIGIN_NOT_ALLOWED');
    getClient.mockImplementation(async (id: string) => registry()[id] ?? null);
  });
});

describe('embedded login envelope (same pattern as the Core Portal login)', () => {
  const BU_ID = '2c3d4e5f-6071-4c8d-8e9f-1a2b3c4d5e6f';
  const UT_ID = '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d';
  const BU_ROLE = { role_id: '7c2d4e3f-9b4e-4b6c-8d2f-3e4f5a6b7c8d', role_name: 'Business Unit Admin', scope_type: 'BUSINESS_UNIT' as const, scope_id: BU_ID, scope_name: 'RMS' };
  const UT_ROLE = { role_id: '6b1f3c2e-8a3d-4a5b-9c1e-2d3f4a5b6c7d', role_name: 'Utility Admin', scope_type: 'UTILITY' as const, scope_id: UT_ID, scope_name: 'Helpdesk' };

  afterEach(() => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Test Member', requires_scope_selection: false, assignments: [] });
    jest.spyOn(authz, 'resolveAssignment').mockResolvedValue(null);
  });

  it('single role: SINGLE with active_role, modules and permissions; the assertion stays identity-only', async () => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValueOnce({ its_id: MEMBER, name: 'Test Member', requires_scope_selection: false, assignments: [BU_ROLE] });
    jest.spyOn(authz, 'resolveAssignment').mockResolvedValueOnce({ active_scope: BU_ROLE, permissions: { DASHBOARD: ['view'], RMS_REGISTRATION: ['view', 'create'] } });
    const { boot } = await openLogin('rms-web-test', { origin: RMS });
    const res = await postLogin(boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      success: true,
      scope: 'BUSINESS_UNIT',
      session: {
        token_type: 'CoreAssertion',
        user: { its_id: MEMBER, name: 'Test Member', status: 'ACTIVE' },
        role_type: 'SINGLE',
        active_role: { role_id: BU_ROLE.role_id, role_name: 'Business Unit Admin', level: 'BUSINESS_UNIT_ADMIN', tenant_id: BU_ID, tenant_name: 'RMS', scope_type: 'BUSINESS_UNIT', scope_id: BU_ID },
        roles: [expect.objectContaining({ role_id: BU_ROLE.role_id, level: 'BUSINESS_UNIT_ADMIN' })],
        modules: ['dashboard', 'rms-registration'],
        permissions: { dashboard: { read: true, create: false }, 'rms-registration': { read: true, create: true, update: false } },
      },
    });
    const claims = decodeJwt(res.json().session.token);
    expect(Object.keys(claims).sort()).toEqual(['aud', 'auth_time', 'exp', 'iat', 'iss', 'jti', 'sid', 'sub', 'txn']);
  });

  it('several roles: MULTI with every role and no active role, for password sign-in and SSO continue', async () => {
    const authz = app.get(AuthzClient);
    jest.spyOn(authz, 'getAssignments').mockResolvedValue({ its_id: MEMBER, name: 'Test Member', requires_scope_selection: true, assignments: [BU_ROLE, UT_ROLE] });
    const first = await openLogin('rms-web-test', { origin: RMS });
    const login = await postLogin(first.boot!, 'rms-web-test', { its_id: MEMBER, password: PASSWORD });
    expect(login.json()).toMatchObject({ success: true, scope: null, session: { role_type: 'MULTI', active_role: null, modules: [], permissions: {} } });
    expect(login.json().session.roles.map((r: { level: string; tenant_name: string }) => `${r.level}:${r.tenant_name}`)).toEqual(['BUSINESS_UNIT_ADMIN:RMS', 'UTILITY_ADMIN:Helpdesk']);

    const cookie = sessionCookie(login);
    const second = await openLogin('ams-web-test', { origin: AMS, cookie });
    const cont = await app.inject({ method: 'POST', url: '/embed/continue', headers: { origin: ISSUER, 'x-csrf-token': second.boot!.csrf, cookie }, payload: { transaction_id: second.txn, client_id: 'ams-web-test' } });
    expect(cont.statusCode).toBe(200);
    expect(cont.json()).toMatchObject({ success: true, session: { token_type: 'CoreAssertion', audience: 'ams-web-test', role_type: 'MULTI', roles: expect.any(Array), delivery: { type: 'MIQAAT_AUTH_SUCCESS', transaction_id: second.txn, target_origin: AMS } } });
    expect(decodeJwt(cont.json().session.token)).toMatchObject({ aud: 'ams-web-test', sub: MEMBER });
  });
});
