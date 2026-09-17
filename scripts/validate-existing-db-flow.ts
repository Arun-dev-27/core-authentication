/**
 * End-to-end validation of Embedded Login -> Authentication (identity_db) -> Authorization (admin_db),
 * driven over HTTP against RUNNING core-authentication and core-authorization services, exactly as a browser
 * iframe and a Business Unit backend would call them.
 *
 * Uses only EXISTING users, databases, schemas and tables. It creates, alters and deletes nothing: it only
 * READS the two databases (fingerprints before/after prove no user or RBAC row was created or changed). The
 * services themselves write only their normal rows into the 8 auth tables and admin_db user_sessions.
 *
 *   npm run validate:existing-db     (env from .env, or ENV_FILE=<file>)
 *
 * Required:
 *   VALIDATE_ITS_ID / VALIDATE_PASSWORD   an existing, active, eligible user who is also in admin_db with a role
 *   VALIDATE_ADMIN_DB_URL                 postgres://user:password@host:5432/admin_db (read-only use)
 * Optional (defaults): VALIDATE_AUTHZ_BASE_URL (http://localhost:3002), VALIDATE_ADMIN_DB_SCHEMA (public),
 *   VALIDATE_CLIENT_ID (rms-web-dev), VALIDATE_ORIGIN (http://localhost:5175)
 * Optional scenario users, each VALIDATE_<NAME>_ITS_ID + VALIDATE_<NAME>_PASSWORD (skipped when unset):
 *   INELIGIBLE (not in user_eligible), INACTIVE (status_id <> 3), NOT_ALLOWED (allow_login = false),
 *   NOT_ONBOARDED (not in admin_db users), ADMIN_DISABLED (admin users.status DISABLED),
 *   NO_ROLE (in admin_db, no role), MULTI_ROLE (several roles)
 * Forged-token checks (expired / wrong issuer / logout token) need SIGNING_KEY_PROVIDER=file; skipped otherwise.
 */
import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { SignJWT, createRemoteJWKSet, decodeJwt, decodeProtectedHeader, importPKCS8, jwtVerify } from 'jose';
import { DataSource } from 'typeorm';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { buildDataSourceOptions } from '@core/database/data-source-options';
import { CoreAssertionVerifier, MemoryReplayStore } from '../examples/bu-reference-app/src/core-assertion-verifier';

/* eslint-disable @typescript-eslint/no-explicit-any */
loadEnvFiles();
const env = loadEnv();
const required = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required (see the header of this script)`);
  return value;
};
const AUTHN = env.ISSUER.replace(/\/+$/, '');
const AUTHZ = (process.env.VALIDATE_AUTHZ_BASE_URL ?? 'http://localhost:3002').replace(/\/+$/, '');
const ADMIN_DB_URL = required('VALIDATE_ADMIN_DB_URL');
const ADMIN_SCHEMA = process.env.VALIDATE_ADMIN_DB_SCHEMA ?? 'public';
const CLIENT_ID = process.env.VALIDATE_CLIENT_ID ?? 'rms-web-dev';
const ORIGIN = process.env.VALIDATE_ORIGIN ?? 'http://localhost:5175';
const UA = 'Mozilla/5.0 (validate-existing-db-flow)';

type TestUser = { itsId: string; password: string };
const MEMBER: TestUser = { itsId: required('VALIDATE_ITS_ID'), password: required('VALIDATE_PASSWORD') };
/** mumin_id is an integer; the assertion subject and admin its_id carry it without leading zeros. */
const SUBJECT = String(Number(MEMBER.itsId));
const optionalUser = (name: string): TestUser | null => {
  const itsId = process.env[`VALIDATE_${name}_ITS_ID`];
  const password = process.env[`VALIDATE_${name}_PASSWORD`];
  return itsId && password ? { itsId, password } : null;
};
const USERS = {
  ineligible: optionalUser('INELIGIBLE'),
  inactive: optionalUser('INACTIVE'),
  notAllowed: optionalUser('NOT_ALLOWED'),
  notOnboarded: optionalUser('NOT_ONBOARDED'),
  adminDisabled: optionalUser('ADMIN_DISABLED'),
  noRole: optionalUser('NO_ROLE'),
  multiRole: optionalUser('MULTI_ROLE'),
};

// ------------------------------------------------------------------------------------------------ reporting
type Result = { section: string; name: string; ok: boolean | 'skip'; detail?: string };
const results: Result[] = [];
let section = '';
async function check(name: string, fn: () => Promise<unknown> | unknown) {
  try {
    const detail = await fn();
    results.push({ section, name, ok: true, detail: typeof detail === 'string' ? detail : undefined });
  } catch (error) {
    results.push({ section, name, ok: false, detail: error instanceof Error ? error.message : String(error) });
  }
}
async function checkUser(name: string, user: TestUser | null, fn: (user: TestUser) => Promise<unknown>) {
  if (!user) return void results.push({ section, name, ok: 'skip', detail: 'scenario user not configured' });
  await check(`${name} (${user.itsId})`, () => fn(user));
}
async function checkForged(name: string, fn: () => Promise<unknown>) {
  if (env.SIGNING_KEY_PROVIDER !== 'file') return void results.push({ section, name, ok: 'skip', detail: 'needs SIGNING_KEY_PROVIDER=file' });
  await check(name, fn);
}
function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}
function eq<T>(actual: T, expected: T, what: string) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

// ------------------------------------------------------------------------------------------------ http + cookies
class Browser {
  private jar = new Map<string, string>();
  cookie(name: string) {
    return this.jar.get(name);
  }
  async fetch(url: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}) {
    const headers: Record<string, string> = { 'user-agent': UA, ...(init.headers ?? {}) };
    if (this.jar.size) headers.cookie = [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ');
    if (init.body !== undefined) headers['content-type'] = 'application/json';
    const res = await fetch(url, { method: init.method ?? 'GET', headers, body: init.body === undefined ? undefined : JSON.stringify(init.body), redirect: 'manual' });
    for (const raw of res.headers.getSetCookie()) {
      const [pair] = raw.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      const value = pair.slice(i + 1).trim();
      if (!value || /max-age=0/i.test(raw)) this.jar.delete(name);
      else this.jar.set(name, value);
    }
    const text = await res.text();
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* html */
    }
    return { status: res.status, headers: res.headers, text, json, setCookies: res.headers.getSetCookie() };
  }
}

// The login page is loaded by the BU page inside an iframe.
const IFRAME_HEADERS = { 'sec-fetch-dest': 'iframe', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'cross-site', referer: `${ORIGIN}/` };
// login.js inside that iframe posts to its own origin.
const PAGE_HEADERS = (csrf: string) => ({ origin: AUTHN, 'x-csrf-token': csrf, 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors' });

async function openLogin(browser: Browser, opts: { clientId?: string; origin?: string; query?: Record<string, string> } = {}) {
  const txn = `txn-validate-${randomUUID()}`;
  const q = new URLSearchParams({ client_id: opts.clientId ?? CLIENT_ID, transaction_id: txn, state: `state-${randomUUID()}`, origin: opts.origin ?? ORIGIN, ...(opts.query ?? {}) });
  const res = await browser.fetch(`${AUTHN}/embed/login?${q}`, { headers: { ...IFRAME_HEADERS, referer: `${opts.origin ?? ORIGIN}/` } });
  const boot = /<script type="application\/json" id="miqaat-boot">(.*?)<\/script>/s.exec(res.text);
  return { res, txn, boot: boot ? (JSON.parse(boot[1]) as { transaction_id: string; csrf: string; session: unknown }) : null };
}

async function login(browser: Browser, { itsId, password }: TestUser) {
  const page = await openLogin(browser);
  expect(page.boot, `login page did not render (HTTP ${page.res.status})`);
  const res = await browser.fetch(`${AUTHN}/embed/login`, {
    method: 'POST',
    headers: PAGE_HEADERS(page.boot.csrf),
    body: { transaction_id: page.boot.transaction_id, client_id: CLIENT_ID, identity_type: 'ITS', its_id: itsId, password },
  });
  return { ...res, txn: page.boot.transaction_id, csrf: page.boot.csrf };
}

const errorCode = (r: { json: any }) => r.json?.error?.code ?? r.json?.code ?? r.json?.error;
const reasonOf = (r: { json: any; text: string }) => r.json?.error?.details?.reason ?? r.json?.details?.reason ?? r.text.match(/"reason":"([A-Z_]+)"/)?.[1];

// ------------------------------------------------------------------------------------------------ forged tokens (negative tests)
async function signingKey() {
  const set = JSON.parse(readFileSync(env.SIGNING_KEYS_FILE, 'utf8')) as { keys: { kid: string; status: string; privateKeyPem: string }[] };
  const active = set.keys.find((k) => k.status === 'ACTIVE')!;
  return { kid: active.kid, key: await importPKCS8(active.privateKeyPem, 'RS256') };
}
async function forge(claims: Record<string, unknown>, opts: { typ?: string; iss?: string; iat?: number; exp?: number } = {}) {
  const { kid, key } = await signingKey();
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sid: `sid_${randomUUID()}`, txn: `txn-${randomUUID()}`, auth_time: now, ...claims })
    .setProtectedHeader({ alg: 'RS256', typ: opts.typ ?? 'JWT', kid })
    .setIssuer(opts.iss ?? AUTHN)
    .setSubject(SUBJECT)
    .setAudience(CLIENT_ID)
    .setJti(randomUUID())
    .setIssuedAt(opts.iat ?? now)
    .setExpirationTime(opts.exp ?? now + 60)
    .sign(key);
}

// ------------------------------------------------------------------------------------------------ database access (read-only)
class Client {
  constructor(private readonly source: DataSource) {}
  connect() {
    return this.source.initialize();
  }
  end() {
    return this.source.destroy();
  }
  async query(sql: string, params: unknown[] = []): Promise<{ rows: any[]; rowCount: number }> {
    const rows = (await this.source.query(sql, params)) as any[];
    return { rows, rowCount: rows.length };
  }
}

// ------------------------------------------------------------------------------------------------ database fingerprints
const q = (s: string) => `"${ADMIN_SCHEMA}"."${s}"`;
async function identityFingerprint(db: Client) {
  const s = env.IDENTITY_DB_SCHEMA;
  const rows = await db.query(
    `SELECT (SELECT count(*) FROM "${s}".users)::int AS users,
            (SELECT count(*) FROM "${s}".user_eligible)::int AS user_eligible,
            (SELECT count(*) FROM "${s}".mumin_master)::int AS mumin_master,
            (SELECT max(updated_at) FROM "${s}".users) AS users_updated,
            (SELECT max(updated_at) FROM "${s}".user_eligible) AS eligible_updated,
            (SELECT max(updated_at) FROM "${s}".mumin_master) AS mumin_updated,
            (SELECT md5(string_agg(u::text, '|' ORDER BY u.id)) FROM "${s}".users u WHERE u.mumin_id = $1::int) AS member_md5`,
    [MEMBER.itsId],
  );
  return rows.rows[0];
}
async function adminFingerprint(db: Client) {
  const out: Record<string, unknown> = {};
  for (const t of ['users', 'tenants', 'roles', 'modules', 'permission_actions', 'module_actions', 'role_permissions', 'user_roles']) {
    out[t] = (await db.query(`SELECT count(*)::int AS n FROM ${q(t)}`)).rows[0].n;
  }
  // Identity of every RBAC row. users.status / last_login_at / has_been_active are login bookkeeping and excluded.
  out.users_md5 = (await db.query(`SELECT md5(string_agg(id || coalesce(its_id, '') || name || email, '|' ORDER BY id)) AS h FROM ${q('users')}`)).rows[0].h;
  for (const t of ['tenants', 'roles', 'modules', 'permission_actions', 'module_actions', 'role_permissions', 'user_roles']) {
    out[`${t}_md5`] = (await db.query(`SELECT md5(string_agg(x::text, '|' ORDER BY x.id)) AS h FROM ${q(t)} x`)).rows[0].h;
  }
  return out;
}

// ------------------------------------------------------------------------------------------------ main
async function main() {
  const identityDb = new Client(new DataSource(buildDataSourceOptions(env)));
  const adminDb = new Client(new DataSource({ type: 'postgres', url: ADMIN_DB_URL, entities: [], synchronize: false, migrationsRun: false }));
  await identityDb.connect();
  await adminDb.connect();
  const S = env.IDENTITY_DB_SCHEMA;
  const identityBefore = await identityFingerprint(identityDb);
  const adminBefore = await adminFingerprint(adminDb);
  const attemptsBefore = Number((await identityDb.query(`SELECT count(*)::int AS n FROM "${S}".auth_login_attempts`)).rows[0].n);

  // ---------------------------------------------------------------------------------- database
  section = 'Database';
  await check(`identity_db connection works and ${S} schema is accessible`, async () => {
    const r = await identityDb.query(`SELECT current_database() AS db, (SELECT count(*) FROM information_schema.schemata WHERE schema_name = $1)::int AS n`, [S]);
    eq(r.rows[0].n, 1, 'schema present');
    return `${r.rows[0].db}.${S}`;
  });
  await check('existing identity user is found by users.mumin_id', async () => {
    const r = await identityDb.query(`SELECT mumin_id FROM "${S}".users WHERE mumin_id = $1::int`, [MEMBER.itsId]);
    eq(r.rowCount > 0, true, `users row for mumin_id ${MEMBER.itsId}`);
  });
  await check(`admin_db connection works and ${ADMIN_SCHEMA} schema is accessible`, async () => {
    const r = await adminDb.query(`SELECT current_database() AS db, count(*)::int AS n FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'user_roles'`, [ADMIN_SCHEMA]);
    eq(r.rows[0].n, 1, 'user_roles present');
    return `${r.rows[0].db}.${ADMIN_SCHEMA}`;
  });
  await check('Mumin_id -> admin users.its_id mapping exists', async () => {
    const r = await adminDb.query(`SELECT status FROM ${q('users')} WHERE its_id = $1`, [SUBJECT]);
    eq(r.rowCount, 1, `admin users row for its_id ${SUBJECT}`);
    return `status ${r.rows[0].status}`;
  });

  // ---------------------------------------------------------------------------------- embedded login
  section = 'Embedded login';
  await check('JWKS endpoint publishes RS256 public keys only', async () => {
    const jwks = await (await fetch(`${AUTHN}/.well-known/jwks.json`)).json();
    expect(jwks.keys.length > 0, 'no keys');
    for (const k of jwks.keys) {
      eq(k.alg, 'RS256', 'alg');
      expect(!('d' in k) && !('p' in k) && !('q' in k), 'private parameters exposed');
    }
    return `${jwks.keys.length} key(s)`;
  });
  await check('registered client_id + registered origin renders the login page, framable only by that origin', async () => {
    const { res, boot } = await openLogin(new Browser());
    eq(res.status, 200, 'status');
    expect(boot?.csrf, 'no CSRF token in boot block');
    const csp = res.headers.get('content-security-policy') ?? '';
    expect(new RegExp(`frame-ancestors ${ORIGIN.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(;|$)`).test(csp), `frame-ancestors not exactly the origin: ${csp}`);
  });
  await check('unknown client_id is rejected', async () => {
    const { res, boot } = await openLogin(new Browser(), { clientId: 'unknown-client-xyz' });
    expect(res.status >= 400 && !boot, `status ${res.status}`);
    return `HTTP ${res.status}`;
  });
  await check('unregistered origin is rejected', async () => {
    const { res, boot } = await openLogin(new Browser(), { origin: 'https://evil.example.com' });
    expect(res.status === 403 && !boot, `status ${res.status}`);
  });
  await check('unregistered callback URL is rejected', async () => {
    const { res, boot } = await openLogin(new Browser(), { query: { redirect_uri: 'https://evil.example.com/cb' } });
    expect(res.status >= 400 && !boot, `status ${res.status}`);
    return `HTTP ${res.status}`;
  });

  // ---------------------------------------------------------------------------------- authentication
  section = 'Authentication';
  let first: Awaited<ReturnType<typeof login>> | null = null;
  await check(`existing valid user (${MEMBER.itsId}) logs in and gets a core assertion`, async () => {
    first = await login(new Browser(), MEMBER);
    eq(first.status, 200, `status (${first.text.slice(0, 200)})`);
    expect(first.json.session.token, 'no assertion');
  });
  await check('assertion is delivered by postMessage to the exact registered origin only', async () => {
    const d = first!.json.session.delivery;
    eq({ type: d.type, delivery: d.delivery, target_origin: d.target_origin }, { type: 'MIQAAT_AUTH_SUCCESS', delivery: 'post_message', target_origin: ORIGIN }, 'delivery');
  });
  await check('response exposes no Core access or refresh token; session cookie is HttpOnly', async () => {
    expect(!/access_token|refresh_token/i.test(first!.text), 'token field present in response');
    const cookie = first!.setCookies.find((c) => c.startsWith(`${env.SESSION_COOKIE_NAME}=`));
    expect(cookie && /HttpOnly/i.test(cookie), 'federation session cookie missing or not HttpOnly');
  });
  await check('assertion: RS256, verified via JWKS, iss = Core, aud = client_id, sub = Mumin_id, required claims, no roles', async () => {
    const token = first!.json.session.token as string;
    eq(decodeProtectedHeader(token).alg, 'RS256', 'alg');
    const { payload } = await jwtVerify(token, createRemoteJWKSet(new URL(`${AUTHN}/.well-known/jwks.json`)), { issuer: AUTHN, audience: CLIENT_ID, algorithms: ['RS256'] });
    eq(payload.sub, SUBJECT, 'sub');
    for (const c of ['iss', 'sub', 'aud', 'sid', 'jti', 'txn', 'auth_time', 'iat', 'exp']) expect(c in payload, `missing claim ${c}`);
    eq(payload.txn, first!.txn, 'txn');
    eq(Object.keys(payload).filter((k) => /role|permission|module|tenant|scope/i.test(k)), [], 'authorization claims in assertion');
    return Object.keys(payload).sort().join(',');
  });
  await check('existing user with an invalid password is rejected (401 INVALID_CREDENTIALS)', async () => {
    const r = await login(new Browser(), { itsId: MEMBER.itsId, password: `${MEMBER.password}-wrong` });
    eq([r.status, errorCode(r)], [401, 'INVALID_CREDENTIALS'], 'response');
  });
  await check('unknown user is rejected with the same response as a wrong password', async () => {
    const r = await login(new Browser(), { itsId: '999999999', password: 'WrongPass@1' });
    eq([r.status, errorCode(r)], [401, 'INVALID_CREDENTIALS'], 'response');
  });
  await checkUser('ineligible user (not in user_eligible) gets the login restriction message', USERS.ineligible, async (u) => {
    const r = await login(new Browser(), u);
    eq([r.status, errorCode(r)], [403, 'LOGIN_RESTRICTED'], 'response');
    eq(r.json.error.message, env.LOGIN_RESTRICTION_MESSAGE, 'message');
    const wrong = await login(new Browser(), { itsId: u.itsId, password: `${u.password}-wrong` });
    eq(errorCode(wrong), 'INVALID_CREDENTIALS', 'wrong password does not reveal eligibility');
  });
  await checkUser('user with status_id <> active is rejected', USERS.inactive, async (u) => {
    const r = await login(new Browser(), u);
    eq([r.status, errorCode(r)], [401, 'INVALID_CREDENTIALS'], 'response');
  });
  await checkUser('user with allow_login = false is rejected', USERS.notAllowed, async (u) => {
    const r = await login(new Browser(), u);
    eq([r.status, errorCode(r)], [403, 'ACCOUNT_UNAVAILABLE'], 'response');
  });
  await check('login attempts are recorded in auth_login_attempts', async () => {
    const r = await identityDb.query(`SELECT count(*)::int AS n FROM "${S}".auth_login_attempts`);
    expect(r.rows[0].n > attemptsBefore, 'no new rows');
  });
  await check('audit events are recorded in auth_audit_events', async () => {
    const r = await identityDb.query(`SELECT DISTINCT event_type FROM "${S}".auth_audit_events ORDER BY 1`);
    const types = r.rows.map((x: any) => x.event_type as string);
    for (const t of ['LOGIN_SUCCEEDED', 'LOGIN_FAILED', 'ASSERTION_ISSUED']) expect(types.includes(t), `missing ${t}`);
    return types.join(', ');
  });

  // ---------------------------------------------------------------------------------- BU backend verification (reference verifier)
  section = 'BU assertion verification';
  const jwks = createRemoteJWKSet(new URL(`${AUTHN}/.well-known/jwks.json`));
  const bu = (over: Partial<{ issuer: string; clientId: string }> = {}) =>
    new CoreAssertionVerifier({ issuer: over.issuer ?? AUTHN, clientId: over.clientId ?? CLIENT_ID, jwksUri: `${AUTHN}/.well-known/jwks.json`, replayStore: new MemoryReplayStore(), keyResolver: jwks });
  const rejectsWith = async (p: Promise<unknown>, code: RegExp) => {
    try {
      await p;
    } catch (e) {
      const c = (e as { code?: string }).code ?? String(e);
      expect(code.test(c), `rejected with ${c}`);
      return c;
    }
    throw new Error('was accepted');
  };
  {
    const fresh = await login(new Browser(), MEMBER);
    const token = fresh.json?.session?.token as string;
    const verifier = bu();
    await check('valid assertion verifies (signature, iss, aud, txn, jti)', async () => {
      const v = await verifier.verifyLoginAssertion(token, { transactionId: fresh.txn });
      eq(v.itsId, SUBJECT, 'itsId');
    });
    await check('replayed assertion is rejected', () => rejectsWith(verifier.verifyLoginAssertion(token, { transactionId: fresh.txn }), /REPLAY/));
    await check('wrong audience is rejected', () => rejectsWith(bu({ clientId: `${CLIENT_ID}-other` }).verifyLoginAssertion(token, { transactionId: fresh.txn }), /AUD|CLAIM/));
    await check('wrong issuer is rejected', () => rejectsWith(bu({ issuer: 'https://not-core.example.com' }).verifyLoginAssertion(token, { transactionId: fresh.txn }), /ISS|CLAIM/));
    await check('assertion for another transaction is rejected', () => rejectsWith(bu().verifyLoginAssertion(token, { transactionId: 'txn-other' }), /TRANSACTION/));
    await checkForged('expired assertion is rejected', async () => {
      const now = Math.floor(Date.now() / 1000);
      const expired = await forge({}, { iat: now - 600, exp: now - 540 });
      return rejectsWith(bu().verifyLoginAssertion(expired, { transactionId: decodeJwt(expired).txn as string }), /EXPIRED|CLAIM|LIFETIME/);
    });
    await checkForged('logout token is not accepted as a login assertion', async () => {
      const logoutToken = await forge({ events: { 'http://schemas.openid.net/event/backchannel-logout': {} } }, { typ: 'logout+jwt' });
      return rejectsWith(bu().verifyLoginAssertion(logoutToken, { transactionId: decodeJwt(logoutToken).txn as string }), /TYP/);
    });
  }

  // ---------------------------------------------------------------------------------- authorization (admin_db)
  section = 'Authorization';
  const buLogin = async (browser: Browser, assertion: string) => browser.fetch(`${AUTHZ}/authorization/session`, { method: 'POST', body: { core_assertion: assertion } });
  const assertionFor = async (u: TestUser) => {
    const r = await login(new Browser(), u);
    expect(r.status === 200, `authentication failed for ${u.itsId}: ${r.status} ${errorCode(r)}`);
    return r.json.session.token as string;
  };
  const checkPerm = (browser: Browser, body: Record<string, string>) => browser.fetch(`${AUTHZ}/authorization/session/check`, { method: 'POST', body });

  // The member's own session: its single role, or the first role when it holds several.
  const member = new Browser();
  let session: any = null;
  await check(`${SUBJECT} (Mumin_id -> its_id) gets its existing role, tenant and module permissions`, async () => {
    let r = await buLogin(member, await assertionFor(MEMBER));
    eq(r.status, 200, `status ${r.text.slice(0, 200)}`);
    if (r.json.selection_required) {
      r = await member.fetch(`${AUTHZ}/authorization/session/select`, { method: 'POST', body: { pending_token: r.json.pending_token, role_id: r.json.roles[0].role_id } });
      eq(r.status, 200, 'select first role');
    }
    session = r.json;
    eq(session.its_id, SUBJECT, 'its_id');
    expect(member.cookie('miqaat_session'), 'no local session cookie');
    return `role ${session.role.code} (${session.role.level}${session.role.tenant_name ? `, ${session.role.tenant_name}` : ''}); modules ${session.modules.join(',')}`;
  });
  const permissions = () => (session?.permissions ?? {}) as Record<string, Record<string, boolean>>;
  const granted = () =>
    Object.entries(permissions())
      .filter(([m]) => m !== 'dashboard')
      .flatMap(([m, actions]) => Object.entries(actions).filter(([, v]) => v).map(([a]) => ({ module: m.toUpperCase(), action: a.toUpperCase() })));
  await check('authorized operation (a granted module action) -> 200', async () => {
    const g = granted()[0];
    expect(g, 'the role holds no module permission to test with');
    const r = await checkPerm(member, { ...g, ...(session.role.tenant_id ? { tenant_id: session.role.tenant_id } : {}) });
    eq(r.status, 200, `${g.module} ${g.action}`);
    return `${g.module} ${g.action}`;
  });
  await check('module-level permission: a module the role has no grant on -> 403', async () => {
    const codes = (await adminDb.query(`SELECT code FROM ${q('modules')} ORDER BY display_order`)).rows.map((x: any) => x.code as string);
    const missing = codes.find((c) => !permissions()[c.toLowerCase()]);
    if (!missing) return 'role is granted every module - nothing to deny';
    const r = await checkPerm(member, { module: missing, action: 'READ' });
    eq([r.status, reasonOf(r)], [403, 'MODULE_NOT_GRANTED'], missing);
    return missing;
  });
  await check('action-level permission: an action the role lacks on a granted module -> 403', async () => {
    const rows = (
      await adminDb.query(
        `SELECT m.code AS module, a.code AS action FROM ${q('module_actions')} ma JOIN ${q('modules')} m ON m.id = ma.module_id JOIN ${q('permission_actions')} a ON a.id = ma.action_id`,
      )
    ).rows as { module: string; action: string }[];
    const target = rows.find((x) => permissions()[x.module.toLowerCase()] && !permissions()[x.module.toLowerCase()][x.action.toLowerCase()]);
    if (!target) return 'role holds every action of its modules - nothing to deny';
    const r = await checkPerm(member, { module: target.module, action: target.action });
    eq([r.status, reasonOf(r)], [403, 'ACTION_NOT_GRANTED'], `${target.module} ${target.action}`);
    return `${target.module} ${target.action}`;
  });
  await check('tenant isolation: operation on another tenant -> 403 TENANT_MISMATCH', async () => {
    if (!session.role.tenant_id) return 'CORE_ADMIN role is platform-wide - not applicable';
    const other = (await adminDb.query(`SELECT id FROM ${q('tenants')} WHERE id <> $1 LIMIT 1`, [session.role.tenant_id])).rows[0]?.id;
    if (!other) return 'no other tenant exists';
    const r = await checkPerm(member, { ...granted()[0], tenant_id: other });
    eq([r.status, reasonOf(r)], [403, 'TENANT_MISMATCH'], 'response');
  });
  await check('assertion replayed at the authorization edge is rejected (401)', async () => {
    const token = await assertionFor(MEMBER);
    eq((await buLogin(new Browser(), token)).status, 200, 'first use');
    eq((await buLogin(new Browser(), token)).status, 401, 'replay status');
  });
  await checkForged('expired / wrong-issuer / logout-typ / tampered assertions are rejected by authorization (401)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const bad = {
      expired: await forge({}, { iat: now - 600, exp: now - 540 }),
      wrongIssuer: await forge({}, { iss: 'https://not-core.example.com' }),
      logoutToken: await forge({ events: {} }, { typ: 'logout+jwt' }),
      tampered: (await forge({})).replace(/\.[^.]+$/, '.AAAA'),
    };
    const statuses: Record<string, number> = {};
    for (const [name, token] of Object.entries(bad)) statuses[name] = (await buLogin(new Browser(), token)).status;
    eq(statuses, { expired: 401, wrongIssuer: 401, logoutToken: 401, tampered: 401 }, 'statuses');
  });
  await checkUser('user with several roles -> role selection; each chosen role is the only one applied', USERS.multiRole, async (u) => {
    const probe = await buLogin(new Browser(), await assertionFor(u));
    eq([probe.status, probe.json.selection_required], [200, true], 'selection');
    const chosen: string[] = [];
    for (const role of probe.json.roles as { role_id: string; role_code: string }[]) {
      const b = new Browser();
      const r = await buLogin(b, await assertionFor(u));
      const s = await b.fetch(`${AUTHZ}/authorization/session/select`, { method: 'POST', body: { pending_token: r.json.pending_token, role_id: role.role_id } });
      eq([s.status, s.json.role?.code], [200, role.role_code], 'selected role');
      eq((await b.fetch(`${AUTHZ}/authorization/session/me`)).json.role.code, role.role_code, '/me role');
      chosen.push(role.role_code);
    }
    return chosen.join(', ');
  });
  await checkUser('authenticated user missing from admin_db -> 403 USER_NOT_ONBOARDED', USERS.notOnboarded, async (u) => {
    const r = await buLogin(new Browser(), await assertionFor(u));
    eq([r.status, errorCode(r)], [403, 'USER_NOT_ONBOARDED'], 'response');
  });
  await checkUser('DISABLED admin user -> 403 USER_DISABLED', USERS.adminDisabled, async (u) => {
    const r = await buLogin(new Browser(), await assertionFor(u));
    eq([r.status, errorCode(r)], [403, 'USER_DISABLED'], 'response');
  });
  await checkUser('admin user with no role -> 403 NO_ROLE_ASSIGNED', USERS.noRole, async (u) => {
    const r = await buLogin(new Browser(), await assertionFor(u));
    eq([r.status, errorCode(r)], [403, 'NO_ROLE_ASSIGNED'], 'response');
  });
  await check('local session: /me works, logout revokes it, /me then 401', async () => {
    eq((await member.fetch(`${AUTHZ}/authorization/session/me`)).status, 200, 'me before');
    const cookie = member.cookie('miqaat_session')!;
    eq((await member.fetch(`${AUTHZ}/authorization/session/logout`, { method: 'POST', body: {} })).status, 200, 'logout');
    const replayed = await fetch(`${AUTHZ}/authorization/session/me`, { headers: { cookie: `miqaat_session=${cookie}`, 'user-agent': UA } });
    eq(replayed.status, 401, 'me with revoked cookie');
  });

  // ---------------------------------------------------------------------------------- SSO + core logout
  section = 'Core session & logout';
  const bob = new Browser();
  const bobLogin = await login(bob, MEMBER);
  const sid = bobLogin.status === 200 ? (decodeJwt(bobLogin.json.session.token).sid as string) : '';
  await check('core session is recorded in auth_sessions', async () => {
    const r = await identityDb.query(`SELECT its_id, revoked_at FROM "${S}".auth_sessions WHERE sid = $1`, [sid]);
    eq([r.rows[0]?.its_id, r.rows[0]?.revoked_at], [SUBJECT, null], 'auth_sessions row');
  });
  await check('SSO: an existing core session issues a new assertion without a password', async () => {
    const page = await openLogin(bob);
    const r = await bob.fetch(`${AUTHN}/embed/continue`, { method: 'POST', headers: PAGE_HEADERS(page.boot!.csrf), body: { transaction_id: page.boot!.transaction_id, client_id: CLIENT_ID } });
    eq([r.status, decodeJwt(r.json.session.token).sid], [200, sid], 'continue');
  });
  await check('logout invalidates exactly that core session', async () => {
    const other = await login(new Browser(), MEMBER);
    const otherSid = decodeJwt(other.json.session.token).sid as string;
    const r = await bob.fetch(`${AUTHN}/federation/logout`, { method: 'POST', headers: { origin: AUTHN }, body: {} });
    eq([r.status, r.json.logged_out], [200, true], 'logout');
    const rows = await identityDb.query(`SELECT sid, revoked_at IS NOT NULL AS revoked FROM "${S}".auth_sessions WHERE sid = ANY($1)`, [[sid, otherSid]]);
    const revoked = Object.fromEntries(rows.rows.map((x: any) => [x.sid, x.revoked]));
    eq([revoked[sid], revoked[otherSid]], [true, false], 'revoked flags (this, other)');
    const page = await openLogin(bob);
    const cont = await bob.fetch(`${AUTHN}/embed/continue`, { method: 'POST', headers: PAGE_HEADERS(page.boot!.csrf), body: { transaction_id: page.boot!.transaction_id, client_id: CLIENT_ID } });
    eq([cont.status, errorCode(cont)], [401, 'SESSION_REQUIRED'], 'continue after logout');
  });

  // ---------------------------------------------------------------------------------- no changes to existing data
  section = 'Existing data untouched';
  await check('identity_db users / user_eligible / mumin_master: no rows created or changed', async () => {
    eq(await identityFingerprint(identityDb), identityBefore, 'identity fingerprint');
    return `${identityBefore.users} users, ${identityBefore.user_eligible} eligible, ${identityBefore.mumin_master} mumin_master`;
  });
  await check('admin_db users / tenants / roles / modules / actions / permissions / user_roles: no rows created or changed', async () => {
    eq(await adminFingerprint(adminDb), adminBefore, 'admin fingerprint');
    return `${adminBefore.users} users, ${adminBefore.roles} roles, ${adminBefore.role_permissions} role_permissions, ${adminBefore.user_roles} user_roles`;
  });

  await identityDb.end();
  await adminDb.end();

  // ---------------------------------------------------------------------------------- report
  let current = '';
  for (const r of results) {
    if (r.section !== current) {
      current = r.section;
      console.log(`\n${current}`);
    }
    console.log(`  ${r.ok === 'skip' ? 'SKIP' : r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `  [${r.detail}]` : ''}`);
  }
  const failed = results.filter((r) => r.ok === false).length;
  const skipped = results.filter((r) => r.ok === 'skip').length;
  console.log(`\n${results.length - failed - skipped} passed, ${failed} failed, ${skipped} skipped`);
  process.exitCode = failed ? 1 : 0;
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
