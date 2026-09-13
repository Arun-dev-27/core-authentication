/**
 * Live end-to-end smoke test across the running stack:
 *   Identity Federation (3001) + Authorization (3002) + RMS (4001) / AMS (4002) / VMS (4003) reference apps.
 *
 * It behaves like a browser at the HTTP level (Origin, Referer, Sec-Fetch-Dest, cookie jar) and exercises:
 * POST /login -> workspaces -> POST /select-scope -> GET /me/permissions (active scope) -> Switch Workspace,
 * JWKS -> embedded login -> assertion -> BU callback verification -> local session -> server-side authorization
 * -> SSO into AMS and VMS -> replay rejection -> federation logout -> back-channel logout in every app.
 *
 *   SMOKE_ITS_ID=30337752 SMOKE_PASSWORD=... [SMOKE_DEMO_PASSWORD=<DEV_DEMO_PASSWORD>] npm run smoke:federation
 * Credentials come only from the environment.
 */
const IDENTITY = process.env.SMOKE_IDENTITY_URL ?? 'http://localhost:3001';
const AUTHZ = process.env.SMOKE_AUTHZ_URL ?? 'http://localhost:3002';
const ITS_ID = process.env.SMOKE_ITS_ID ?? '30337752';
const PASSWORD = process.env.SMOKE_PASSWORD;
const DEMO_PASSWORD = process.env.SMOKE_DEMO_PASSWORD;
/** GET /me/permissions example of the Role & Permission Module doc (section 6): Business Unit Admin. */
const BU_ADMIN_PERMISSIONS = {
  DASHBOARD: ['view'],
  ROLE_MGMT: ['view', 'create', 'edit'],
  USER_MGMT: ['view', 'create', 'edit'],
  EVENT_CONTRACT: ['view', 'create', 'approve'],
  API_CONTRACT: ['view', 'create', 'approve'],
  CONTRACT_LIBRARY: ['view'],
  ACCESS_REQUEST: ['view', 'create', 'approve'],
  TICKET_MGMT: ['view', 'create', 'edit'],
  MONITORING: ['view'],
  AUDIT_LOG: ['view'],
  CONFIGURATION: ['view', 'edit'],
};
type Workspace = { role_id: string; role_name: string; scope_type: string; scope_id: string | null; scope_name: string | null };
const claimsOf = (token: string | undefined) => (token ? JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) : {});
const bearer = (token: string | undefined) => ({ headers: { authorization: `Bearer ${token}` } });
const APPS = [
  { name: 'RMS', url: 'http://localhost:4001', allowed: 'delete', denied: null as string | null },
  { name: 'AMS', url: 'http://localhost:4002', allowed: 'edit', denied: null as string | null },
  { name: 'VMS', url: 'http://localhost:4003', allowed: 'view', denied: 'create' },
];

const jar = new Map<string, string>(); // browsers scope localhost cookies by host, not port
const results: { check: string; ok: boolean; detail: string }[] = [];

function record(check: string, ok: boolean, detail = '') {
  results.push({ check, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${check}${detail ? `  (${detail})` : ''}`);
}

async function http(url: string, init: RequestInit & { headers?: Record<string, string> } = {}) {
  const cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  const res = await fetch(url, { ...init, redirect: 'manual', headers: { ...(cookie ? { cookie } : {}), ...(init.headers ?? {}) } });
  for (const line of res.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(';');
    const idx = pair.indexOf('=');
    const name = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    const expired = attrs.some((a) => /max-age=0/i.test(a) || /expires=Thu, 01 Jan 1970/i.test(a));
    if (expired || value === '') jar.delete(name);
    else jar.set(name, value);
  }
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* html */
  }
  return { res, text, json };
}

function boot(html: string) {
  const m = /<script type="application\/json" id="miqaat-boot">(.*?)<\/script>/s.exec(html);
  return m ? JSON.parse(m[1]) : null;
}

async function signIn(app: (typeof APPS)[number], mode: 'password' | 'sso') {
  const start = await http(`${app.url}/auth/core/start`, { method: 'POST', headers: { 'content-type': 'application/json', origin: app.url }, body: JSON.stringify({ display: 'embed' }) });
  const loginUrl = start.json?.login_url as string;

  const page = await http(loginUrl, { headers: { referer: `${app.url}/`, 'sec-fetch-dest': 'iframe' } });
  const csp = page.res.headers.get('content-security-policy') ?? '';
  record(`${app.name}: embedded login page served for registered origin`, page.res.status === 200 && csp.includes(`frame-ancestors ${app.url};`), `status ${page.res.status}`);
  const b = boot(page.text);

  let delivery;
  if (mode === 'password') {
    delivery = await http(`${IDENTITY}/embed/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: IDENTITY, 'x-csrf-token': b.csrf },
      body: JSON.stringify({ transaction_id: b.transaction_id, client_id: b.client_id, its_id: ITS_ID, password: PASSWORD }),
    });
  } else {
    record(`${app.name}: SSO session detected in login page`, b?.session?.its_id === ITS_ID);
    delivery = await http(`${IDENTITY}/embed/continue`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: IDENTITY, 'x-csrf-token': b.csrf },
      body: JSON.stringify({ transaction_id: b.transaction_id, client_id: b.client_id }),
    });
  }
  const d = delivery.json;
  const parts = typeof d?.core_assertion === 'string' ? d.core_assertion.split('.') : [];
  record(`${app.name}: ${mode === 'password' ? 'password login' : 'SSO continue'} returned compact RS256 assertion for exact origin`, delivery.res.status === 200 && parts.length === 3 && d.target_origin === app.url, `status ${delivery.res.status}${d?.error ? ` ${d.error}` : ''}`);

  const payload = { transaction_id: d.transaction_id, state: d.state, core_assertion: d.core_assertion };
  const callback = await http(`${app.url}/auth/core/callback`, { method: 'POST', headers: { 'content-type': 'application/json', origin: app.url }, body: JSON.stringify(payload) });
  record(`${app.name}: backend verified assertion via JWKS and created local session`, callback.res.status === 200, `status ${callback.res.status}${callback.json?.error ? ` ${callback.json.error}` : ''}`);

  const replay = await http(`${app.url}/auth/core/callback`, { method: 'POST', headers: { 'content-type': 'application/json', origin: app.url }, body: JSON.stringify(payload) });
  record(`${app.name}: replayed callback rejected`, replay.res.status >= 400, `status ${replay.res.status} ${replay.json?.error ?? ''}`);

  const header = JSON.parse(Buffer.from(parts[0] ?? 'e30', 'base64url').toString());
  return { sid: JSON.parse(Buffer.from(parts[1] ?? 'e30', 'base64url').toString()).sid as string, kid: header.kid as string };
}

/** Core Portal login at the Role & Permission Module paths (POST /login, POST /select-scope). */
async function coreLogin(itsId: string, password: string) {
  const page = await http(`${IDENTITY}/portal`);
  const b = boot(page.text);
  const login = await http(`${IDENTITY}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: IDENTITY, 'x-csrf-token': b.csrf },
    body: JSON.stringify({ transaction_id: b.transaction_id, its_id: itsId, password }),
  });
  const select = (ws: Pick<Workspace, 'role_id' | 'scope_type' | 'scope_id'>) =>
    http(`${IDENTITY}/select-scope`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: IDENTITY, 'x-csrf-token': b.csrf },
      body: JSON.stringify({ transaction_id: b.transaction_id, role_id: ws.role_id, scope_type: ws.scope_type, scope_id: ws.scope_id }),
    });
  return { login, body: login.json ?? {}, assignments: (login.json?.assignments ?? []) as Workspace[], select };
}

async function main() {
  if (!PASSWORD) throw new Error('SMOKE_PASSWORD is required');

  const jwks = await http(`${IDENTITY}/.well-known/jwks.json`);
  const keys = (jwks.json?.keys ?? []) as Record<string, unknown>[];
  record('JWKS publishes public RSA keys only', keys.length > 0 && keys.every((k) => k.kty === 'RSA' && !('d' in k) && typeof k.kid === 'string'), `${keys.length} key(s)`);

  const evil = await http(`${IDENTITY}/embed/login?client_id=rms-web-dev&transaction_id=txn-smoke-evil-${Date.now()}&state=smoke-state-evil&origin=http://evil.localhost:9999`);
  record('Unregistered embedding origin rejected', evil.res.status === 403 && (evil.res.headers.get('content-security-policy') ?? '').includes("frame-ancestors 'none'"), `status ${evil.res.status}`);

  // ---- Core login with workspaces; admin APIs accept only JWKS-verified, scope-carrying bearer tokens ----
  const core = await coreLogin(ITS_ID, PASSWORD);
  record(
    `POST /login returns ${ITS_ID}'s workspaces (role x scope) and requires_scope_selection`,
    core.login.res.status === 200 && core.assignments.length > 0 && core.body.requires_scope_selection === core.assignments.length > 1,
    core.assignments.map((a) => `${a.role_name}@${a.scope_name}`).join(', '),
  );
  const unscoped = await http(`${AUTHZ}/me/permissions`, bearer(core.body.token));
  record('Unscoped login token cannot read permissions before POST /select-scope', unscoped.res.status === 403 && unscoped.json?.error === 'SCOPE_SELECTION_REQUIRED', unscoped.json?.error);

  const coreWs = core.assignments.find((a) => a.scope_type === 'CORE');
  const coreSel = coreWs ? await core.select(coreWs) : null;
  const adminToken = coreSel?.json?.token as string | undefined;
  const header = adminToken ? JSON.parse(Buffer.from(adminToken.split('.')[0], 'base64url').toString()) : {};
  const adminClaims = claimsOf(adminToken);
  record(
    'POST /select-scope issues an RS256 at+jwt carrying only the active scope (kid in JWKS)',
    coreSel?.res.status === 200 && header.typ === 'at+jwt' && keys.some((k) => k.kid === header.kid) && adminClaims.scope_type === 'CORE' && adminClaims.scope_id === null && !('permissions' in adminClaims),
    coreSel?.json?.active_scope?.role_name,
  );
  const corePerms = await http(`${AUTHZ}/me/permissions`, bearer(adminToken));
  record('GET /me/permissions resolves the CORE workspace from the Authorization DB', corePerms.res.status === 200 && corePerms.json?.CONFIGURATION?.includes('edit') === true, Object.keys(corePerms.json ?? {}).join(','));

  const noToken = await http(`${AUTHZ}/clients`, { headers: { cookie: '' } });
  const apiKey = await http(`${AUTHZ}/clients`, { headers: { 'x-api-key': 'adm_1234abcd.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } });
  record('Authorization admin API rejects missing credentials and API keys', noToken.res.status === 401 && apiKey.res.status === 401, `${noToken.res.status}/${apiKey.res.status}`);
  const adminList = await http(`${AUTHZ}/clients`, bearer(adminToken));
  record(`CORE workspace token for ${ITS_ID} accepted (CONFIGURATION view)`, adminList.res.status === 200 && Array.isArray(adminList.json), `${Array.isArray(adminList.json) ? adminList.json.length : 0} clients`);

  const buWs = core.assignments.find((a) => a.role_name === 'RMS Registration Admin');
  if (buWs) {
    const buSel = await core.select(buWs);
    const buToken = buSel.json?.token as string | undefined;
    const buList = await http(`${AUTHZ}/clients`, bearer(buToken));
    record('Switch Workspace: RMS Registration Admin @RMS token is denied Core CONFIGURATION', buSel.res.status === 200 && claimsOf(buToken).scope_id === buWs.scope_id && buList.res.status === 403, buList.json?.error);
  }
  const foreign = await core.select({ role_id: (coreWs ?? core.assignments[0]).role_id, scope_type: 'UTILITY', scope_id: '00000000-0000-4000-8000-000000000000' });
  record('POST /select-scope rejects a workspace the user does not hold', foreign.res.status === 403 && foreign.json?.error === 'SCOPE_NOT_ASSIGNED', foreign.json?.error);

  const userOnCheck = await http(`${AUTHZ}/authorization/check`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ its_id: ITS_ID, client_id: 'rms-web-dev', permission: 'RMS_REGISTRATION_VIEW' }),
  });
  record('User tokens cannot call service-only authorization checks', userOnCheck.res.status === 403, userOnCheck.json?.error);
  for (const app of APPS) {
    const buJwks = await http(`${app.url}/.well-known/jwks.json`);
    const buKeys = (buJwks.json?.keys ?? []) as Record<string, unknown>[];
    record(`${app.name}: backend publishes its service-principal JWKS (public key only)`, buKeys.length === 1 && !('d' in buKeys[0]) && buKeys[0].kty === 'RSA', String(buKeys[0]?.kid ?? ''));
  }

  const sids = new Set<string>();
  for (const [i, app] of APPS.entries()) {
    const { sid, kid } = await signIn(app, i === 0 ? 'password' : 'sso');
    sids.add(sid);
    record(`${app.name}: assertion kid is published in JWKS`, keys.some((k) => k.kid === kid), kid);

    const me = await http(`${app.url}/api/me`);
    const roles = (me.json?.effective?.roles ?? []).map((r: { role_name: string; scope_type: string }) => `${r.role_name}(${r.scope_type})`).join(',');
    record(`${app.name}: local session + Core roles for ${ITS_ID}`, me.res.status === 200 && me.json.its_id === ITS_ID, roles || 'no roles');

    const allowed = await http(`${app.url}/api/demo/${app.allowed}`);
    record(`${app.name}: server-side permission '${app.allowed}' allowed`, allowed.res.status === 200, allowed.json?.permission);
    if (app.denied) {
      const denied = await http(`${app.url}/api/demo/${app.denied}`);
      record(`${app.name}: server-side permission '${app.denied}' denied`, denied.res.status === 403, `${denied.json?.permission} ${denied.json?.reason ?? ''}`);
    }
  }
  record('One central federation session (same sid) across all apps', sids.size === 1, [...sids].join(','));

  const session = await http(`${IDENTITY}/auth/session`);
  record('Identity knows all participating clients', (session.json?.clients ?? []).length === 3, (session.json?.clients ?? []).join(','));

  const prepared = await http(`${APPS[0].url}/auth/logout/federated`, { method: 'POST', headers: { origin: APPS[0].url } });
  const logout = await http(prepared.json.action, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: APPS[0].url },
    body: new URLSearchParams(prepared.json.fields).toString(),
  });
  record('Federation logout redirects to registered post-logout URI', logout.res.status === 303 && (logout.res.headers.get('location') ?? '').startsWith(`${APPS[0].url}/logout/callback`), `status ${logout.res.status}`);

  await new Promise((r) => setTimeout(r, 2500));
  for (const app of APPS) {
    const me = await http(`${app.url}/api/me`);
    record(`${app.name}: local session ended (${app === APPS[0] ? 'local logout' : 'back-channel logout'})`, me.res.status === 401, `status ${me.res.status}`);
  }
  const after = await http(`${IDENTITY}/auth/session`);
  record('Central federation session revoked', after.json?.authenticated === false);

  // ---- Role & Permission Module demo: one person, several workspaces (31267890) ----
  if (DEMO_PASSWORD) {
    jar.clear();
    const demo = await coreLogin('31267890', DEMO_PASSWORD);
    const names = demo.assignments.map((a) => `${a.role_name}@${a.scope_name}`);
    record('31267890 POST /login lists 3 workspaces and requires_scope_selection', demo.body.requires_scope_selection === true && demo.assignments.length === 3, names.join(', '));
    const bu = demo.assignments.find((a) => a.scope_type === 'BUSINESS_UNIT');
    const buSel = bu ? await demo.select(bu) : null;
    const buPerms = await http(`${AUTHZ}/me/permissions`, bearer(buSel?.json?.token));
    record('31267890 Business Unit Admin @RMS: GET /me/permissions equals the doc example', JSON.stringify(buPerms.json) === JSON.stringify(BU_ADMIN_PERMISSIONS), Object.keys(buPerms.json ?? {}).join(','));
    const util = demo.assignments.find((a) => a.scope_type === 'UTILITY');
    const utilSel = util ? await demo.select(util) : null;
    const utilPerms = await http(`${AUTHZ}/me/permissions`, bearer(utilSel?.json?.token));
    // Doc matrix: Utility Admin has the same module/action columns as Business Unit Admin; the difference is the scope (one utility).
    record('31267890 Switch Workspace -> Utility Admin @Helpdesk: doc permission map, token scoped to the utility', JSON.stringify(utilPerms.json) === JSON.stringify(BU_ADMIN_PERMISSIONS) && utilSel?.json?.active_scope?.scope_type === 'UTILITY' && claimsOf(utilSel?.json?.token).scope_id === util?.scope_id, `${util?.scope_name}: ${Object.keys(utilPerms.json ?? {}).length} modules`);
    const buCreate = await http(`${AUTHZ}/business-units`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${utilSel?.json?.token}` }, body: JSON.stringify({ bu_name: 'Smoke BU' }) });
    record('Utility workspace cannot create business units', buCreate.res.status === 403, buCreate.json?.error);
  } else {
    console.log('SKIP  demo multi-workspace checks (set SMOKE_DEMO_PASSWORD)');
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((error: unknown) => {
  console.error('smoke test error:', error instanceof Error ? error.message : error);
  process.exit(1);
});
