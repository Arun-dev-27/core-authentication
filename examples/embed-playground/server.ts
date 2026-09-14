/**
 * Embedded login playground: a minimal "your own app" on http://localhost:3000 for testing Miqaat Identity
 * Federation locally, end to end, in a real browser.
 *
 *   1. register the origin once:   (core-authorization) npm run client -- origins add rms-web-dev http://localhost:3000
 *   2. start:                      (core-authentication) npm run example:playground
 *   3. open http://localhost:3000, click "Start embedded login", sign in inside the iframe
 *
 * The page shows every step: transaction, postMessage, JWKS verification (all checks), and the
 * Authorization decision. Dev tool only - it keeps state in memory and runs on http.
 */
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import Fastify from 'fastify';
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose';
import { ServiceCredentials } from '../bu-reference-app/src/service-credentials';

const PORT = Number(process.env.PLAYGROUND_PORT ?? 3000);
const ORIGIN = `http://localhost:${PORT}`;
const IDENTITY = process.env.IDENTITY_BASE_URL ?? 'http://localhost:3001';
const AUTHZ = process.env.AUTHZ_BASE_URL ?? 'http://localhost:3002';
const CLIENT_ID = process.env.PLAYGROUND_CLIENT_ID ?? 'rms-web-dev';
const PRINCIPAL = process.env.PLAYGROUND_SERVICE_PRINCIPAL ?? 'rms-backend'; // service principal allowed to query CLIENT_ID
const PERMISSION = process.env.PLAYGROUND_PERMISSION ?? 'RMS_REGISTRATION_VIEW';

const jwks = createRemoteJWKSet(new URL(`${IDENTITY}/.well-known/jwks.json`));
const pending = new Map<string, { state: string; expires: number }>(); // transaction_id -> state (single use)
const seenJti = new Set<string>();
const credentials = ServiceCredentials.load(PRINCIPAL, join(__dirname, '..', 'bu-reference-app', '.keys', `${PRINCIPAL}.pem`)).catch(() => null);

const app = Fastify({ logger: { level: 'info', redact: ['req.headers.cookie', '*.core_assertion'] } });

app.get('/', async (_req, reply) => reply.type('text/html; charset=utf-8').send(PAGE));

/** Backend step 1: pre-create the transaction on Identity (server-to-server) and remember the state. */
app.post('/api/start', async (req, reply) => {
  // Bind the transaction to the origin the page is actually served from (any origin registered for the client).
  const origin = typeof req.headers.origin === 'string' && /^https?:\/\/[^/]+$/.test(req.headers.origin) ? req.headers.origin : ORIGIN;
  const state = randomBytes(24).toString('base64url');
  const request = { client_id: CLIENT_ID, state, origin, display: 'embed' };
  const res = await fetch(`${IDENTITY}/auth/transaction`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  const body = (await res.json()) as { transaction_id?: string; login_url?: string; expires_in?: number; error?: string; message?: string };
  if (!res.ok || !body.transaction_id) {
    return reply.status(res.status).send({ error: body.error, message: body.message, hint: body.error === 'ORIGIN_NOT_ALLOWED' ? `register ${origin}: npm run client -- origins add ${CLIENT_ID} ${origin}` : undefined });
  }
  pending.set(body.transaction_id, { state, expires: Date.now() + (body.expires_in ?? 300) * 1000 });
  // The CSRF token is for the login page itself; never show it in the parent page.
  return { request, response: { ...body, csrf: body && 'csrf' in body ? '(returned; used only by the login page)' : undefined } };
});

/** Backend step 2: verify the assertion received via postMessage, then ask Authorization. */
app.post<{ Body: { transaction_id?: string; state?: string; expected_state?: string; external?: boolean; core_assertion?: string } }>('/api/callback', async (req, reply) => {
  const { transaction_id: txn, state, core_assertion: assertion } = req.body ?? {};
  const checks: { check: string; ok: boolean; detail?: string }[] = [];
  const fail = (status: number) => reply.status(status).send({ verified: false, checks });

  let expectedState: string | undefined;
  if (req.body?.external) {
    // Pasted login_url (e.g. created in Postman): this backend did not store the state, so it comes from the URL.
    // A real BU backend must always create and remember the transaction itself.
    expectedState = req.body.expected_state;
    checks.push({ check: 'transaction created outside this backend (pasted login_url) - state taken from the URL', ok: typeof expectedState === 'string', detail: 'dev playground only' });
  } else {
    const stored = txn ? pending.get(txn) : undefined;
    if (txn) pending.delete(txn);
    checks.push({ check: 'transaction started by this backend (single use, not expired)', ok: Boolean(stored && stored.expires > Date.now()) });
    if (!stored || stored.expires <= Date.now()) return fail(400);
    expectedState = stored.state;
  }
  checks.push({ check: 'state matches', ok: expectedState === state });
  if (!expectedState || expectedState !== state || typeof assertion !== 'string') return fail(400);

  let header;
  try {
    header = decodeProtectedHeader(assertion);
  } catch {
    checks.push({ check: 'compact JWS', ok: false });
    return fail(401);
  }
  checks.push({ check: 'alg is RS256 and kid present', ok: header.alg === 'RS256' && typeof header.kid === 'string', detail: `alg=${header.alg} kid=${header.kid}` });
  if (header.alg !== 'RS256' || !header.kid) return fail(401);

  let payload;
  try {
    ({ payload } = await jwtVerify(assertion, jwks, { issuer: IDENTITY, audience: CLIENT_ID, algorithms: ['RS256'], typ: 'JWT', maxTokenAge: '60s', clockTolerance: 5 }));
    checks.push({ check: 'signature verified with Identity JWKS; iss, aud, exp, iat, typ valid', ok: true, detail: `iss=${payload.iss} aud=${payload.aud}` });
  } catch (error) {
    checks.push({ check: 'signature / claims', ok: false, detail: (error as Error).message });
    return fail(401);
  }
  checks.push({ check: 'txn claim equals transaction_id', ok: payload.txn === txn });
  checks.push({ check: 'jti not replayed', ok: typeof payload.jti === 'string' && !seenJti.has(payload.jti) });
  if (payload.txn !== txn || typeof payload.jti !== 'string' || seenJti.has(payload.jti)) return fail(401);
  seenJti.add(payload.jti);

  // Authorization (server-side, service token signed by this backend's key; verified via its JWKS)
  let authorization: unknown = { skipped: `no key for service principal ${PRINCIPAL} (start npm run example:rms once to generate it)` };
  const creds = await credentials;
  if (creds) {
    const call = async (path: string, body: unknown) => {
      const res = await fetch(`${AUTHZ}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${await creds.mint('miqaat-core-authorization')}` },
        body: JSON.stringify(body),
      });
      return { status: res.status, body: await res.json() };
    };
    authorization = {
      check: { request: { its_id: payload.sub, client_id: CLIENT_ID, permission: PERMISSION }, response: await call('/authorization/check', { its_id: payload.sub, client_id: CLIENT_ID, permission: PERMISSION }) },
      effective: await call('/authorization/effective-permissions', { its_id: payload.sub, client_id: CLIENT_ID }),
    };
  }
  return { verified: true, checks, header, claims: payload, authorization };
});

const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Embedded login playground</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 24px; color: #1d2433; background: #f6f7f9 }
  h1 { font-size: 20px } .grid { display: grid; grid-template-columns: 440px 1fr; gap: 20px; align-items: start }
  .panel { background: #fff; border: 1px solid #dde1e7; border-radius: 10px; padding: 16px }
  iframe { width: 100%; height: 560px; border: 0 } button { padding: 8px 14px; border-radius: 6px; border: 1px solid #1f6f5c; background: #1f6f5c; color: #fff; cursor: pointer }
  pre { background: #0f1720; color: #d7e0ea; padding: 12px; border-radius: 8px; overflow: auto; max-height: 360px; font-size: 12px }
  .ok { color: #1f7a3a } .bad { color: #b3261e } code { background: #eef1f4; padding: 1px 4px; border-radius: 4px }
  @media (max-width: 900px) { .grid { grid-template-columns: 1fr } }
</style></head>
<body>
  <h1>Miqaat Identity Federation: embedded login playground</h1>
  <p>App origin <code>${ORIGIN}</code> · client <code>${CLIENT_ID}</code> · Identity <code>${IDENTITY}</code></p>
  <div class="grid">
    <div class="panel">
      <button id="start">Start embedded login</button>
      <p style="margin:14px 0 6px">or paste a <code>login_url</code> from Postman (<code>POST /auth/transaction</code> with <code>"origin": "${ORIGIN}"</code>):</p>
      <div style="display:flex;gap:6px"><input id="pasted" style="flex:1;padding:6px" placeholder="http://localhost:3001/embed/login?client_id=...&amp;origin=${encodeURIComponent(ORIGIN)}"><button id="open">Open</button></div>
      <div id="frame"><p>The Core login form will appear here in an iframe.</p></div>
    </div>
    <div class="panel">
      <h3>1. Transaction (backend → POST /auth/transaction)</h3><pre id="s1">-</pre>
      <h3>2. postMessage from the iframe</h3><pre id="s2">-</pre>
      <h3>3. Backend verification (JWKS) + Authorization</h3><div id="checks"></div><pre id="s3">-</pre>
    </div>
  </div>
<script>
  const IDENTITY = ${JSON.stringify(new URL(IDENTITY).origin)};
  let pending = null;
  const show = (id, v) => document.getElementById(id).textContent = typeof v === 'string' ? v : JSON.stringify(v, null, 2);
  const short = (t) => typeof t === 'string' && t.length > 60 ? t.slice(0, 40) + '…(' + t.length + ' chars)' : t;

  function mount(loginUrl, transactionId, state, external) {
    const iframe = document.createElement('iframe');
    iframe.title = 'Miqaat Core sign in';
    iframe.src = loginUrl;
    iframe.referrerPolicy = 'origin';
    iframe.allow = 'storage-access';
    iframe.setAttribute('sandbox', 'allow-scripts allow-forms allow-same-origin allow-storage-access-by-user-activation');
    document.getElementById('frame').replaceChildren(iframe);
    pending = { transaction_id: transactionId, state, iframe, external };
  }
  const reset = () => { show('s2', '-'); show('s3', '-'); document.getElementById('checks').innerHTML = ''; };

  document.getElementById('start').onclick = async () => {
    reset();
    const res = await fetch('/api/start', { method: 'POST' });
    const data = await res.json();
    show('s1', data);
    if (!res.ok) return;
    mount(data.response.login_url, data.response.transaction_id, data.request.state, false);
  };

  function openPasted(raw) {
    reset();
    let url;
    try { url = new URL(raw.trim()); } catch { return show('s1', 'Not a valid URL'); }
    const p = url.searchParams;
    const problems = [];
    if (url.origin !== IDENTITY || url.pathname !== '/embed/login') problems.push('must start with ' + IDENTITY + '/embed/login');
    if ((p.get('display') || 'embed') !== 'embed') problems.push('display must be embed');
    if (p.get('origin') !== location.origin) problems.push('origin parameter must be ' + location.origin + ' (was ' + p.get('origin') + '). Create the transaction with "origin": "' + location.origin + '"');
    if (!p.get('transaction_id') || !p.get('state')) problems.push('transaction_id and state are required');
    if (problems.length) return show('s1', { error: 'This login_url cannot be embedded here', problems });
    show('s1', { source: 'pasted login_url (transaction created outside this page, e.g. Postman)', client_id: p.get('client_id'), transaction_id: p.get('transaction_id'), state: p.get('state'), origin: p.get('origin'),
      note: 'Transactions expire after 5 minutes and work once. If the frame shows "The sign-in request has expired", create a new one.' });
    mount(url.toString(), p.get('transaction_id'), p.get('state'), true);
  }
  document.getElementById('open').onclick = () => openPasted(document.getElementById('pasted').value);
  const fromQuery = new URLSearchParams(location.search).get('login_url');
  if (fromQuery) { document.getElementById('pasted').value = fromQuery; openPasted(fromQuery); }

  window.addEventListener('message', async (event) => {
    if (event.origin !== IDENTITY) return;                                   // exact Identity origin
    if (!pending || event.source !== pending.iframe.contentWindow) return;   // our iframe only
    const d = event.data;
    if (!d || d.transaction_id !== pending.transaction_id) return;
    if (d.type === 'MIQAAT_AUTH_RESIZE') { pending.iframe.style.height = Math.min(Math.max(d.height, 320), 1200) + 'px'; return; }
    if (d.type === 'MIQAAT_AUTH_ERROR') {
      show('s2', { origin: event.origin, ...d });
      show('s3', d.error === 'TRANSACTION_EXPIRED'
        ? (pending.external
          ? 'This login_url was already used or has expired. Create a new transaction in Postman and paste the new login_url.'
          : 'This transaction was already used or has expired. Click "Start embedded login" again.')
        : 'Sign-in could not start (' + (d.code || d.error) + ').');
      return;
    }
    show('s2', { origin: event.origin, ...d, core_assertion: short(d.core_assertion) });
    if (d.type !== 'MIQAAT_AUTH_SUCCESS' || d.state !== pending.state) return;
    const body = { transaction_id: d.transaction_id, state: d.state, core_assertion: d.core_assertion, external: pending.external, expected_state: pending.state };
    pending = null;
    const res = await fetch('/api/callback', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const result = await res.json();
    document.getElementById('checks').innerHTML = (result.checks || []).map((c) =>
      '<div class="' + (c.ok ? 'ok' : 'bad') + '">' + (c.ok ? '✔ ' : '✘ ') + c.check.replace(/</g, '&lt;') + '</div>').join('');
    show('s3', { verified: result.verified, header: result.header, claims: result.claims, authorization: result.authorization });
    document.getElementById('frame').innerHTML = result.verified
      ? '<p class="ok"><b>Signed in as ' + result.claims.sub + '</b> (sid ' + result.claims.sid + ')</p>'
      : '<p class="bad">Verification failed</p>';
  });
</script>
</body></html>`;

app.listen({ port: PORT, host: '127.0.0.1' }).then(() => app.log.info(`playground on ${ORIGIN} (client ${CLIENT_ID})`));
