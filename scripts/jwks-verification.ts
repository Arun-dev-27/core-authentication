/**
 * Live JWKS verification: every token is verified with the PUBLISHED keys of the service that signed it, fetched over
 * HTTP from the configured URLs exactly as an application does, and must fail with any other key.
 *
 *   1. discovery      each service names its own JWKS; Authorization points authentication at Identity's JWKS
 *   2. published      both key sets are public-only RSA (>= 2048 bits, RS256, use sig) and share no kid or modulus
 *   3. Identity       core_assertion (typ JWT) and access token (typ at+jwt) verify ONLY with Identity's JWKS
 *   4. Authorization  authorization_token (typ authz+jwt) verifies ONLY with Authorization's JWKS, for the same sub
 *   5. forged         both services reject tokens signed by an unpublished key under a published kid, and replays
 *
 * Needs the running stack: Identity :3001, Authorization :3002 and the RMS reference app :4001 (it publishes the
 * rms-backend service key Authorization uses to verify this script's service token), plus the demo users.
 *
 *   npm run test:jwks                                  # password from DEV_DEMO_PASSWORD in .env
 *   JWKS_CHECK_ITS_ID=... JWKS_CHECK_PASSWORD=... npm run test:jwks
 *
 * JWKS locations come from configuration only, never from a token or a discovery response. Credentials come only from
 * the environment. The user is signed in once and signed out at the end.
 */
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { createLocalJWKSet, createRemoteJWKSet, decodeJwt, decodeProtectedHeader, errors, generateKeyPair, JWK, JWTPayload, jwtVerify, JWTVerifyGetKey, JWTVerifyOptions, SignJWT } from 'jose';
import { loadEnvFiles } from '@config/configuration';
import { ServiceCredentials } from '../examples/bu-reference-app/src/service-credentials';

loadEnvFiles();

const env = process.env;
const IDENTITY = new URL(env.JWKS_CHECK_IDENTITY_URL ?? env.ISSUER ?? 'http://localhost:3001').origin;
const AUTHZ = (env.JWKS_CHECK_AUTHZ_URL ?? env.AUTHZ_BASE_URL ?? 'http://localhost:3002').replace(/\/+$/, '');
const AUTHZ_ISSUER = (env.JWKS_CHECK_AUTHZ_ISSUER ?? AUTHZ).replace(/\/+$/, '');
const AUTHZ_AUDIENCE = env.AUTHZ_AUDIENCE ?? 'miqaat-core-authorization';
const CLIENT_ID = env.JWKS_CHECK_CLIENT_ID ?? 'rms-web-dev';
const OTHER_CLIENT_ID = 'ams-web-dev';
const APP_ORIGIN = new URL(env.JWKS_CHECK_APP_ORIGIN ?? 'http://localhost:4001').origin;
const PRINCIPAL_ID = env.JWKS_CHECK_SERVICE_PRINCIPAL ?? 'rms-backend';
const SERVICE_KEY_FILE = env.JWKS_CHECK_SERVICE_KEY_FILE ?? join(__dirname, '..', 'examples', 'bu-reference-app', '.keys', `${PRINCIPAL_ID}.pem`);
const ITS_ID = env.JWKS_CHECK_ITS_ID ?? '31267890';
const PASSWORD = env.JWKS_CHECK_PASSWORD ?? env.DEV_DEMO_PASSWORD;

const IDENTITY_JWKS_URI = `${IDENTITY}/.well-known/jwks.json`;
const AUTHZ_JWKS_URI = `${AUTHZ}/.well-known/jwks.json`;
const PRIVATE_JWK_PARAMS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

type PublishedKey = JWK & { kid: string; n: string };
type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
type Verification = { ok: true; payload: JWTPayload } | { ok: false; code: string };

const results: { check: string; ok: boolean }[] = [];

function record(check: string, ok: boolean, detail = '') {
  results.push({ check, ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${check}${detail ? `  (${detail})` : ''}`);
}

function section(title: string) {
  console.log(`\n-- ${title}`);
}

const jar = new Map<string, string>();

async function http(url: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}) {
  const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  const res = await fetch(url, {
    method: init.method ?? 'GET',
    redirect: 'manual',
    headers: { ...(cookie ? { cookie } : {}), ...(init.body !== undefined ? { 'content-type': 'application/json' } : {}), ...(init.headers ?? {}) },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    signal: AbortSignal.timeout(10_000),
  });
  for (const line of res.headers.getSetCookie()) {
    const [pair, ...attrs] = line.split(';');
    const i = pair.indexOf('=');
    const name = pair.slice(0, i).trim();
    const value = pair.slice(i + 1).trim();
    if (value === '' || attrs.some((a) => /max-age=0/i.test(a))) jar.delete(name);
    else jar.set(name, value);
  }
  const text = await res.text();
  let json: Json | null = null;
  try {
    json = JSON.parse(text) as Json;
  } catch {
    /* html */
  }
  return { status: res.status, headers: res.headers, text, json };
}

function joseCode(error: unknown): string {
  if (error instanceof errors.JWKSNoMatchingKey) return 'UNKNOWN_KID';
  if (error instanceof errors.JWSSignatureVerificationFailed) return 'SIGNATURE_INVALID';
  if (error instanceof errors.JWTClaimValidationFailed) return `CLAIM_INVALID_${error.claim.toUpperCase()}`;
  if (error instanceof errors.JWTExpired) return 'EXPIRED';
  if (error instanceof errors.JWSInvalid || error instanceof errors.JWTInvalid) return 'MALFORMED';
  return error instanceof Error ? error.name : 'ERROR';
}

async function verify(token: string, keys: JWTVerifyGetKey, options: JWTVerifyOptions): Promise<Verification> {
  try {
    const { payload } = await jwtVerify(token, keys, { algorithms: ['RS256'], clockTolerance: 5, ...options });
    return { ok: true, payload };
  } catch (error) {
    return { ok: false, code: joseCode(error) };
  }
}

const verdict = (v: Verification) => (v.ok ? 'VERIFIED' : v.code);

/** Same header and signature, different claims. */
function tamper(token: string, claims: Json): string {
  const [header, , signature] = token.split('.');
  return `${header}.${Buffer.from(JSON.stringify({ ...decodeJwt(token), ...claims })).toString('base64url')}.${signature}`;
}

/** A key set holding another service's public key under the token's kid: only the signature can decide. */
function keyUnderKid(key: PublishedKey, kid: string): JWTVerifyGetKey {
  return createLocalJWKSet({ keys: [{ ...key, kid }] });
}

function bits(key: PublishedKey): number {
  return typeof key.n === 'string' ? Buffer.from(key.n, 'base64url').length * 8 : 0;
}

function checkPublishedKeys(name: string, uri: string, res: Awaited<ReturnType<typeof http>>): PublishedKey[] {
  const keys = (Array.isArray(res.json?.keys) ? res.json?.keys : []) as PublishedKey[];
  record(`${name} JWKS is published at ${uri}`, res.status === 200 && keys.length > 0, `${keys.length} key(s), cache-control ${res.headers.get('cache-control') ?? '-'}`);
  const leaked = keys.filter((k) => PRIVATE_JWK_PARAMS.some((p) => p in k));
  record(`${name} JWKS holds public parameters only (no d, p, q, dp, dq, qi)`, keys.length > 0 && leaked.length === 0 && !res.text.includes('PRIVATE KEY'), leaked.map((k) => k.kid).join(','));
  const invalid = keys.filter((k) => k.kty !== 'RSA' || k.alg !== 'RS256' || k.use !== 'sig' || typeof k.kid !== 'string' || k.kid === '' || bits(k) < 2048);
  record(`${name} keys are RSA >= 2048 bits, alg RS256, use sig, with a kid`, keys.length > 0 && invalid.length === 0, keys.map((k) => `${k.kid} ${bits(k)} bits`).join(', '));
  return keys;
}

async function checks() {
  if (!PASSWORD) throw new Error('Set JWKS_CHECK_PASSWORD, or DEV_DEMO_PASSWORD in .env, for the demo user');
  if (!existsSync(SERVICE_KEY_FILE)) throw new Error(`service key ${SERVICE_KEY_FILE} not found: run "npm run example:rms" once so the ${PRINCIPAL_ID} key exists`);
  console.log(`Identity ${IDENTITY} | Authorization ${AUTHZ} | client ${CLIENT_ID} | user ${ITS_ID} | service principal ${PRINCIPAL_ID}`);

  // ------------------------------------------------------------------ 1
  section('1. Discovery');
  const idMeta = await http(`${IDENTITY}/.well-known/miqaat-federation`);
  record("Identity discovery names Identity's own JWKS", idMeta.status === 200 && idMeta.json?.issuer === IDENTITY && idMeta.json?.jwks_uri === IDENTITY_JWKS_URI, String(idMeta.json?.jwks_uri));
  const azMeta = await http(`${AUTHZ}/.well-known/miqaat-authorization`);
  record(
    "Authorization discovery names Authorization's own JWKS, not Identity's",
    azMeta.status === 200 && azMeta.json?.issuer === AUTHZ_ISSUER && azMeta.json?.jwks_uri === AUTHZ_JWKS_URI && azMeta.json?.jwks_uri !== IDENTITY_JWKS_URI,
    String(azMeta.json?.jwks_uri),
  );
  record("Authorization discovery points authentication at Identity's JWKS", azMeta.json?.authentication_jwks_uri === IDENTITY_JWKS_URI, String(azMeta.json?.authentication_jwks_uri));

  // ------------------------------------------------------------------ 2
  section('2. Published keys');
  const identityPublished = checkPublishedKeys('Identity', IDENTITY_JWKS_URI, await http(IDENTITY_JWKS_URI));
  const authzPublished = checkPublishedKeys('Authorization', AUTHZ_JWKS_URI, await http(AUTHZ_JWKS_URI));
  const sharedKid = identityPublished.filter((a) => authzPublished.some((b) => b.kid === a.kid));
  const sharedModulus = identityPublished.filter((a) => authzPublished.some((b) => b.n === a.n));
  record(
    'Identity and Authorization publish different keys (no shared kid or modulus)',
    identityPublished.length > 0 && authzPublished.length > 0 && sharedKid.length === 0 && sharedModulus.length === 0,
    `Identity ${identityPublished.map((k) => k.kid).join(',')} | Authorization ${authzPublished.map((k) => k.kid).join(',')}`,
  );
  if (identityPublished.length === 0 || authzPublished.length === 0) return;

  // Remote key sets with kid lookup, as an application uses them.
  const identityKeys = createRemoteJWKSet(new URL(IDENTITY_JWKS_URI));
  const authzKeys = createRemoteJWKSet(new URL(AUTHZ_JWKS_URI));

  // ------------------------------------------------------------------ 3
  section("3. Identity tokens verify only with Identity's published JWKS");
  const txn = await http(`${IDENTITY}/auth/transaction`, {
    method: 'POST',
    body: { client_id: CLIENT_ID, state: randomBytes(16).toString('hex'), origin: APP_ORIGIN, display: 'embed' },
  });
  if (txn.status !== 201 || typeof txn.json?.csrf !== 'string') {
    record(`Login transaction created for ${CLIENT_ID}`, false, `status ${txn.status} ${txn.json?.error ?? ''} (the CSRF token is returned outside production only)`);
    return;
  }
  const login = await http(`${IDENTITY}/embed/login`, {
    method: 'POST',
    headers: { origin: IDENTITY, 'x-csrf-token': txn.json.csrf },
    body: { transaction_id: txn.json.transaction_id, client_id: CLIENT_ID, identity_type: 'ITS', its_id: ITS_ID, password: PASSWORD },
  });
  const assertion = login.json?.session?.token;
  record(`Embedded sign-in as ${ITS_ID} returns a core_assertion`, login.status === 200 && typeof assertion === 'string', `status ${login.status}${login.json?.error ? ` ${login.json.error.code}` : ''}`);
  if (typeof assertion !== 'string') return;

  const aHeader = decodeProtectedHeader(assertion);
  const aKid = String(aHeader.kid);
  record(
    "core_assertion is RS256 / typ JWT and its kid is published by Identity, not by Authorization",
    aHeader.alg === 'RS256' && aHeader.typ === 'JWT' && identityPublished.some((k) => k.kid === aKid) && !authzPublished.some((k) => k.kid === aKid),
    aKid,
  );
  const assertionOk = await verify(assertion, identityKeys, { issuer: IDENTITY, audience: CLIENT_ID, typ: 'JWT', requiredClaims: ['sub', 'sid', 'txn', 'jti', 'iat', 'exp'] });
  record(
    "core_assertion verifies with Identity's published JWKS (signature, iss, aud, typ, exp)",
    assertionOk.ok && assertionOk.payload.sub === ITS_ID && assertionOk.payload.txn === txn.json.transaction_id,
    assertionOk.ok ? `sub ${assertionOk.payload.sub}, aud ${String(assertionOk.payload.aud)}` : assertionOk.code,
  );
  const aWithAuthz = await verify(assertion, authzKeys, { issuer: IDENTITY, audience: CLIENT_ID });
  record("core_assertion is rejected by Authorization's published JWKS", !aWithAuthz.ok, verdict(aWithAuthz));
  const aAuthzKeySameKid = await verify(assertion, keyUnderKid(authzPublished[0], aKid), { issuer: IDENTITY, audience: CLIENT_ID });
  record("core_assertion fails the signature with Authorization's key even under the same kid", !aAuthzKeySameKid.ok && aAuthzKeySameKid.code === 'SIGNATURE_INVALID', verdict(aAuthzKeySameKid));
  const aTampered = await verify(tamper(assertion, { sub: '30416234' }), identityKeys, { issuer: IDENTITY, audience: CLIENT_ID });
  record("core_assertion with a changed sub is rejected by Identity's JWKS", !aTampered.ok && aTampered.code === 'SIGNATURE_INVALID', verdict(aTampered));
  const aOtherClient = await verify(assertion, identityKeys, { issuer: IDENTITY, audience: OTHER_CLIENT_ID });
  record(`core_assertion for ${CLIENT_ID} is rejected for ${OTHER_CLIENT_ID} (aud)`, !aOtherClient.ok && aOtherClient.code === 'CLAIM_INVALID_AUD', verdict(aOtherClient));

  const portal = await http(`${IDENTITY}/portal`);
  const bootMatch = /<script type="application\/json" id="miqaat-boot">(.*?)<\/script>/s.exec(portal.text);
  const boot = bootMatch ? (JSON.parse(bootMatch[1]) as Json) : null;
  const portalLogin = boot
    ? await http(`${IDENTITY}/login`, { method: 'POST', headers: { origin: IDENTITY, 'x-csrf-token': boot.csrf }, body: { transaction_id: boot.transaction_id, its_id: ITS_ID, password: PASSWORD } })
    : null;
  const accessToken = portalLogin?.json?.session?.token;
  record(`Portal sign-in as ${ITS_ID} returns an access token`, typeof accessToken === 'string', `status ${portalLogin?.status ?? portal.status}${portalLogin?.json?.error ? ` ${portalLogin.json.error.code}` : ''}`);
  if (typeof accessToken === 'string') {
    const tHeader = decodeProtectedHeader(accessToken);
    const accessOk = await verify(accessToken, identityKeys, { issuer: IDENTITY, audience: AUTHZ_AUDIENCE, typ: 'at+jwt', requiredClaims: ['sub', 'jti', 'iat', 'exp'] });
    record(
      "Access token (at+jwt) verifies with Identity's published JWKS",
      accessOk.ok && accessOk.payload.sub === ITS_ID && identityPublished.some((k) => k.kid === tHeader.kid),
      accessOk.ok ? `kid ${String(tHeader.kid)}, aud ${String(accessOk.payload.aud)}` : accessOk.code,
    );
    const accessWithAuthz = await verify(accessToken, authzKeys, { issuer: IDENTITY, audience: AUTHZ_AUDIENCE });
    record("Access token is rejected by Authorization's published JWKS", !accessWithAuthz.ok, verdict(accessWithAuthz));
    const accepted = await http(`${AUTHZ}/me/assignments`, { headers: { authorization: `Bearer ${accessToken}` } });
    record("Authorization service accepts the access token it verifies with Identity's JWKS (GET /me/assignments)", accepted.status === 200, `status ${accepted.status}`);
  }

  // ------------------------------------------------------------------ 4
  section("4. Authorization tokens verify only with Authorization's published JWKS");
  const credentials = await ServiceCredentials.load(PRINCIPAL_ID, SERVICE_KEY_FILE);
  const serviceKid = String(credentials.jwks().keys[0].kid);
  const appJwks = await http(`${APP_ORIGIN}/.well-known/jwks.json`).catch(() => null);
  record(
    `${PRINCIPAL_ID} publishes the service key this check signs with (${APP_ORIGIN}/.well-known/jwks.json)`,
    appJwks?.status === 200 && ((appJwks.json?.keys ?? []) as JWK[]).some((k) => k.kid === serviceKid),
    appJwks ? serviceKid : 'not reachable: start npm run example:rms',
  );
  const tokenRes = await http(`${AUTHZ}/authorization/token`, {
    method: 'POST',
    headers: { authorization: `Bearer ${await credentials.mint(AUTHZ_AUDIENCE)}` },
    body: { its_id: ITS_ID, client_id: CLIENT_ID },
  });
  const authzToken = tokenRes.json?.authorization_token;
  record(
    'POST /authorization/token returns a signed authorization_token',
    tokenRes.status === 200 && typeof authzToken === 'string',
    `status ${tokenRes.status}${tokenRes.json?.error ? ` ${tokenRes.json.error}` : ''}, access ${tokenRes.json?.access ?? '-'}${tokenRes.json?.reason ? ` ${tokenRes.json.reason}` : ''}`,
  );
  if (typeof authzToken === 'string') {
    const zHeader = decodeProtectedHeader(authzToken);
    const zKid = String(zHeader.kid);
    record(
      'authorization_token is RS256 / typ authz+jwt and its kid is published by Authorization, not by Identity',
      zHeader.alg === 'RS256' && zHeader.typ === 'authz+jwt' && zKid === tokenRes.json?.kid && authzPublished.some((k) => k.kid === zKid) && !identityPublished.some((k) => k.kid === zKid),
      zKid,
    );
    record("Token response names Authorization's own issuer and JWKS", tokenRes.json?.issuer === AUTHZ_ISSUER && tokenRes.json?.jwks_uri === AUTHZ_JWKS_URI, String(tokenRes.json?.jwks_uri));
    const zOk = await verify(authzToken, authzKeys, { issuer: AUTHZ_ISSUER, audience: CLIENT_ID, typ: 'authz+jwt', requiredClaims: ['sub', 'jti', 'iat', 'exp', 'access'] });
    record(
      "authorization_token verifies with Authorization's published JWKS (signature, iss, aud, typ, exp) for the core_assertion's sub",
      zOk.ok && assertionOk.ok && zOk.payload.sub === assertionOk.payload.sub,
      zOk.ok ? `sub ${zOk.payload.sub}, access ${String(zOk.payload.access)}` : zOk.code,
    );
    const zWithIdentity = await verify(authzToken, identityKeys, { issuer: AUTHZ_ISSUER, audience: CLIENT_ID });
    record("authorization_token is rejected by Identity's published JWKS", !zWithIdentity.ok, verdict(zWithIdentity));
    const zIdentityKeySameKid = await verify(authzToken, keyUnderKid(identityPublished[0], zKid), { issuer: AUTHZ_ISSUER, audience: CLIENT_ID });
    record("authorization_token fails the signature with Identity's key even under the same kid", !zIdentityKeySameKid.ok && zIdentityKeySameKid.code === 'SIGNATURE_INVALID', verdict(zIdentityKeySameKid));
    const zTampered = await verify(tamper(authzToken, { access: 'GRANTED', permissions: ['RMS_REGISTRATION_DELETE'] }), authzKeys, { issuer: AUTHZ_ISSUER, audience: CLIENT_ID });
    record("authorization_token with added permissions is rejected by Authorization's JWKS", !zTampered.ok && zTampered.code === 'SIGNATURE_INVALID', verdict(zTampered));
    const zOtherClient = await verify(authzToken, authzKeys, { issuer: AUTHZ_ISSUER, audience: OTHER_CLIENT_ID });
    record(`authorization_token for ${CLIENT_ID} is rejected for ${OTHER_CLIENT_ID} (aud)`, !zOtherClient.ok && zOtherClient.code === 'CLAIM_INVALID_AUD', verdict(zOtherClient));
    const asBearer = await http(`${AUTHZ}/me/assignments`, { headers: { authorization: `Bearer ${authzToken}` } });
    record('Authorization service refuses an authorization_token as a login credential', asBearer.status === 401, `status ${asBearer.status} ${asBearer.json?.error ?? ''}`);
  }

  // ------------------------------------------------------------------ 5
  section('5. Services reject tokens not signed by the published keys');
  const { privateKey: rogueKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const now = Math.floor(Date.now() / 1000);
  const jti = () => randomBytes(16).toString('hex');

  const forgedAccess = await new SignJWT({ token_use: 'access', sid: 'sid_forged_by_jwks_check' })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: identityPublished[0].kid })
    .setIssuer(IDENTITY).setSubject(ITS_ID).setAudience(AUTHZ_AUDIENCE).setJti(jti()).setIssuedAt(now).setExpirationTime(now + 300)
    .sign(rogueKey);
  const forgedAtAuthz = await http(`${AUTHZ}/me/assignments`, { headers: { authorization: `Bearer ${forgedAccess}` } });
  record("Authorization rejects an access token signed by an unpublished key under Identity's kid", forgedAtAuthz.status === 401, `status ${forgedAtAuthz.status} ${forgedAtAuthz.json?.error ?? ''}`);

  const forgedAdmin = await new SignJWT({ token_use: 'access', sid: 'sid_forged_by_jwks_check', role_id: '00000000-0000-4000-8000-000000000000', scope_type: 'CORE', scope_id: null })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: identityPublished[0].kid })
    .setIssuer(IDENTITY).setSubject(ITS_ID).setAudience(IDENTITY).setJti(jti()).setIssuedAt(now).setExpirationTime(now + 300)
    .sign(rogueKey);
  const forgedAtIdentity = await http(`${IDENTITY}/federation/clients/${CLIENT_ID}/refresh`, { method: 'POST', headers: { authorization: `Bearer ${forgedAdmin}` } });
  record("Identity rejects an admin token signed by an unpublished key under its own kid", forgedAtIdentity.status === 401, `status ${forgedAtIdentity.status} ${forgedAtIdentity.json?.error ?? ''}`);

  const forgedService = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ: 'client-authentication+jwt', kid: serviceKid })
    .setIssuer(PRINCIPAL_ID).setSubject(PRINCIPAL_ID).setAudience(AUTHZ_AUDIENCE).setJti(jti()).setIssuedAt(now).setExpirationTime(now + 120)
    .sign(rogueKey);
  const forgedServiceRes = await http(`${AUTHZ}/authorization/token`, { method: 'POST', headers: { authorization: `Bearer ${forgedService}` }, body: { its_id: ITS_ID, client_id: CLIENT_ID } });
  record(`Authorization rejects a ${PRINCIPAL_ID} service token signed by an unpublished key under its kid`, forgedServiceRes.status === 401, `status ${forgedServiceRes.status} ${forgedServiceRes.json?.error ?? ''}`);

  const once = await credentials.mint(AUTHZ_AUDIENCE);
  const first = await http(`${AUTHZ}/authorization/token`, { method: 'POST', headers: { authorization: `Bearer ${once}` }, body: { its_id: ITS_ID, client_id: CLIENT_ID } });
  const replay = await http(`${AUTHZ}/authorization/token`, { method: 'POST', headers: { authorization: `Bearer ${once}` }, body: { its_id: ITS_ID, client_id: CLIENT_ID } });
  record('A genuine service token works once and its replay is rejected', first.status === 200 && replay.status === 401, `first ${first.status}, replay ${replay.status} ${replay.json?.error ?? ''}`);
}

async function main() {
  try {
    await checks();
  } finally {
    // End the federation session this check created (and its back-channel logout).
    if (jar.size > 0) await http(`${IDENTITY}/federation/logout`, { method: 'POST', headers: { origin: IDENTITY }, body: {} }).catch(() => undefined);
  }
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length > 0 || results.length === 0 ? 1 : 0);
}

main().catch((error: unknown) => {
  console.error('jwks verification error:', error instanceof Error ? error.message : error);
  process.exit(1);
});
