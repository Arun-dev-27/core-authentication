# Business Unit integration guide

A complete, runnable implementation lives in `examples/bu-reference-app` (used for RMS, AMS and VMS in local dev).

## 1. Prerequisites (from Core onboarding)

* `client_id` per environment (e.g. `rms-web-prod`) in status `ACTIVE`
* registered embed origin (e.g. `https://rms.example.com`), callback `https://rms.example.com/auth/core/callback`,
  back-channel logout `https://rms.example.com/auth/core/logout`, post-logout redirect
* a registered **service principal** (`AUTHZ_CHECK`, your client IDs) pointing at your backend's public JWKS — there are no API keys
* Federation metadata: `GET https://identity.miqaat.com/.well-known/miqaat-federation`

## 2. Start login (backend)

```ts
const transactionId = `txn_${randomBytes(18).toString('base64url')}`;
const state = randomBytes(24).toString('base64url');
await redis.set(`bu:${CLIENT_ID}:login:${transactionId}`, JSON.stringify({ state }), 'EX', 300);
reply.setCookie('rms_login_txn', transactionId, { httpOnly: true, secure: true, sameSite: 'none', path: '/auth/core', maxAge: 300 });
// The calling page's own origin: a client may register several (e.g. the app and its admin site).
// Identity accepts it only if it is registered for CLIENT_ID.
const origin = new URL(req.headers.origin ?? APP_ORIGIN).origin;
return { transaction_id: transactionId, state,
  login_url: `${IDENTITY}/embed/login?client_id=${CLIENT_ID}&transaction_id=${transactionId}&state=${state}&origin=${encodeURIComponent(origin)}` };
```

Alternatively let Identity create the transaction: `POST /auth/transaction { client_id, state, origin, display }` returns
`transaction_id`, `target_origin`, `login_url`, `expires_in`, `status` and, outside production, the transaction's `csrf` token
(`TRANSACTION_API_RETURNS_CSRF`). Identity reads your client configuration fresh for every transaction, so an origin added or removed
in the Authorization service applies to the next sign-in without a refresh call. `GET /auth/transaction/:id?client_id=` shows its status.

## 3. Embed and receive the assertion (frontend)

```html
<iframe title="Miqaat Core sign in" src="{login_url}" referrerpolicy="origin" allow="storage-access"
        sandbox="allow-scripts allow-forms allow-same-origin allow-storage-access-by-user-activation"></iframe>
```

```js
window.addEventListener('message', (event) => {
  if (event.origin !== 'https://identity.miqaat.com') return;          // exact
  if (event.source !== iframe.contentWindow) return;
  const d = event.data;
  if (!d || d.transaction_id !== pending.transaction_id) return;
  if (d.type === 'MIQAAT_AUTH_RESIZE') { iframe.style.height = `${d.height}px`; return; }
  if (d.type === 'MIQAAT_AUTH_TOP_LEVEL_REQUIRED') { startTopLevelLogin(); return; }
  if (d.type !== 'MIQAAT_AUTH_SUCCESS') return;
  if (Object.keys(d).sort().join() !== 'core_assertion,state,transaction_id,type' || d.state !== pending.state) return;
  // forward UNCHANGED; never decode or trust claims in the browser
  fetch('/auth/core/callback', { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ transaction_id: d.transaction_id, state: d.state, core_assertion: d.core_assertion }) });
});
```

Message types sent by Core: `MIQAAT_AUTH_SUCCESS`, `MIQAAT_AUTH_ERROR` (`TRANSACTION_EXPIRED`, `LOGIN_FAILED`),
`MIQAAT_AUTH_TOP_LEVEL_REQUIRED`, `MIQAAT_AUTH_RESIZE`.

## 4. Verify in the callback (backend)

```ts
import { CoreAssertionVerifier, RedisReplayStore } from './core-assertion-verifier';

const verifier = new CoreAssertionVerifier({
  issuer: 'https://identity.miqaat.com',
  clientId: 'rms-web-prod',
  jwksUri: 'https://identity.miqaat.com/.well-known/jwks.json',
  replayStore: new RedisReplayStore(redis, 'bu:rms-web-prod:jti'),
});

// 1-2: transaction + state (single use, bound to this browser)
if (req.cookies.rms_login_txn !== body.transaction_id) throw 'LOGIN_TRANSACTION_MISMATCH';
const pending = JSON.parse(await redis.getdel(`bu:rms-web-prod:login:${body.transaction_id}`));
if (!pending || !safeEqual(pending.state, body.state)) throw 'STATE_MISMATCH';

// 3-15: kid → JWKS → RS256 → iss → aud (exact) → exp → iat → lifetime → txn → sid → jti replay
const v = await verifier.verifyLoginAssertion(body.core_assertion, { transactionId: body.transaction_id });

// 16-17: map + authorize (server-side)
const access = await authz.effective(v.itsId);          // POST /authorization/effective-permissions
if (access.access !== 'GRANTED') throw 'ACCESS_DENIED';

// 18-19: local session (Redis = revocation list) + encrypted session cookie (examples/bu-reference-app/src/session-cookie-cipher.ts)
const id = await sessions.create({ its_id: v.itsId, sid: v.sid, auth_time: v.authTime });
const core = { iss: v.issuer, sub: v.itsId, aud: v.audience, sid: v.sid, jti: v.jti, txn: v.transactionId, auth_time: v.authTime, iat: v.issuedAt, exp: v.expiresAt };
const cookie = await cookieCipher.seal(id, core, body.core_assertion, SESSION_TTL_SECONDS); // JWE dir + A256GCM, your own key
reply.setCookie('rms_session', cookie, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: SESSION_TTL_SECONDS });
```

On every request decrypt the cookie with `cookieCipher.open()` (tag, `iss` = your origin, `aud` = your client_id, `exp`) and require
the Redis session `lid` to still exist with the same `sid`, so local and back-channel logout revoke a copied cookie at once.
The key (`SESSION_ENC_KEY`, 32 random bytes) comes from your own secret store, never from Core. Details: README section 6.1.

## 5. Authorize every protected API

Every call to the Authorization service carries a fresh RS256 service token signed with your backend's private key
(`examples/bu-reference-app/src/service-credentials.ts`). Publish the public key at `GET /.well-known/jwks.json`.

```ts
const token = await credentials.mint('miqaat-core-authorization'); // typ client-authentication+jwt, iss = sub = rms-backend, 120 s, single use
const res = await fetch(`${AUTHZ}/authorization/check`, {
  method: 'POST',
  headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
  body: JSON.stringify({ its_id, client_id: 'rms-web-prod', module: 'RMS_REGISTRATION', permission: 'RMS_REGISTRATION_VIEW' }),
});
```

```ts
const decision = await authz.check(session.its_id, 'RMS_REGISTRATION_VIEW', 'RMS_REGISTRATION'); // POST /authorization/check
if (!decision.allowed) return reply.status(403).send({ reason: decision.reason });
```

Identity Federation is **not** called for business requests.

## 6. Logout

* **Local only**: destroy your session and cookie.
* **Everywhere**: destroy your session, then top-level form POST to `https://identity.miqaat.com/federation/logout` with
  `client_id`, `logout_hint` (= `sid` from the assertion), `post_logout_redirect_uri` (registered), `state`.
* **Back-channel endpoint** (`POST /auth/core/logout`, form field `logout_token`):

```ts
const { sid } = await verifier.verifyLogoutToken(body.logout_token); // RS256, typ logout+jwt, iss, aud, events, no nonce, jti replay
await sessions.destroyBySid(sid);
return reply.status(200).header('cache-control', 'no-store').send();
```

## 7. Third-party cookies blocked

On `MIQAAT_AUTH_TOP_LEVEL_REQUIRED`, start a new transaction with `display=page` and navigate top-level to the login URL.
Core returns with an auto-submitted form POST (`application/x-www-form-urlencoded`) to your callback. Your callback must
accept both JSON and form bodies, and your transaction cookie must be `SameSite=None; Secure`.
