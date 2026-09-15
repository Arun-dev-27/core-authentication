# Redis key design (with example values)

Every Redis key used by Identity Federation, Core Authorization and the application (BU) reference apps, with its type, TTL and an
**example value**.

- **Structure:** examples keep the real format (field order as written by the code, ID formats, the seeded `login-web-dev` client).
- **Mock values:** `csrf`, `handle_hash` and the rate-limit hash are fake. Real IDs and timestamps differ on every run.
- **Storage:** JSON values are stored as one line; here they are pretty-printed.

Complete guide (instances, atomicity, failure behaviour, production settings, operations): [`../../REDIS.md`](../../REDIS.md).

Look at real keys locally (names and TTLs; values contain CSRF tokens and session data, so don't paste them into tickets):

```powershell
docker exec miqaat-authn-redis redis-cli -n 0 --scan --pattern 'federation:*'
docker exec miqaat-authz-redis redis-cli -n 0 --scan --pattern 'authz:*'
docker exec miqaat-authn-redis redis-cli -n 0 TTL  federation:session:sid_hqJmohH8o1Hkbk_a-ALPH9if
docker exec miqaat-authn-redis redis-cli -n 0 GET  federation:session:sid_hqJmohH8o1Hkbk_a-ALPH9if
```

Contents: [Identity Federation](#1-identity-federation-redis_url-elasticache-a) · [Core Authorization](#2-core-authorization-elasticache-b) · [Application (BU) reference apps](#3-application-bu-reference-apps-their-own-redis) · [Rules](#4-rules)

---

## 1. Identity Federation (`REDIS_URL`, ElastiCache A)

Local: `redis://localhost:6391/0` (tests use DB 1).

| Key | Type | TTL | Example value (short) |
|---|---|---|---|
| `federation:txn:<transaction_id>` | string (JSON) | 300 s; portal transaction bound to a session: session's remaining absolute lifetime | `{"transaction_id":"txn_…","client_id":"login-web-dev","status":"PENDING",…}` |
| `federation:session:<sid>` | string (JSON) | idle 1800 s, extended on SSO continue, never past absolute 28800 s | `{"sid":"sid_…","its_id":"31267890","is_active":true,…}` |
| `federation:session-handle:<sha256(handle)>` | string | same as session | `sid_hqJmohH8o1Hkbk_a-ALPH9if` |
| `federation:user-sessions:<its_id>` | set | 28800 s | `sid_hqJmohH8o1Hkbk_a-ALPH9if` |
| `federation:session-clients:<sid>` | set | session absolute remaining | `login-web-dev`, `rms-web-dev` |
| `federation:jti:<jti>` | string | 60 s | `login-web-dev\|sid_hqJmohH8o1Hkbk_a-ALPH9if` |
| `federation:client-cfg:<client_id>` | string (JSON) or `__NOT_FOUND__` | 30 s (`__NOT_FOUND__`: 10 s) | `{"client_id":"login-web-dev","status":"ACTIVE",…}` |
| `ratelimit:login:ip:<ip>` | string counter | 300 s | `4` |
| `ratelimit:login:id:<sha256("ITS:<its_id>")>` | string counter | 900 s | `2` |

### 1.1 `federation:txn:<transaction_id>`: login transaction

Created by `POST /auth/transaction` or `GET /embed/login` (`SET … EX 300 NX`); completed atomically by a Lua script (`status` → `COMPLETED`, `KEEPTTL`).

```text
> TYPE federation:txn:txn_BZp1czcVyQqQBPDbGjlb8NWB
string
> TTL federation:txn:txn_BZp1czcVyQqQBPDbGjlb8NWB
(integer) 241
> GET federation:txn:txn_BZp1czcVyQqQBPDbGjlb8NWB
```
```json
{
  "transaction_id": "txn_BZp1czcVyQqQBPDbGjlb8NWB",
  "client_id": "login-web-dev",
  "state": "PnBg2UVRSmUikxUgJ8yCvO0vHsZGn-kZ",
  "display": "embed",
  "embed_origin": "http://localhost:3100",
  "callback_uri": null,
  "csrf": "Q2xR7mNvT4kPz8LwYs1BcH6dFj0aE3gUoI5qW9tVnXe",
  "status": "PENDING",
  "created_at": "2026-09-15T12:26:58.999Z",
  "expires_at": "2026-09-15T12:31:58.999Z"
}
```

After sign-in the same key holds `"status": "COMPLETED"` until it expires; a second use returns `409 TRANSACTION_ALREADY_USED`.

**Portal transaction** (`GET /portal`), after sign-in bound to the session, so its TTL becomes the session's remaining absolute lifetime:

```text
> TTL federation:txn:txn_70TD8d7gWtaqDpGAm1FgC7Rc
(integer) 28740
> GET federation:txn:txn_70TD8d7gWtaqDpGAm1FgC7Rc
```
```json
{
  "transaction_id": "txn_70TD8d7gWtaqDpGAm1FgC7Rc",
  "client_id": null,
  "state": null,
  "display": "portal",
  "embed_origin": null,
  "callback_uri": null,
  "csrf": "mK4tR9vBw2XyLp7Qe5Nh1Zc8Jd3Gs6Fa0Ui4Oo2Tl9x",
  "status": "COMPLETED",
  "created_at": "2026-09-15T12:26:58.120Z",
  "expires_at": "2026-09-15T12:31:58.120Z",
  "sid": "sid_KwlFpQ2u31rpK9z8QhXmVypN"
}
```

`expires_at` keeps the original 5-minute value; the Redis TTL is what actually applies after binding.

### 1.2 `federation:session:<sid>`: central federation session

Written together with the three keys below in one `MULTI` on password sign-in. The cookie holds a random handle; Redis stores only its SHA-256 (`handle_hash`).

```text
> TYPE federation:session:sid_hqJmohH8o1Hkbk_a-ALPH9if
string
> TTL federation:session:sid_hqJmohH8o1Hkbk_a-ALPH9if
(integer) 1742
> GET federation:session:sid_hqJmohH8o1Hkbk_a-ALPH9if
```
```json
{
  "sid": "sid_hqJmohH8o1Hkbk_a-ALPH9if",
  "its_id": "31267890",
  "identity_type": "ITS",
  "display_name": "Murtaza Saifuddin",
  "auth_method": "password",
  "auth_time": 1789475219,
  "created_at": "2026-09-15T12:26:59.256Z",
  "expires_at": "2026-09-15T12:56:59.256Z",
  "absolute_expires_at": "2026-09-15T20:26:59.256Z",
  "is_active": true,
  "handle_hash": "9f2c4e7a1b3d5f6082a4c6e8f0b2d4f61a3c5e7092b4d6f8a0c2e4f6081a3c5e"
}
```

A Non-ITS member has `"identity_type": "NON_ITS"` and an `its_id` like `NITS-3FA91C0E`.

### 1.3 `federation:session-handle:<sha256(handle)>`: cookie → session index

```text
> TYPE federation:session-handle:9f2c4e7a1b3d5f6082a4c6e8f0b2d4f61a3c5e7092b4d6f8a0c2e4f6081a3c5e
string
> TTL federation:session-handle:9f2c4e7a1b3d5f6082a4c6e8f0b2d4f61a3c5e7092b4d6f8a0c2e4f6081a3c5e
(integer) 1742
> GET federation:session-handle:9f2c4e7a1b3d5f6082a4c6e8f0b2d4f61a3c5e7092b4d6f8a0c2e4f6081a3c5e
"sid_hqJmohH8o1Hkbk_a-ALPH9if"
```

### 1.4 `federation:user-sessions:<its_id>`: sessions of a user (force logout)

```text
> TYPE federation:user-sessions:31267890
set
> TTL federation:user-sessions:31267890
(integer) 28641
> SMEMBERS federation:user-sessions:31267890
1) "sid_hqJmohH8o1Hkbk_a-ALPH9if"
2) "sid_KwlFpQ2u31rpK9z8QhXmVypN"
```

Two members = the user is signed in on two browsers or devices.

### 1.5 `federation:session-clients:<sid>`: applications to notify on logout

```text
> TYPE federation:session-clients:sid_hqJmohH8o1Hkbk_a-ALPH9if
set
> TTL federation:session-clients:sid_hqJmohH8o1Hkbk_a-ALPH9if
(integer) 28641
> SMEMBERS federation:session-clients:sid_hqJmohH8o1Hkbk_a-ALPH9if
1) "login-web-dev"
2) "rms-web-dev"
```

On sign-out everywhere Identity POSTs a signed `logout+jwt` to the back-channel URI of each member.

### 1.6 `federation:jti:<jti>`: issued assertion marker

Traceability only (`client_id|sid`); the token itself is never stored. One-time use is enforced by the receiving application.

```text
> TYPE federation:jti:f417f849-7aca-4a78-a7b6-b5b3a8ff50cf
string
> TTL federation:jti:f417f849-7aca-4a78-a7b6-b5b3a8ff50cf
(integer) 47
> GET federation:jti:f417f849-7aca-4a78-a7b6-b5b3a8ff50cf
"login-web-dev|sid_hqJmohH8o1Hkbk_a-ALPH9if"
```

### 1.7 `federation:client-cfg:<client_id>`: client configuration cache

Copy of `GET /internal/federation/clients/:clientId` from Authorization. Deleted and re-read when a transaction is created, the login page opens and a user signs in; `config_version` is the client's `updated_at`.

```text
> TYPE federation:client-cfg:login-web-dev
string
> TTL federation:client-cfg:login-web-dev
(integer) 26
> GET federation:client-cfg:login-web-dev
```
```json
{
  "client_id": "login-web-dev",
  "name": "Miqaat Login Page (DEV)",
  "application_code": "login-page",
  "application_name": "Miqaat Login Page",
  "business_unit": "Core Services",
  "utility": null,
  "environment": "DEV",
  "client_type": "WEB",
  "authentication_mode": "EMBEDDED_OR_REDIRECT",
  "status": "ACTIVE",
  "allowed_embed_origins": ["http://localhost:3100"],
  "callback_uri": "http://localhost:3100/auth/core/callback",
  "callback_uris": ["http://localhost:3100/auth/core/callback"],
  "back_channel_logout_uri": "http://localhost:3100/auth/core/logout",
  "post_logout_redirect_uri": "http://localhost:3100/logout/callback",
  "post_logout_redirect_uris": ["http://localhost:3100/logout/callback"],
  "initiate_login_uri": "http://localhost:3100/auth/core/login",
  "config_version": "2026-09-14T09:12:41.587Z"
}
```

Unknown client (negative cache):

```text
> GET federation:client-cfg:hbs-web-dev
"__NOT_FOUND__"
> TTL federation:client-cfg:hbs-web-dev
(integer) 8
```

### 1.8 `ratelimit:login:ip:<ip>`: attempts per IP

Incremented on **every** sign-in attempt; TTL set on the first one. More than 30 in 300 s → `429 TOO_MANY_ATTEMPTS`.

```text
> TYPE ratelimit:login:ip:10.0.12.34
string
> GET ratelimit:login:ip:10.0.12.34
"4"
> TTL ratelimit:login:ip:10.0.12.34
(integer) 213
```

Locally the IP is usually `127.0.0.1` or `::1` (key `ratelimit:login:ip:::1`).

### 1.9 `ratelimit:login:id:<sha256>`: failures per identifier

The hash is `sha256("ITS:31267890")` (or `sha256("NON_ITS:<lower-case username>")`), so ITS IDs are not visible in key names. Incremented on a wrong password, deleted on success. 5 failures in 900 s → `429 TOO_MANY_ATTEMPTS`.

```text
> TYPE ratelimit:login:id:4b7d0e2f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b
string
> GET ratelimit:login:id:4b7d0e2f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b
"2"
> TTL ratelimit:login:id:4b7d0e2f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b
(integer) 684
```

The hash shown is an example; compute the real one with the PowerShell snippet in [`REDIS.md` section 10](../../REDIS.md#10-operations-useful-commands).

---

## 2. Core Authorization (ElastiCache B)

Local: `redis://localhost:6392/0` (tests use DB 1).

| Key | Type | TTL | Example value (short) |
|---|---|---|---|
| `authz:version` | string counter | none | `57` |
| `authz:eff:v<version>:<its_id>:<client_id>` | string (JSON) | `EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS` (60) | `{"its_id":"31267890","client_id":"login-web-dev","access":"GRANTED",…}` |
| `authz:svc-jti:<principal_id>:<jti>` | string | token `exp` − now + 5 s (≤ 305 s) | `1` |

### 2.1 `authz:version`: authorization model version

`INCR` after every committed change to roles, role permissions, users, assignments, tenants, business units, utilities, applications, modules or clients (and by the seed scripts). Never delete it on its own (see `REDIS.md` 8.2).

```text
> TYPE authz:version
string
> TTL authz:version
(integer) -1
> GET authz:version
"57"
```

### 2.2 `authz:eff:v<version>:<its_id>:<client_id>`: effective-permission cache

Written by `/authorization/check`, `/authorization/effective-permissions` and `/authorization/token`. The version in the key is the value of `authz:version` at write time, so one `INCR` hides every older entry.

**Granted** (user 31267890, Login Page Viewer):

```text
> TTL authz:eff:v57:31267890:login-web-dev
(integer) 44
> GET authz:eff:v57:31267890:login-web-dev
```
```json
{
  "its_id": "31267890",
  "client_id": "login-web-dev",
  "roles": [
    {
      "role_id": "680332ea-64ad-444c-8d05-a7cec3b68cab",
      "role_name": "Login Page Viewer",
      "scope_type": "BUSINESS_UNIT",
      "scope_id": "56a691c6-2961-4469-936c-a7f0297b602d"
    }
  ],
  "modules": [
    { "code": "LOGIN_PROFILE", "name": "Login Profile", "permissions": ["LOGIN_PROFILE_VIEW"] }
  ],
  "permissions": ["LOGIN_PROFILE_VIEW"],
  "evaluated_at": "2026-09-15T12:26:59.301Z",
  "application": { "code": "login-page", "name": "Miqaat Login Page" },
  "environment": "DEV",
  "business_unit": "Core Services",
  "utility": null,
  "access": "GRANTED"
}
```

**Denied** (user 31189012 has no role covering this application; denials are cached too):

```text
> GET authz:eff:v57:31189012:login-web-dev
```
```json
{
  "its_id": "31189012",
  "client_id": "login-web-dev",
  "roles": [],
  "modules": [],
  "permissions": [],
  "evaluated_at": "2026-09-15T12:26:58.861Z",
  "application": { "code": "login-page", "name": "Miqaat Login Page" },
  "environment": "DEV",
  "business_unit": "Core Services",
  "utility": null,
  "access": "DENIED",
  "reason": "APPLICATION_ACCESS_DENIED"
}
```

Other `reason` values: `CLIENT_NOT_FOUND`, `CLIENT_NOT_ACTIVE`, `APPLICATION_INACTIVE`, `USER_NOT_FOUND`, `USER_INACTIVE`. For `CLIENT_NOT_FOUND` the `application` / `environment` / `business_unit` / `utility` fields are absent.

After a change (`INCR authz:version` → 58) the next check writes `authz:eff:v58:31267890:login-web-dev`; the `v57` entry is no longer read and expires.

### 2.3 `authz:svc-jti:<principal_id>:<jti>`: service-token replay marker

`SET … 1 EX <ttl> NX` after a service token (`typ: client-authentication+jwt`) passes signature and claim checks. If the key already exists, the call is rejected with `401 INVALID_TOKEN` (reason `REPLAYED`).

```text
> TYPE authz:svc-jti:rms-backend:9886cc53-2a1f-4d7e-9b3c-5e8f1a2b4c6d
string
> GET authz:svc-jti:rms-backend:9886cc53-2a1f-4d7e-9b3c-5e8f1a2b4c6d
"1"
> TTL authz:svc-jti:rms-backend:9886cc53-2a1f-4d7e-9b3c-5e8f1a2b4c6d
(integer) 112
```

Identity's own calls use principal `identity-federation`, e.g. `authz:svc-jti:identity-federation:3c8e1f4a-7b2d-4e9c-a1f5-6d0b8c2e4a7f`.

---

## 3. Application (BU) reference apps (their own Redis)

`core-authentication/examples/bu-reference-app` (RMS, AMS, VMS). Locally `redis://localhost:6391/2` (dev only; in production each application uses its own Redis).

| Key | Type | TTL | Example value (short) |
|---|---|---|---|
| `bu:<client_id>:login:<transaction_id>` | string (JSON) | 300 s; read once with `GETDEL` | `{"state":"…","display":"embed"}` |
| `bu:<client_id>:jti:assertion:<jti>` | string | until assertion `exp` + skew | `1` |
| `bu:<client_id>:jti:logout:<jti>` | string | until logout token `exp` + skew | `1` |
| `bu:<client_id>:session:<id>` | string (JSON) | `SESSION_TTL_SECONDS` (28800) | `{"its_id":"30337752","sid":"sid_…",…}` |
| `bu:<client_id>:sid:<sid>` | set | 28800 s | local session ids |
| `bu:<client_id>:authz:check:<its_id>:<module>:<permission>` | string (JSON) | 30 s | `{"allowed":true}` |
| `bu:<client_id>:authz:effective:<its_id>` | string (JSON) | 30 s | effective permissions JSON |

### 3.1 `bu:<client_id>:login:<transaction_id>`: sign-in started by this browser

```text
> GET bu:rms-web-dev:login:txn_C6BfjesJxPz4wcQa5E5vonw6
```
```json
{ "state": "gMex8oVPHAKw9MUQrCZ8KqQQZRvnOP48", "display": "embed" }
```
```text
> TTL bu:rms-web-dev:login:txn_C6BfjesJxPz4wcQa5E5vonw6
(integer) 287
```

### 3.2 `bu:<client_id>:jti:assertion:<jti>` and `…:jti:logout:<jti>`: replay markers

```text
> GET bu:rms-web-dev:jti:assertion:ca19907b-5d3e-4f1a-9c2b-7e6d8f0a1b3c
"1"
> TTL bu:rms-web-dev:jti:assertion:ca19907b-5d3e-4f1a-9c2b-7e6d8f0a1b3c
(integer) 58
> GET bu:rms-web-dev:jti:logout:7a2e9c41-0b8d-4f6e-a3c5-1d9f2b4e6a8c
"1"
```

### 3.3 `bu:<client_id>:session:<id>`: the application's own session

The encrypted `rms_session` cookie carries `lid` = this id; the request is accepted only while this key exists with the same `sid`.

```text
> TTL bu:rms-web-dev:session:Xk3pR8vN2wQ7tL5yB9cH1dF6jA0sE4gU7oI2mZ8qW5n
(integer) 28511
> GET bu:rms-web-dev:session:Xk3pR8vN2wQ7tL5yB9cH1dF6jA0sE4gU7oI2mZ8qW5n
```
```json
{
  "its_id": "30337752",
  "sid": "sid_-IajPVFnfiF9ZfIAkzk9KVTU",
  "auth_time": 1789297102,
  "created_at": "2026-09-13T11:38:22.418Z"
}
```

### 3.4 `bu:<client_id>:sid:<sid>`: back-channel logout index

```text
> SMEMBERS bu:rms-web-dev:sid:sid_-IajPVFnfiF9ZfIAkzk9KVTU
1) "Xk3pR8vN2wQ7tL5yB9cH1dF6jA0sE4gU7oI2mZ8qW5n"
```

On a valid `logout+jwt` for that `sid`, every listed session key and this set are deleted.

### 3.5 `bu:<client_id>:authz:check:<its_id>:<module>:<permission>` and `…:authz:effective:<its_id>`

```text
> GET bu:rms-web-dev:authz:check:30337752:RMS_REGISTRATION:RMS_REGISTRATION_DELETE
"{\"allowed\":true}"
> GET bu:vms-web-dev:authz:check:30337752:VMS_EVENTS:VMS_EVENTS_CREATE
"{\"allowed\":false,\"reason\":\"PERMISSION_DENIED\"}"
> GET bu:rms-web-dev:authz:check:30337752:*:RMS_REPORTS_VIEW
"{\"allowed\":true}"
> TTL bu:rms-web-dev:authz:check:30337752:RMS_REGISTRATION:RMS_REGISTRATION_DELETE
(integer) 21
```

`*` is used when the check did not name a module. `bu:<client_id>:authz:effective:<its_id>` holds the `/authorization/effective-permissions`
response for 30 s, the same shape as [2.2](#22-authzeffvversionits_idclient_id-effective-permission-cache).
If Authorization cannot be reached, the check is denied (`AUTHORIZATION_UNAVAILABLE`) and not cached.

---

## 4. Rules

Atomicity:

* Transaction creation uses `SET … NX EX`; completion is a Lua script (PENDING → COMPLETED with `KEEPTTL`), so one transaction yields at most one assertion.
* Binding a portal transaction to a session is a Lua script that refuses a different `sid`.
* Session creation, touch and revoke use `MULTI`; rate-limit check and failure counting use `MULTI`.
* Service-token and assertion replay checks use `SET … NX`.
* Authorization cache invalidation is a single `INCR authz:version` (retried up to 3 times; then `503 CACHE_INVALIDATION_FAILED`).

Every key has a TTL except `authz:version`.

Never stored in Redis: passwords, password hashes, the cookie handle itself, assertions, access tokens, authorization tokens, service tokens, private keys.
Redis does hold CSRF tokens, `state`, ITS IDs and display names, so it must stay private (TLS, AUTH, private network).
