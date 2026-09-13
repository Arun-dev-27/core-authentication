# Redis key design

## Identity Federation (`REDIS_URL`, ElastiCache A)

| Key | Type | Value | TTL | Written by |
|---|---|---|---|---|
| `federation:txn:<transaction_id>` | string | JSON `{transaction_id, client_id, state, display, embed_origin, callback_uri, csrf, sid?, status, created_at, expires_at}` | `TRANSACTION_TTL_SECONDS` (300); a portal transaction bound to a session (`sid`) is extended to that session's remaining absolute lifetime | `GET /embed/login`, `POST /auth/transaction`, `/portal`, portal `/login` + `/select-scope` (binding) |
| `federation:session:<sid>` | string | JSON `{sid, its_id, identity_type, display_name, auth_method, auth_time, created_at, expires_at, absolute_expires_at, is_active, handle_hash}` | sliding idle (1800) capped by absolute (28800) | login, SSO continue |
| `federation:session-handle:<sha256(handle)>` | string | `sid` | same as session | login |
| `federation:user-sessions:<its_id>` | set | sids | absolute TTL | login |
| `federation:session-clients:<sid>` | set | client_ids that received assertions | session TTL | assertion issuance |
| `federation:jti:<jti>` | string | `client_id|sid` (traceability, no token) | `ASSERTION_TTL_SECONDS` | assertion issuance |
| `federation:client-cfg:<client_id>` | string | client config JSON or `__NOT_FOUND__` | 30 s (10 s negative) | client registry |
| `ratelimit:login:ip:<ip>` | counter | attempts | `LOGIN_IP_WINDOW_SECONDS` | every login attempt |
| `ratelimit:login:id:<sha256(type:identifier)>` | counter | failures | `LOGIN_IDENTIFIER_WINDOW_SECONDS` | failed logins |

Atomicity:
* Transaction creation uses `SET … NX EX`; completion is a Lua script (PENDING → COMPLETED with `KEEPTTL`), so one transaction yields at most one assertion.
* Session creation/touch/revoke use `MULTI`.

Never stored in Redis: passwords, password hashes, the cookie handle itself, assertions, private keys.

## Authorization Service (ElastiCache B)

| Key | Type | Value | TTL |
|---|---|---|---|
| `authz:version` | counter | incremented on every model/client/user change | none |
| `authz:eff:v<version>:<its_id>:<client_id>` | string | effective access JSON (including denial reason) | `EFFECTIVE_PERMISSION_CACHE_TTL_SECONDS` (60) |

## BU reference application (its own Redis)

| Key | Value | TTL |
|---|---|---|
| `bu:<client_id>:login:<transaction_id>` | `{state, display}` (single use via `GETDEL`) | 300 |
| `bu:<client_id>:jti:assertion:<jti>` / `…:logout:<jti>` | replay marker (`SET NX`) | until `exp` + skew |
| `bu:<client_id>:session:<id>` | local session `{its_id, sid, auth_time, created_at}` | 8 h |
| `bu:<client_id>:sid:<sid>` | set of local session ids (back-channel logout index) | 8 h |
| `bu:<client_id>:authz:check:<its>:<module>:<permission>` | decision | 30 s |
