# Deploying to the Miqaat Core DEV server (3.7.149.74)

What runs there: **core-authentication** (3001) and **core-authorization** (3002).
`core-embed-login` is an npm/React SDK, not a service — it is consumed by BU apps, not deployed here.

Both services attach to the existing `dev_miqaat_core_net` and use the shared infrastructure
from the connection handover. They start **no** Postgres and **no** Redis of their own.

| Service | PostgreSQL | Redis DB index |
|---|---|---|
| core-authentication | `dev_miqaat_core_rds1` / `miqaat_core_rds1` | `1` |
| core-authorization | `dev_miqaat_core_rds2` / `miqaat_core_rds2` | `2` |

They are on **different clusters on purpose**: both create their tables in `public` and both
use a `schema_migrations` table, so one database cannot hold both. The handover says the
cluster choice is Miqaat Core's to make — if they assign differently, it is one line in each
`.env.dev-server`, nothing else changes.

## Files

| File | Purpose |
|---|---|
| `core-*/docker/docker-compose.dev-server.yml` | dev-server topology: app + one-shot migration, on the external network |
| `core-*/.env.dev-server` | live credentials, gitignored — **not** in the repo, ship it out of band |
| `core-*/docker/docker-compose.yml` | unchanged; still the *local laptop* stack with its own PG/Redis/LocalStack |

## Deploy

```bash
# 0. The Miqaat Core stack owns the network and must be up first.
cd /opt/miqaat-core-network && docker compose up -d

# 1. authentication (build, migrate, run)
cd /srv/core-authentication
docker compose -f docker/docker-compose.dev-server.yml --env-file .env.dev-server up -d --build

# 2. authorization
cd /srv/core-authorization
docker compose -f docker/docker-compose.dev-server.yml --env-file .env.dev-server up -d --build
```

The `*-migrate` container runs TypeORM migrations and exits 0; the app container waits on
`service_completed_successfully`, so a failed migration stops the deploy instead of booting an
app against a half-built schema. Migrations run from `dist/`, so no ts-node is needed in the image.

## Seed

```bash
# authorization (run from the checkout, in core-authorization/)
ENV_FILE=.env.dev-server npm run seed
ENV_FILE=.env.dev-server npm run principal:register   # trusts authn's service tokens
ENV_FILE=.env.dev-server npm run seed:miqaat-core-demo
ENV_FILE=.env.dev-server npm run onboard

# authentication (in core-authentication/) - the client registry lives in AUTHN's DB, not authz's
ENV_FILE=.env.dev-server npm run seed:clients
ENV_FILE=.env.dev-server npm run seed:dev-users
```

The seed scripts are ts-node and are **not** in the runtime image (devDependencies are pruned).
Run them from a checkout on the server that is itself on `dev_miqaat_core_net` — or temporarily
point a checkout at the cluster from a container: `docker run --rm --network dev_miqaat_core_net …`.
Running them from your laptop will not work: the databases publish no host ports and are not
reachable from outside the network.

## Verify

```bash
curl -s localhost:3001/health && curl -s localhost:3002/health
curl -s localhost:3001/.well-known/jwks.json | head -c 200

# DB reachability, without involving the apps
docker run --rm --network dev_miqaat_core_net -e PGPASSWORD='<rds1-pw>' postgres:16.10-alpine \
  psql -h dev_miqaat_core_rds1 -U miqaat_rds1 -d miqaat_core_rds1 -c '\dt'

# Redis: confirm nothing else is squatting on our index
docker run --rm --network dev_miqaat_core_net redis:7-alpine \
  redis-cli --no-auth-warning -h dev_miqaat_core_redis -a '<redis-pw>' -n 1 --scan --pattern 'federation:*' | head
```

## Things that will bite you

1. **Redis is a shared LRU cache with one password and no ACLs.** `maxmemory 256mb` +
   `allkeys-lru` means another project's traffic can evict *our* keys. For authn that is not a
   cache miss — `federation:session:*`, `federation:txn:*` and `ratelimit:login:*` live there, so
   eviction logs users out mid-flow and silently resets brute-force counters. Separate DB indexes
   (1 and 2) stop key collisions but **not** eviction: `allkeys-lru` ignores DB boundaries. Ask
   Miqaat Core for per-project ACL users and, for authn, either its own Redis or a raised
   `maxmemory` with `volatile-lru`.
2. **The DB accounts are cluster owners.** `miqaat_rds1` / `miqaat_rds2` can drop schemas and read
   every other project's tables. Fine for first-week integration, wrong after that — request a
   scoped `<project>_app` role (section 7 of the handover) and swap `*_DB_USER`/`*_DB_PASSWORD`.
3. **Embed origins must be https.** `uri-policy.ts` accepts `http://` only for `localhost`, so
   `http://3.7.149.74:5175` cannot be registered as a BU client origin — it fails `INVALID_ORIGIN`.
   A real embed test on this box needs a hostname with TLS in front.
4. **Cookies.** `COOKIE_SECURE=false` / `SameSite=Lax` is set because plain http on an IP drops a
   `Secure; SameSite=None` cookie. The cross-origin iframe flow needs `None`+`Secure` — flip both
   once TLS is in place, and set `TRUST_PROXY=1` at the same time so session IP binding sees the
   real client instead of the proxy.
5. **`NODE_ENV=development` is deliberate**, not a leftover: `SIGNING_KEY_PROVIDER=file` is refused
   under `production`, and there is no Secrets Manager on this box. The keyset lives in the
   `authn-keys` volume — **do not** `docker compose down -v`, and never in `/opt/miqaat-core-network`
   (that destroys every database volume).
6. **Legacy password login stays off here.** MMS (20.0.10.201) is not reachable from Lightsail and
   `legacy-decrypt` refuses to boot without it, so Embedded Login verifies scrypt hashes. The MHP
   eligibility gate still applies, from the mirrored `users.mhp_*` columns.

## What the migrations create

Verified by running both migration sets against empty PostgreSQL 16 databases.

**core-authentication → `dev_miqaat_core_rds1` / `miqaat_core_rds1`, schema `public` (10 tables)**

```
users                     accounts, scrypt password_hash, mirrored mhp_* eligibility flags
auth_sessions             federation sessions
auth_session_clients      which BU clients participated in a session (back-channel logout)
auth_login_attempts       per-attempt log; failure_reason carries the MHP_* gate reasons
auth_audit_events         authentication audit trail
auth_clients              BU client registry (lives HERE, not in authorization)
auth_client_origins       allowed embed origins per client
auth_client_callbacks     callback / post-logout / back-channel URIs
signing_key_metadata      RS256 keyset metadata (kid, state) - never the private key
schema_migrations         TypeORM migration ledger
```

**core-authorization → `dev_miqaat_core_rds2` / `miqaat_core_rds2`, TWO schemas (27 tables)**

`public` (18) — catalog, client registry and audit:

```
tenants  business_units  utilities  environments  applications  modules
permissions  roles  role_permissions  users  user_roles
clients  client_origins  client_redirect_uris  client_status_history
service_principals        service-to-service identities (replaced the old api_clients)
authorization_audit_logs  every decision; denials always, allows per AUDIT_ALLOW_DECISIONS
schema_migrations
```

`miqaat_core` (9) — the Core RBAC model the browser session endpoints actually read:

```
users  tenants  roles  role_permissions  user_roles
modules  permission_actions  module_actions
user_sessions             miqaat_session records
```

Note `public.users`/`roles`/`user_roles` and `miqaat_core.users`/`roles`/`user_roles` are
**different tables**. Permission checks on a browser session read `miqaat_core`; reading `public`
by mistake is the classic phantom-403.

This is also the concrete reason the two services cannot share one database: each creates its own
`public.users` and its own `schema_migrations`.
