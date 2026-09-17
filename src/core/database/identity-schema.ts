import type { DataSource, EntityManager, EntityTarget } from 'typeorm';
import {
  AuthAuditEvent,
  AuthClient,
  AuthClientCallback,
  AuthClientOrigin,
  AuthLoginAttempt,
  AuthSession,
  AuthSessionClient,
  IDENTITY_SYNCED_ENTITIES,
  SigningKeyMetadata,
} from './entities';

/**
 * What core-authentication needs from the EXISTING identity_db, and the only DDL it is allowed to run there.
 *
 * Two kinds of table live in the identity schema (miqaat_core):
 *
 *  - SYNCED tables (users, user_eligible, mumin_master) are owned by the Mumin sync service. This service
 *    only ever SELECTs from them: it never creates, alters or writes to them.
 *  - AUTH tables (auth_*, signing_key_metadata) are this service's own state. They are created here only
 *    when missing (CREATE TABLE IF NOT EXISTS). An existing table is never altered, dropped or truncated;
 *    if it lacks a column this service needs, that is reported and left for a human.
 *
 * Only these 8 tables (and their own indexes) are ever created - never a schema, database, function, trigger,
 * or any users / password / eligibility / role / permission / tenant table. Nothing is ever ALTERed or DROPped.
 * Identity comes from the synced tables; authorization lives in admin_db.
 *
 * The columns checked on every table come from the TypeORM entities themselves (src/core/database/entities), so an
 * entity and the real table can never silently disagree.
 */

export interface AuthTable {
  entity: EntityTarget<unknown>;
  /** CREATE TABLE IF NOT EXISTS for the entity's table, then its indexes. Run only when the table is missing. */
  create: string[];
}

/** Created in dependency order (auth_session_clients references auth_sessions, callbacks/origins reference auth_clients). */
export const AUTH_TABLES: AuthTable[] = [
  {
    entity: AuthSession,
    create: [
      `CREATE TABLE IF NOT EXISTS auth_sessions (
         sid                 varchar(64)  PRIMARY KEY,
         its_id              varchar(64)  NOT NULL,
         auth_method         varchar(32)  NOT NULL,
         created_at          timestamptz  NOT NULL DEFAULT now(),
         expires_at          timestamptz  NOT NULL,
         absolute_expires_at timestamptz  NOT NULL,
         last_seen_at        timestamptz,
         revoked_at          timestamptz,
         revoke_reason       varchar(64),
         ip_address          varchar(64),
         user_agent          varchar(512),
         updated_at          timestamptz  NOT NULL DEFAULT now()
       )`,
      `CREATE INDEX IF NOT EXISTS idx_auth_sessions_its ON auth_sessions (its_id, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_auth_sessions_active ON auth_sessions (its_id) WHERE revoked_at IS NULL`,
    ],
  },
  {
    entity: AuthSessionClient,
    create: [
      `CREATE TABLE IF NOT EXISTS auth_session_clients (
         id                 bigserial   PRIMARY KEY,
         sid                varchar(64) NOT NULL REFERENCES auth_sessions (sid) ON DELETE CASCADE,
         client_id          varchar(64) NOT NULL,
         first_assertion_at timestamptz NOT NULL DEFAULT now(),
         last_assertion_at  timestamptz NOT NULL DEFAULT now(),
         assertion_count    integer     NOT NULL DEFAULT 1,
         logout_status      varchar(16) CHECK (logout_status IN ('PENDING', 'SUCCEEDED', 'FAILED', 'NO_ENDPOINT')),
         logout_at          timestamptz,
         created_at         timestamptz NOT NULL DEFAULT now(),
         updated_at         timestamptz NOT NULL DEFAULT now(),
         CONSTRAINT uq_auth_session_clients_sid_client UNIQUE (sid, client_id)
       )`,
    ],
  },
  {
    entity: AuthLoginAttempt,
    create: [
      `CREATE TABLE IF NOT EXISTS auth_login_attempts (
         id              bigserial    PRIMARY KEY,
         identifier_hash char(64)     NOT NULL,
         its_id          varchar(64),
         client_id       varchar(64),
         ip_address      varchar(64),
         success         boolean      NOT NULL,
         failure_reason  varchar(64),
         correlation_id  varchar(128),
         created_at      timestamptz  NOT NULL DEFAULT now(),
         updated_at      timestamptz  NOT NULL DEFAULT now()
       )`,
      `CREATE INDEX IF NOT EXISTS idx_login_attempts_identifier ON auth_login_attempts (identifier_hash, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON auth_login_attempts (ip_address, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_login_attempts_its ON auth_login_attempts (its_id, created_at DESC)`,
    ],
  },
  {
    entity: AuthAuditEvent,
    create: [
      `CREATE TABLE IF NOT EXISTS auth_audit_events (
         id             bigserial    PRIMARY KEY,
         event_type     varchar(64)  NOT NULL,
         outcome        varchar(16)  NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'INFO')),
         its_id         varchar(64),
         sid            varchar(64),
         client_id      varchar(64),
         jti            varchar(64),
         ip_address     varchar(64),
         user_agent     varchar(512),
         correlation_id varchar(128),
         metadata       jsonb,
         created_at     timestamptz  NOT NULL DEFAULT now(),
         updated_at     timestamptz  NOT NULL DEFAULT now()
       )`,
      `CREATE INDEX IF NOT EXISTS idx_auth_audit_its ON auth_audit_events (its_id, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_auth_audit_event ON auth_audit_events (event_type, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_auth_audit_sid ON auth_audit_events (sid)`,
    ],
  },
  {
    entity: AuthClient,
    create: [
      `CREATE TABLE IF NOT EXISTS auth_clients (
         id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
         client_id           varchar(64)  NOT NULL UNIQUE CHECK (client_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
         name                varchar(255) NOT NULL,
         application_code    varchar(64)  NOT NULL,
         application_name    varchar(255) NOT NULL,
         business_unit       varchar(255),
         utility             varchar(255),
         environment         varchar(32)  NOT NULL,
         client_type         varchar(16)  NOT NULL DEFAULT 'WEB' CHECK (client_type IN ('WEB', 'SPA', 'MOBILE', 'SERVICE')),
         authentication_mode varchar(24)  NOT NULL CHECK (authentication_mode IN ('EMBEDDED', 'REDIRECT', 'EMBEDDED_OR_REDIRECT')),
         status              varchar(24)  NOT NULL DEFAULT 'PENDING'
                               CHECK (status IN ('PENDING', 'SECURITY_REVIEW', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
         initiate_login_uri  varchar(2048),
         created_at          timestamptz  NOT NULL DEFAULT now(),
         updated_at          timestamptz  NOT NULL DEFAULT now()
       )`,
    ],
  },
  {
    entity: AuthClientOrigin,
    create: [
      `CREATE TABLE IF NOT EXISTS auth_client_origins (
         id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
         client_ref uuid NOT NULL REFERENCES auth_clients (id) ON DELETE CASCADE,
         origin     varchar(512) NOT NULL CHECK (origin !~ '\\*'),
         created_at timestamptz  NOT NULL DEFAULT now(),
         CONSTRAINT uq_auth_client_origins_client_origin UNIQUE (client_ref, origin)
       )`,
      `CREATE INDEX IF NOT EXISTS idx_auth_client_origins_client ON auth_client_origins (client_ref)`,
    ],
  },
  {
    entity: AuthClientCallback,
    create: [
      `CREATE TABLE IF NOT EXISTS auth_client_callbacks (
         id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
         client_ref uuid NOT NULL REFERENCES auth_clients (id) ON DELETE CASCADE,
         uri        varchar(2048) NOT NULL CHECK (uri !~ '\\*'),
         uri_type   varchar(32)   NOT NULL CHECK (uri_type IN ('CALLBACK', 'BACK_CHANNEL_LOGOUT', 'POST_LOGOUT_REDIRECT')),
         is_primary boolean       NOT NULL DEFAULT false,
         created_at timestamptz   NOT NULL DEFAULT now(),
         CONSTRAINT uq_auth_client_callbacks_client_uri_type UNIQUE (client_ref, uri, uri_type)
       )`,
      `CREATE INDEX IF NOT EXISTS idx_auth_client_callbacks_client ON auth_client_callbacks (client_ref)`,
      `CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_client_single_backchannel ON auth_client_callbacks (client_ref) WHERE uri_type = 'BACK_CHANNEL_LOGOUT'`,
    ],
  },
  {
    entity: SigningKeyMetadata,
    create: [
      `CREATE TABLE IF NOT EXISTS signing_key_metadata (
         kid               varchar(128) PRIMARY KEY,
         alg               varchar(16)  NOT NULL,
         status            varchar(16)  NOT NULL CHECK (status IN ('NEXT', 'ACTIVE', 'RETIRING', 'RETIRED')),
         jwk_thumbprint    varchar(64),
         first_seen_at     timestamptz  NOT NULL DEFAULT now(),
         status_changed_at timestamptz  NOT NULL DEFAULT now(),
         created_at        timestamptz  NOT NULL DEFAULT now(),
         updated_at        timestamptz  NOT NULL DEFAULT now()
       )`,
    ],
  },
];

export interface IdentitySchemaReport {
  schema: string;
  schemaExists: boolean;
  /** Synced tables that are missing entirely. */
  missingSyncedTables: string[];
  /** Auth tables not present yet. */
  missingAuthTables: string[];
  /** "table.column" the service needs but an existing table lacks. Never auto-fixed. */
  missingColumns: string[];
  /** Tables in the schema whose names suggest they might already play an auth_* role under another name. */
  possibleEquivalents: string[];
}

const EQUIVALENT_HINT = /(session|audit|login_attempt|signing|jwk|client_origin|client_callback|oauth|oidc)/i;

/** Table name and column names of an entity, as TypeORM maps them. */
export function tableOf(db: DataSource, entity: EntityTarget<unknown>): { table: string; columns: string[] } {
  const metadata = db.getMetadata(entity);
  return { table: metadata.tableName, columns: metadata.columns.map((c) => c.databaseName) };
}

export async function inspectIdentitySchema(db: DataSource, schema: string): Promise<IdentitySchemaReport> {
  const [{ exists }] = (await db.query(`SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = $1) AS exists`, [schema])) as {
    exists: boolean;
  }[];
  const rows = (await db.query(
    `SELECT c.table_name, c.column_name
       FROM information_schema.columns c
       JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
      WHERE c.table_schema = $1`,
    [schema],
  )) as { table_name: string; column_name: string }[];

  const columnsByTable = new Map<string, Set<string>>();
  for (const r of rows) {
    if (!columnsByTable.has(r.table_name)) columnsByTable.set(r.table_name, new Set());
    columnsByTable.get(r.table_name)!.add(r.column_name);
  }

  const missingColumns: string[] = [];
  const checkEntity = (entity: EntityTarget<unknown>) => {
    const { table, columns } = tableOf(db, entity);
    const present = columnsByTable.get(table);
    if (!present) return false;
    for (const column of columns) if (!present.has(column)) missingColumns.push(`${table}.${column}`);
    return true;
  };

  const missingSyncedTables = IDENTITY_SYNCED_ENTITIES.filter((e) => !checkEntity(e)).map((e) => tableOf(db, e).table);
  const missingAuthTables = AUTH_TABLES.filter((t) => !checkEntity(t.entity)).map((t) => tableOf(db, t.entity).table);

  const known = new Set([...IDENTITY_SYNCED_ENTITIES, ...AUTH_TABLES.map((t) => t.entity)].map((e) => tableOf(db, e).table));
  const possibleEquivalents = [...columnsByTable.keys()].filter((t) => !known.has(t) && EQUIVALENT_HINT.test(t)).sort();

  return { schema, schemaExists: exists, missingSyncedTables, missingAuthTables, missingColumns, possibleEquivalents };
}

/**
 * Creates the auth tables that do not exist yet, in one transaction. Existing tables are left exactly as
 * they are. Refuses to run when the schema or the synced tables are missing - that means the connection
 * points at the wrong database, and creating auth tables there would be wrong too.
 */
export async function ensureAuthTables(
  db: DataSource,
  schema: string,
): Promise<{ created: string[]; report: IdentitySchemaReport }> {
  const before = await inspectIdentitySchema(db, schema);
  if (!before.schemaExists) throw new Error(`schema "${schema}" does not exist in this database; refusing to create anything`);
  if (before.missingSyncedTables.length) {
    throw new Error(`synced tables missing from "${schema}": ${before.missingSyncedTables.join(', ')}; is IDENTITY_DB_* pointing at identity_db?`);
  }

  const toCreate = AUTH_TABLES.filter((t) => before.missingAuthTables.includes(tableOf(db, t.entity).table));
  if (toCreate.length === 0) return { created: [], report: before };

  await db.transaction(async (tx: EntityManager) => {
    // Unqualified names below must land in the identity schema, whatever the caller's search_path is.
    await tx.query(`SELECT set_config('search_path', $1, true)`, [schema]);

    for (const table of toCreate) {
      for (const statement of table.create) await tx.query(statement);
    }
  });

  return { created: toCreate.map((t) => tableOf(db, t.entity).table), report: await inspectIdentitySchema(db, schema) };
}
