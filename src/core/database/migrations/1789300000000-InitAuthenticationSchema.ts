import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Authentication DB schema (Identity Federation only).
 *
 * This is the ONLY place end-user credentials live (as scrypt hashes). Roles, permissions and
 * application access are intentionally absent - they belong to the Authorization DB.
 * Signing private keys are NOT stored here (see AWS SSM); only non-secret key metadata is.
 */
export class InitAuthenticationSchema1789300000000 implements MigrationInterface {
  name = 'InitAuthenticationSchema1789300000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE auth_users (
        id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        its_id               varchar(64)  NOT NULL UNIQUE CHECK (its_id ~ '^[A-Za-z0-9._-]{1,64}$'),
        identity_type        varchar(16)  NOT NULL DEFAULT 'ITS' CHECK (identity_type IN ('ITS', 'NON_ITS')),
        username             varchar(256) NOT NULL UNIQUE CHECK (username = lower(username)),
        display_name         varchar(256),
        password_hash        text,
        password_algo        varchar(32),
        credential_source    varchar(32)  NOT NULL DEFAULT 'LOCAL'
                               CHECK (credential_source IN ('LOCAL', 'LEGACY_MHP_MIGRATED', 'EXTERNAL')),
        legacy_user_id       integer,
        account_status       varchar(16)  NOT NULL DEFAULT 'ACTIVE' CHECK (account_status IN ('ACTIVE', 'LOCKED', 'DISABLED')),
        failed_login_count   integer      NOT NULL DEFAULT 0,
        locked_until         timestamptz,
        last_login_at        timestamptz,
        last_failed_login_at timestamptz,
        password_changed_at  timestamptz,
        mfa_enabled          boolean      NOT NULL DEFAULT false,
        created_at           timestamptz  NOT NULL DEFAULT now(),
        updated_at           timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE UNIQUE INDEX uq_auth_users_legacy ON auth_users (legacy_user_id) WHERE legacy_user_id IS NOT NULL`);

    await q.query(`
      CREATE TABLE auth_mfa_factors (
        id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id      uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        factor_type  varchar(16)  NOT NULL CHECK (factor_type IN ('TOTP', 'SMS', 'EMAIL', 'WEBAUTHN')),
        secret_ref   varchar(512),
        status       varchar(16)  NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED')),
        created_at   timestamptz  NOT NULL DEFAULT now(),
        last_used_at timestamptz
      )`);

    await q.query(`
      CREATE TABLE auth_sessions (
        sid                 varchar(64)  PRIMARY KEY,
        user_id             uuid         NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
        its_id              varchar(64)  NOT NULL,
        auth_method         varchar(32)  NOT NULL,
        created_at          timestamptz  NOT NULL DEFAULT now(),
        expires_at          timestamptz  NOT NULL,
        absolute_expires_at timestamptz  NOT NULL,
        last_seen_at        timestamptz,
        revoked_at          timestamptz,
        revoke_reason       varchar(64),
        ip_address          varchar(64),
        user_agent          varchar(512)
      )`);
    await q.query(`CREATE INDEX idx_auth_sessions_its ON auth_sessions (its_id, created_at DESC)`);
    await q.query(`CREATE INDEX idx_auth_sessions_active ON auth_sessions (user_id) WHERE revoked_at IS NULL`);

    await q.query(`
      CREATE TABLE auth_session_clients (
        id                 bigserial PRIMARY KEY,
        sid                varchar(64) NOT NULL REFERENCES auth_sessions(sid) ON DELETE CASCADE,
        client_id          varchar(64) NOT NULL,
        first_assertion_at timestamptz NOT NULL DEFAULT now(),
        last_assertion_at  timestamptz NOT NULL DEFAULT now(),
        assertion_count    integer     NOT NULL DEFAULT 1,
        logout_status      varchar(16) CHECK (logout_status IN ('PENDING', 'SUCCEEDED', 'FAILED', 'NO_ENDPOINT')),
        logout_at          timestamptz,
        UNIQUE (sid, client_id)
      )`);

    await q.query(`
      CREATE TABLE auth_login_attempts (
        id              bigserial PRIMARY KEY,
        identifier_hash char(64)    NOT NULL,
        user_id         uuid,
        client_id       varchar(64),
        ip_address      varchar(64),
        success         boolean     NOT NULL,
        failure_reason  varchar(64),
        correlation_id  varchar(128),
        created_at      timestamptz NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX idx_login_attempts_identifier ON auth_login_attempts (identifier_hash, created_at DESC)`);
    await q.query(`CREATE INDEX idx_login_attempts_ip ON auth_login_attempts (ip_address, created_at DESC)`);

    await q.query(`
      CREATE TABLE auth_audit_events (
        id             bigserial PRIMARY KEY,
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
        created_at     timestamptz  NOT NULL DEFAULT now()
      )`);
    await q.query(`CREATE INDEX idx_auth_audit_its ON auth_audit_events (its_id, created_at DESC)`);
    await q.query(`CREATE INDEX idx_auth_audit_event ON auth_audit_events (event_type, created_at DESC)`);
    await q.query(`CREATE INDEX idx_auth_audit_sid ON auth_audit_events (sid)`);

    await q.query(`
      CREATE TABLE signing_key_metadata (
        kid               varchar(128) PRIMARY KEY,
        alg               varchar(16)  NOT NULL,
        status            varchar(16)  NOT NULL CHECK (status IN ('NEXT', 'ACTIVE', 'RETIRING', 'RETIRED')),
        jwk_thumbprint    varchar(64),
        first_seen_at     timestamptz  NOT NULL DEFAULT now(),
        status_changed_at timestamptz  NOT NULL DEFAULT now()
      )`);
  }

  public async down(q: QueryRunner): Promise<void> {
    for (const table of ['signing_key_metadata', 'auth_audit_events', 'auth_login_attempts', 'auth_session_clients', 'auth_sessions', 'auth_mfa_factors', 'auth_users']) {
      await q.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
    }
  }
}
