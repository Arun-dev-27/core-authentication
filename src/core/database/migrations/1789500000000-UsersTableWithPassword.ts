import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Authentication DB aligned with the Core RBAC user model:
 *  - auth_users becomes `users`, keyed by ITS ID (no separate UUID), with name, email and the scrypt `password_hash`
 *  - dependent tables reference users(its_id)
 *  - created_at + updated_at on every table (updated_at maintained by trigger)
 *
 * Passwords live only here. The Authorization DB `users` table carries the same its_id and profile, never credentials.
 */
export class UsersTableWithPassword1789500000000 implements MigrationInterface {
  name = 'UsersTableWithPassword1789500000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        NEW.updated_at = now();
        RETURN NEW;
      END $$`);

    await q.query(`ALTER TABLE auth_users RENAME TO users`);
    await q.query(`ALTER TABLE users RENAME COLUMN display_name TO name`);
    await q.query(`ALTER TABLE users RENAME COLUMN account_status TO status`);
    await q.query(`ALTER TABLE users ADD COLUMN email varchar(256)`);
    await q.query(`COMMENT ON COLUMN users.password_hash IS 'scrypt$ln=..,r=..,p=..$salt$hash - never plaintext'`);

    // Re-key dependents from users.id (uuid) to users.its_id.
    await q.query(`ALTER TABLE auth_sessions DROP COLUMN user_id`);
    await q.query(`ALTER TABLE auth_mfa_factors ADD COLUMN its_id varchar(64)`);
    await q.query(`UPDATE auth_mfa_factors f SET its_id = u.its_id FROM users u WHERE u.id = f.user_id`);
    await q.query(`ALTER TABLE auth_mfa_factors DROP COLUMN user_id`);
    await q.query(`ALTER TABLE auth_mfa_factors ALTER COLUMN its_id SET NOT NULL`);
    await q.query(`ALTER TABLE auth_login_attempts ADD COLUMN its_id varchar(64)`);
    await q.query(`UPDATE auth_login_attempts a SET its_id = u.its_id FROM users u WHERE u.id = a.user_id`);
    await q.query(`ALTER TABLE auth_login_attempts DROP COLUMN user_id`);

    await q.query(`ALTER TABLE users DROP CONSTRAINT auth_users_pkey`);
    await q.query(`ALTER TABLE users DROP COLUMN id`);
    await q.query(`ALTER TABLE users DROP CONSTRAINT auth_users_its_id_key`);
    await q.query(`ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY (its_id)`);

    await q.query(`ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_its_id_fkey FOREIGN KEY (its_id) REFERENCES users(its_id) ON DELETE CASCADE`);
    await q.query(`CREATE INDEX idx_auth_sessions_active ON auth_sessions (its_id) WHERE revoked_at IS NULL`);
    await q.query(`ALTER TABLE auth_mfa_factors ADD CONSTRAINT auth_mfa_factors_its_id_fkey FOREIGN KEY (its_id) REFERENCES users(its_id) ON DELETE CASCADE`);
    await q.query(`CREATE INDEX idx_login_attempts_its ON auth_login_attempts (its_id, created_at DESC)`);

    await q.query(`ALTER TABLE auth_sessions ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE auth_session_clients ADD COLUMN created_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE auth_session_clients ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE auth_login_attempts ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE auth_audit_events ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE auth_mfa_factors ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE signing_key_metadata ADD COLUMN created_at timestamptz NOT NULL DEFAULT now()`);
    await q.query(`ALTER TABLE signing_key_metadata ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`);

    for (const table of ['users', 'auth_sessions', 'auth_session_clients', 'auth_login_attempts', 'auth_audit_events', 'auth_mfa_factors', 'signing_key_metadata']) {
      await q.query(`CREATE TRIGGER trg_${table}_updated_at BEFORE UPDATE ON ${table} FOR EACH ROW EXECUTE FUNCTION set_updated_at()`);
    }
  }

  public async down(): Promise<void> {
    throw new Error('UsersTableWithPassword1789500000000 re-keys users by ITS ID and cannot be reverted automatically; restore from backup.');
  }
}
