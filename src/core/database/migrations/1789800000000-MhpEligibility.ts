import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Mirrors the legacy MMS eligibility gate into the Authentication DB so the Embedded Login flow can
 * enforce it without reaching SQL Server on every attempt (MMS is on-prem and is not reachable from
 * every environment this service runs in).
 *
 * Source of each column, as read by `npm run migrate:legacy`:
 *   mhp_eligible    row exists in  MHP_User_Login_Eligible  (joined on Mumin_ID = MHP_User_Login.UserId)
 *   mhp_status_id   mumin_mast_Cal_grades.Status_ID         (3 = active)
 *   mhp_allow_login MHP_User_Login.Allow_Login
 *   mhp_synced_at   when the three above were last refreshed from MMS
 *
 * Deliberately NOT mirrored: MHP_User_Login.Password. It is reversible by design (see
 * legacy-decrypt.ts), so copying the ciphertext here would be strictly weaker than the scrypt hash
 * already in password_hash. The decrypt-and-compare path therefore reads MMS directly, and only
 * where it is configured and enabled.
 *
 * Defaults are chosen to fail closed: an existing row is `mhp_eligible = false` until a sync says
 * otherwise, so enabling the gate cannot silently admit an unverified account.
 */
export class MhpEligibility1789800000000 implements MigrationInterface {
  name = 'MhpEligibility1789800000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`ALTER TABLE users ADD COLUMN mhp_eligible boolean NOT NULL DEFAULT false`);
    await q.query(`ALTER TABLE users ADD COLUMN mhp_status_id integer`);
    await q.query(`ALTER TABLE users ADD COLUMN mhp_allow_login boolean`);
    await q.query(`ALTER TABLE users ADD COLUMN mhp_synced_at timestamptz`);

    await q.query(`
      COMMENT ON COLUMN users.mhp_eligible IS
        'Mirror of MHP_User_Login_Eligible membership. false until a legacy sync proves otherwise.'`);
    await q.query(`COMMENT ON COLUMN users.mhp_status_id IS 'Mirror of mumin_mast_Cal_grades.Status_ID; 3 = active.'`);
    await q.query(`COMMENT ON COLUMN users.mhp_allow_login IS 'Mirror of MHP_User_Login.Allow_Login.'`);
    await q.query(`COMMENT ON COLUMN users.mhp_synced_at IS 'When the mhp_* columns were last refreshed from MMS.'`);

    // The gate reads these together with the account row, so a partial index on the passing
    // combination keeps the common lookup cheap without indexing every rejected account.
    await q.query(`
      CREATE INDEX idx_users_mhp_eligible ON users (its_id)
        WHERE mhp_eligible AND mhp_allow_login`);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP INDEX IF EXISTS idx_users_mhp_eligible`);
    await q.query(`ALTER TABLE users DROP COLUMN IF EXISTS mhp_synced_at`);
    await q.query(`ALTER TABLE users DROP COLUMN IF EXISTS mhp_allow_login`);
    await q.query(`ALTER TABLE users DROP COLUMN IF EXISTS mhp_status_id`);
    await q.query(`ALTER TABLE users DROP COLUMN IF EXISTS mhp_eligible`);
  }
}
