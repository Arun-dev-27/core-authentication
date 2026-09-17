import 'reflect-metadata';
import { parseArgs } from 'node:util';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { buildDataSourceOptions } from '@core/database/data-source-options';
import { createStandaloneAuthzClient } from '@modules/authorization-client/standalone-authz-client';
import { decrypt } from '@modules/credentials/services/legacy-decrypt';
import { PasswordHasher } from '@modules/credentials/services/password-hasher';
import { UserProfileSync } from '@shared/types/federation-client.types';
import { LEGACY_ENTITIES } from './legacy/legacy.entities';

/**
 * One-off migration: legacy MMS (SQL Server, READ-ONLY) -> Authentication DB, profile -> Authorization service.
 *
 *   npm run migrate:legacy                          # LEGACY_MIGRATION_LIMIT users (default 50)
 *   npm run migrate:legacy -- --limit 50 --include 30337752 --dry-run
 *   npm run migrate:legacy -- --skip-authz-sync
 *
 * Selection (deterministic): Allow_Login = 1, present in MHP_User_Login_Eligible, non-null password;
 * users listed in --include first, then ascending UserId.
 *
 * Per user:
 *  1. decrypt legacy password with the validated C# port   (plaintext kept only in memory)
 *  2. scrypt-hash it                                        -> users.password_hash (Authentication DB)
 *  3. POST profile (ITS ID, name, email, mobile) to Authorization service /users/sync  (NO credential data)
 *  4. mirror the Embedded Login gate onto the row: mhp_eligible (true by construction - every
 *     selected row came through the MHP_User_Login_Eligible join), mhp_status_id
 *     (mumin_mast_Cal_grades.Status_ID), mhp_allow_login, mhp_synced_at.
 *     The password ciphertext is deliberately NOT mirrored; it is reversible by design.
 *
 * Idempotent: re-running updates profile/status and only re-hashes when the legacy password changed.
 * Plaintext passwords, legacy ciphertext and hashes are never logged.
 */

interface LegacyRow {
  UserId: number;
  Password: string | null;
  Allow_Login: boolean | null;
  /** mumin_mast_Cal_grades.Status_ID; 3 = active. Null when the person row is absent. */
  Status_ID: number | null;
  Fullname: string | null;
  email: string | null;
  mobile_no: string | null;
}

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const MOBILE = /^[+0-9 ()-]{5,32}$/;

async function main() {
  loadEnvFiles();
  const env = loadEnv();
  const { values } = parseArgs({
    options: {
      limit: { type: 'string' },
      include: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      'skip-authz-sync': { type: 'boolean', default: false },
    },
  });
  const limit = Number(values.limit ?? process.env.LEGACY_MIGRATION_LIMIT ?? 50);
  if (!Number.isInteger(limit) || limit < 1 || limit > 5000) throw new Error('--limit must be 1..5000');
  const include = (values.include ?? process.env.LEGACY_INCLUDE_USER_IDS ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean)
    .map(Number);
  if (include.some((n) => !Number.isInteger(n))) throw new Error('--include must be comma-separated integer UserIds');

  for (const name of ['LEGACY_DB_HOST', 'LEGACY_DB_USER', 'LEGACY_DB_PASSWORD']) {
    if (!process.env[name]) throw new Error(`${name} is required`);
  }

  const legacy = new DataSource({
    type: 'mssql',
    host: process.env.LEGACY_DB_HOST,
    port: Number(process.env.LEGACY_DB_PORT ?? 1433),
    username: process.env.LEGACY_DB_USER,
    password: process.env.LEGACY_DB_PASSWORD,
    database: process.env.LEGACY_DB_NAME ?? 'MMS',
    entities: LEGACY_ENTITIES,
    synchronize: false,
    options: { encrypt: process.env.LEGACY_DB_ENCRYPT === 'true', trustServerCertificate: true, readOnlyIntent: true },
    requestTimeout: 120_000,
  });
  const auth = new DataSource(buildDataSourceOptions(env));
  const hasher = new PasswordHasher();
  const authz = (await createStandaloneAuthzClient(env));

  await legacy.initialize();
  await auth.initialize();
  console.log(`legacy: connected (read-only intent) | auth db: ${env.AUTH_DB_NAME} | limit ${limit} | include [${include.join(', ')}]${values['dry-run'] ? ' | DRY RUN' : ''}`);

  // Parameter placeholders for the include list: @1..@n (TOP uses @0).
  const includeParams = include.map((_, i) => `@${i + 1}`).join(', ');
  const rows = (await legacy.query(
    `SELECT TOP (@0) l.UserId, l.Password, l.Allow_Login, g.Status_ID, g.Fullname, g.email, g.mobile_no
       FROM MHP_User_Login l
       JOIN MHP_User_Login_Eligible e ON e.Mumin_ID = l.UserId
       OUTER APPLY (SELECT TOP 1 m.Status_ID, m.Fullname, m.email, m.mobile_no FROM mumin_mast_Cal_grades m WHERE m.Mumin_ID = l.UserId) g
      WHERE l.Allow_Login = 1 AND l.Password IS NOT NULL
      GROUP BY l.UserId, l.Password, l.Allow_Login, g.Status_ID, g.Fullname, g.email, g.mobile_no
      ORDER BY CASE WHEN ${include.length ? `l.UserId IN (${includeParams})` : '1 = 0'} THEN 0 ELSE 1 END, l.UserId`,
    [limit, ...include],
  )) as LegacyRow[];

  const summary = { selected: rows.length, created: 0, updated: 0, rehashed: 0, skipped: 0, synced: 0, syncFailed: 0 };
  const skippedReasons: Record<string, number> = {};

  for (const row of rows) {
    const itsId = String(row.UserId);
    const plaintext = decrypt(row.Password);
    if (!plaintext) {
      summary.skipped++;
      skippedReasons.UNDECRYPTABLE_PASSWORD = (skippedReasons.UNDECRYPTABLE_PASSWORD ?? 0) + 1;
      continue;
    }
    const displayName = row.Fullname?.trim() || null;
    const status = row.Allow_Login ? 'ACTIVE' : 'DISABLED';
    const rawEmail = row.email?.trim().toLowerCase();
    const email = rawEmail && EMAIL.test(rawEmail) ? rawEmail : null;

    if (!values['dry-run']) {
      // Authentication DB `users` (ITS ID primary key) holds the scrypt password_hash.
      const existing = (await auth.query(`SELECT its_id, password_hash FROM users WHERE its_id = $1`, [itsId])) as { its_id: string; password_hash: string | null }[];
      if (existing[0]) {
        const unchanged = await hasher.verify(plaintext, existing[0].password_hash);
        const hash = unchanged ? existing[0].password_hash : await hasher.hash(plaintext);
        await auth.query(
          `UPDATE users SET name = $2, email = COALESCE($7, email), status = $3, password_hash = $4, password_algo = 'scrypt',
                  password_changed_at = CASE WHEN $5 THEN password_changed_at ELSE now() END, legacy_user_id = $6,
                  mhp_eligible = true, mhp_status_id = $8, mhp_allow_login = $9, mhp_synced_at = now()
            WHERE its_id = $1`,
          [itsId, displayName, status, hash, unchanged, row.UserId, email, row.Status_ID, row.Allow_Login ?? false],
        );
        summary.updated++;
        if (!unchanged) summary.rehashed++;
      } else {
        await auth.query(
          `INSERT INTO users (its_id, identity_type, username, name, email, password_hash, password_algo, credential_source, legacy_user_id, status, password_changed_at,
                              mhp_eligible, mhp_status_id, mhp_allow_login, mhp_synced_at)
           VALUES ($1, 'ITS', $1, $2, $3, $4, 'scrypt', 'LEGACY_MHP_MIGRATED', $5, $6, now(),
                   true, $7, $8, now())`,
          [itsId, displayName, email, await hasher.hash(plaintext), row.UserId, status, row.Status_ID, row.Allow_Login ?? false],
        );
        summary.created++;
      }
      await auth.query(
        `INSERT INTO auth_audit_events (event_type, outcome, its_id, metadata) VALUES ('LEGACY_USER_MIGRATED', 'SUCCESS', $1, $2)`,
        [itsId, JSON.stringify({ source: 'MMS.MHP_User_Login', status })],
      );

      if (!values['skip-authz-sync']) {
        const profile: UserProfileSync = {
          its_id: itsId,
          status: status === 'ACTIVE' ? 'active' : 'inactive',
          ...(displayName ? { name: displayName.slice(0, 256) } : {}),
          ...(email ? { email } : {}),
        };
        try {
          await authz.syncUser(profile);
          summary.synced++;
        } catch {
          summary.syncFailed++;
        }
      }
    }
  }

  console.log('legacy migration summary', summary, Object.keys(skippedReasons).length ? { skippedReasons } : '');
  if (summary.syncFailed > 0) console.log('Some profiles were not synced to the Authorization service; start it and re-run (idempotent).');
  await legacy.destroy();
  await auth.destroy();
}

main().catch((error: unknown) => {
  console.error('legacy migration failed:', error instanceof Error ? error.message : error);
  process.exit(1);
});
