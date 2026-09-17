import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import dataSource from '@core/database/data-source';
import { createStandaloneAuthzClient } from '@modules/authorization-client/standalone-authz-client';
import { PasswordHasher } from '@modules/credentials/services/password-hasher';

/**
 * DEV ONLY: demo accounts in the Authentication DB `users` table (scrypt password_hash) + profile sync.
 *
 *  - the Role & Permission Module demo ITS IDs that do not exist in MMS (31189012, 31145678, 31267890, 31278901),
 *    password from DEV_DEMO_PASSWORD. 30416234 exists in MMS and is migrated with its legacy password instead.
 *  - a Non-ITS member (DEV_NON_ITS_USERNAME / DEV_NON_ITS_PASSWORD)
 *
 * Credentials come only from .env; nothing is hardcoded. Legacy-migrated accounts are never overwritten.
 *   npm run seed:dev-users
 */
const DEMO_USERS: { itsId: string; name: string }[] = [
  { itsId: '31189012', name: 'Burhan' },
  { itsId: '31145678', name: 'BU Sub-Level Admin (demo)' },
  { itsId: '31267890', name: 'Murtaza Saifuddin' },
  { itsId: '31278901', name: 'Utility Sub-Level Admin (demo)' },
];

async function main() {
  loadEnvFiles();
  const env = loadEnv();
  if (env.NODE_ENV === 'production') throw new Error('refusing to seed demo users in production');
  const demoPassword = process.env.DEV_DEMO_PASSWORD;
  const username = process.env.DEV_NON_ITS_USERNAME?.trim().toLowerCase();
  const nonItsPassword = process.env.DEV_NON_ITS_PASSWORD;
  if (!demoPassword) throw new Error('DEV_DEMO_PASSWORD is required');

  await dataSource.initialize();
  const hasher = new PasswordHasher();
  const authz = await createStandaloneAuthzClient(env);
  const synced: string[] = [];
  const sync = async (profile: { its_id: string; name: string; email?: string }) => {
    await authz
      .syncUser({ ...profile, status: 'active' })
      .then(() => synced.push(profile.its_id))
      .catch(() => console.log(`authorization service unreachable for ${profile.its_id}; re-run after starting it`));
  };

  let demo = 0;
  for (const user of DEMO_USERS) {
    const rows = (await dataSource.query(
      // mhp_* is mirrored as a passing gate: these are LOCAL demo accounts with no MHP row, and
      // the Embedded Login gate applies to every client login, so without this the demo personas
      // would all be refused. Only ever applied to credential_source = 'LOCAL' rows.
      `INSERT INTO users (its_id, identity_type, username, name, password_hash, password_algo, credential_source, status, password_changed_at,
                          mhp_eligible, mhp_status_id, mhp_allow_login, mhp_synced_at)
       VALUES ($1, 'ITS', $1, $2, $3, 'scrypt', 'LOCAL', 'ACTIVE', now(),
               true, $4, true, now())
       ON CONFLICT (its_id) DO UPDATE SET name = EXCLUDED.name, password_hash = EXCLUDED.password_hash, status = 'ACTIVE',
         failed_login_count = 0, locked_until = NULL,
         mhp_eligible = true, mhp_status_id = EXCLUDED.mhp_status_id, mhp_allow_login = true, mhp_synced_at = now()
       WHERE users.credential_source = 'LOCAL'
       RETURNING its_id`,
      [user.itsId, user.name, await hasher.hash(demoPassword), env.MHP_ACTIVE_STATUS_ID],
    )) as unknown[];
    demo += rows.length;
    await sync({ its_id: user.itsId, name: user.name });
  }

  let nonIts = 'skipped (DEV_NON_ITS_USERNAME / DEV_NON_ITS_PASSWORD not set)';
  if (username && nonItsPassword) {
    const existing = (await dataSource.query(`SELECT its_id FROM users WHERE username = $1`, [username])) as { its_id: string }[];
    const itsId = existing[0]?.its_id ?? `NITS-${randomBytes(4).toString('hex').toUpperCase()}`;
    await dataSource.query(
      `INSERT INTO users (its_id, identity_type, username, name, email, password_hash, password_algo, credential_source, password_changed_at,
                          mhp_eligible, mhp_status_id, mhp_allow_login, mhp_synced_at)
       VALUES ($1, 'NON_ITS', $2, 'Guest Member', $3, $4, 'scrypt', 'LOCAL', now(),
               true, $5, true, now())
       ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, status = 'ACTIVE', failed_login_count = 0, locked_until = NULL,
         mhp_eligible = true, mhp_status_id = EXCLUDED.mhp_status_id, mhp_allow_login = true, mhp_synced_at = now()`,
      [itsId, username, username.includes('@') ? username : null, await hasher.hash(nonItsPassword), env.MHP_ACTIVE_STATUS_ID],
    );
    await sync({ its_id: itsId, name: 'Guest Member', ...(username.includes('@') ? { email: username } : {}) });
    nonIts = itsId;
  }

  console.log(`demo users ready: ${demo}/${DEMO_USERS.length} (password from DEV_DEMO_PASSWORD); Non-ITS member: ${nonIts}; profiles synced: ${synced.length}`);
  await dataSource.destroy();
}

main().catch(async (error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  await dataSource.destroy().catch(() => undefined);
  process.exit(1);
});
