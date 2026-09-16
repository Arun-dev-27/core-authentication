/**
 * Idempotent seed of core-authentication's own federation client registry (auth_clients /
 * auth_client_origins / auth_client_callbacks - see AuthClients1789600000000). Reproduces the same
 * rms-web-dev configuration this project has been using throughout local development and testing,
 * now owned here instead of read from core-authorization.
 *
 * Only :5175 (the core-embed-react example app) is a real, currently-used origin. :3000 and :4001 were
 * carried over from the original catalog seed and the now-deleted example/server/ legacy backend
 * respectively - removed from here (and from the live registry) since nothing serves either port anymore.
 * This script only ever adds rows (ON CONFLICT DO NOTHING); it never removes ones a prior run already
 * created, so an existing dev database with stale origins needs `npm run client -- origins remove ...`
 * to actually clean up (see HANDOFF.md).
 *
 *   npm run seed:clients
 */
import 'reflect-metadata';
import dataSource from '@core/database/data-source';

const CLIENT_ID = 'rms-web-dev';
const ORIGINS = ['http://localhost:5175'];
const CALLBACKS: { uri: string; uri_type: 'CALLBACK' | 'BACK_CHANNEL_LOGOUT' | 'POST_LOGOUT_REDIRECT'; is_primary: boolean }[] = [
  { uri: 'http://localhost:4001/auth/core/callback', uri_type: 'CALLBACK', is_primary: true },
  { uri: 'http://localhost:4001/auth/core/logout', uri_type: 'BACK_CHANNEL_LOGOUT', is_primary: true },
  { uri: 'http://localhost:4001/logout/callback', uri_type: 'POST_LOGOUT_REDIRECT', is_primary: true },
];

async function main() {
  await dataSource.initialize();
  await dataSource.transaction(async (tx) => {
    let client = await tx.query(`SELECT id FROM auth_clients WHERE client_id = $1`, [CLIENT_ID]);
    if (!client.length) {
      client = await tx.query(
        `INSERT INTO auth_clients (client_id, name, application_code, application_name, business_unit, environment, client_type, authentication_mode, status, initiate_login_uri)
         VALUES ($1, 'RMS Web (DEV)', 'rms', 'RMS Web', 'RMS', 'DEV', 'WEB', 'EMBEDDED_OR_REDIRECT', 'ACTIVE', 'http://localhost:4001/auth/core/login')
         RETURNING id`,
        [CLIENT_ID],
      );
      console.log(`created client ${CLIENT_ID}`);
    }
    const clientRef = client[0].id;

    for (const origin of ORIGINS) {
      const result = await tx.query(`INSERT INTO auth_client_origins (client_ref, origin) VALUES ($1, $2) ON CONFLICT (client_ref, origin) DO NOTHING RETURNING id`, [clientRef, origin]);
      if (result.length) console.log(`added origin ${origin}`);
    }

    for (const cb of CALLBACKS) {
      const result = await tx.query(
        `INSERT INTO auth_client_callbacks (client_ref, uri, uri_type, is_primary) VALUES ($1, $2, $3, $4) ON CONFLICT (client_ref, uri, uri_type) DO NOTHING RETURNING id`,
        [clientRef, cb.uri, cb.uri_type, cb.is_primary],
      );
      if (result.length) console.log(`added ${cb.uri_type} ${cb.uri}`);
    }
  });
  await dataSource.destroy();
  console.log('client seed complete');
}

main().catch(async (error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  await dataSource.destroy().catch(() => undefined);
  process.exit(1);
});
