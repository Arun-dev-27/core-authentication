/**
 * Operator CLI for a federation client's embed origins and callback / logout URIs - local to
 * core-authentication's own auth_clients tables (see AuthClients1789600000000). Use `seed-clients.ts` to
 * create a client in the first place; this manages origins/callbacks on an existing one.
 *
 *   npm run client -- show      <client_id>
 *   npm run client -- origins   list   <client_id>
 *   npm run client -- origins   add    <client_id> <origin>
 *   npm run client -- origins   remove <client_id> <origin>
 *   npm run client -- callbacks list   <client_id>
 *   npm run client -- callbacks add    <client_id> <uri> [--type CALLBACK|BACK_CHANNEL_LOGOUT|POST_LOGOUT_REDIRECT] [--primary]
 *   npm run client -- callbacks remove <client_id> <uri> [--type ...]
 *
 * core-authentication reads client configuration fresh on every transaction/login page load (no restart
 * needed), and the Redis cache used elsewhere is bypassed for those reads - a change here applies at once.
 */
import 'reflect-metadata';
import { parseArgs } from 'node:util';
import dataSource from '@core/database/data-source';

const URI_TYPES = ['CALLBACK', 'BACK_CHANNEL_LOGOUT', 'POST_LOGOUT_REDIRECT'] as const;
type UriType = (typeof URI_TYPES)[number];

const USAGE = `usage:
  npm run client -- show <client_id>
  npm run client -- origins list|add|remove <client_id> [origin]
  npm run client -- callbacks list|add|remove <client_id> [uri] [--type CALLBACK|BACK_CHANNEL_LOGOUT|POST_LOGOUT_REDIRECT] [--primary]`;

async function requireClientRef(clientId: string): Promise<string> {
  const rows = await dataSource.query(`SELECT id FROM auth_clients WHERE client_id = $1`, [clientId]);
  if (!rows.length) throw new Error(`client '${clientId}' not found - run seed-clients.ts or create it first`);
  return rows[0].id;
}

async function main() {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: { type: { type: 'string' }, primary: { type: 'boolean', default: false } },
  });
  const [resource, second, third, fourth] = positionals;
  const action = resource === 'show' ? 'show' : second;
  const clientId = resource === 'show' ? second : third;
  const value = resource === 'show' ? undefined : fourth;

  if (!['show', 'origins', 'callbacks'].includes(resource ?? '') || !clientId) throw new Error(USAGE);
  if (resource !== 'show' && !['list', 'add', 'remove'].includes(action ?? '')) throw new Error(USAGE);
  if ((action === 'add' || action === 'remove') && !value) throw new Error(`${resource} ${action} needs a value\n${USAGE}`);
  const uriType = (values.type ?? 'CALLBACK') as UriType;
  if (!URI_TYPES.includes(uriType)) throw new Error(`--type must be one of ${URI_TYPES.join(', ')}`);

  await dataSource.initialize();
  try {
    if (resource === 'show') {
      const client = await dataSource.query(`SELECT * FROM auth_clients WHERE client_id = $1`, [clientId]);
      if (!client.length) throw new Error(`client '${clientId}' not found`);
      const clientRef = client[0].id;
      const origins = await dataSource.query(`SELECT origin FROM auth_client_origins WHERE client_ref = $1 ORDER BY created_at`, [clientRef]);
      const callbacks = await dataSource.query(`SELECT uri, uri_type, is_primary FROM auth_client_callbacks WHERE client_ref = $1 ORDER BY created_at`, [clientRef]);
      console.log(JSON.stringify({ ...client[0], allowed_embed_origins: origins.map((o: { origin: string }) => o.origin), callbacks }, null, 2));
      return;
    }

    const clientRef = await requireClientRef(clientId);

    if (resource === 'origins') {
      if (action === 'add') {
        await dataSource.query(`INSERT INTO auth_client_origins (client_ref, origin) VALUES ($1, $2) ON CONFLICT (client_ref, origin) DO NOTHING`, [clientRef, value]);
      } else if (action === 'remove') {
        await dataSource.query(`DELETE FROM auth_client_origins WHERE client_ref = $1 AND origin = $2`, [clientRef, value]);
      }
      const origins = await dataSource.query(`SELECT origin, created_at FROM auth_client_origins WHERE client_ref = $1 ORDER BY created_at`, [clientRef]);
      console.log(JSON.stringify(origins, null, 2));
    } else {
      if (action === 'add') {
        await dataSource.query(
          `INSERT INTO auth_client_callbacks (client_ref, uri, uri_type, is_primary) VALUES ($1, $2, $3, $4) ON CONFLICT (client_ref, uri, uri_type) DO NOTHING`,
          [clientRef, value, uriType, values.primary],
        );
      } else if (action === 'remove') {
        await dataSource.query(`DELETE FROM auth_client_callbacks WHERE client_ref = $1 AND uri = $2 AND uri_type = $3`, [clientRef, value, uriType]);
      }
      const callbacks = await dataSource.query(`SELECT uri, uri_type, is_primary, created_at FROM auth_client_callbacks WHERE client_ref = $1 ORDER BY created_at`, [clientRef]);
      console.log(JSON.stringify(callbacks, null, 2));
    }

    if (action === 'add' || action === 'remove') {
      console.log(`\n${resource} ${action} done. core-authentication reads client config fresh on every transaction/login page load - no restart needed.`);
    }
  } finally {
    await dataSource.destroy();
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
