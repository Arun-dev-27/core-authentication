/**
 * Operator CLI for a federation client's embed origins and callback / logout URIs, in core-authentication's own
 * auth_clients / auth_client_origins / auth_client_callbacks tables (TypeORM entities AuthClient, AuthClientOrigin,
 * AuthClientCallback). Use `seed-clients.ts` to create a client first; this manages origins/callbacks on an existing one.
 *
 *   npm run client -- show      <client_id>
 *   npm run client -- origins   list   <client_id>
 *   npm run client -- origins   add    <client_id> <origin>
 *   npm run client -- origins   remove <client_id> <origin>
 *   npm run client -- callbacks list   <client_id>
 *   npm run client -- callbacks add    <client_id> <uri> [--type CALLBACK|BACK_CHANNEL_LOGOUT|POST_LOGOUT_REDIRECT] [--primary]
 *   npm run client -- callbacks remove <client_id> <uri> [--type ...]
 *
 * Only these three client-registry tables are touched - never user, eligibility or RBAC data. core-authentication
 * reads client configuration fresh on every transaction/login page load, so a change here applies at once.
 */
import 'reflect-metadata';
import { parseArgs } from 'node:util';
import dataSource from '@core/database/data-source';
import { AuthClient } from '@core/database/entities/auth/auth-client.entity';
import { type CallbackUriType, AuthClientCallback } from '@core/database/entities/auth/auth-client-callback.entity';
import { AuthClientOrigin } from '@core/database/entities/auth/auth-client-origin.entity';

const URI_TYPES: readonly CallbackUriType[] = ['CALLBACK', 'BACK_CHANNEL_LOGOUT', 'POST_LOGOUT_REDIRECT'];

const USAGE = `usage:
  npm run client -- show <client_id>
  npm run client -- origins list|add|remove <client_id> [origin]
  npm run client -- callbacks list|add|remove <client_id> [uri] [--type CALLBACK|BACK_CHANNEL_LOGOUT|POST_LOGOUT_REDIRECT] [--primary]`;

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
  const uriType = (values.type ?? 'CALLBACK') as CallbackUriType;
  if (!URI_TYPES.includes(uriType)) throw new Error(`--type must be one of ${URI_TYPES.join(', ')}`);

  await dataSource.initialize();
  const clients = dataSource.getRepository(AuthClient);
  const origins = dataSource.getRepository(AuthClientOrigin);
  const callbacks = dataSource.getRepository(AuthClientCallback);
  try {
    const client = await clients.findOne({
      where: { clientId },
      relations: { origins: true, callbacks: true },
      order: { origins: { createdAt: 'ASC' }, callbacks: { createdAt: 'ASC' } },
    });
    if (!client) throw new Error(`client '${clientId}' not found - run seed-clients.ts or create it first`);

    if (resource === 'show') {
      console.log(JSON.stringify(client, null, 2));
      return;
    }

    if (resource === 'origins') {
      if (action === 'add') {
        await origins.createQueryBuilder().insert().into(AuthClientOrigin).values({ clientRef: client.id, origin: value! }).orIgnore().execute();
      } else if (action === 'remove') {
        await origins.delete({ clientRef: client.id, origin: value! });
      }
      console.log(JSON.stringify(await origins.find({ where: { clientRef: client.id }, order: { createdAt: 'ASC' } }), null, 2));
    } else {
      if (action === 'add') {
        await callbacks
          .createQueryBuilder()
          .insert()
          .into(AuthClientCallback)
          .values({ clientRef: client.id, uri: value!, uriType, isPrimary: values.primary })
          .orIgnore()
          .execute();
      } else if (action === 'remove') {
        await callbacks.delete({ clientRef: client.id, uri: value!, uriType });
      }
      console.log(JSON.stringify(await callbacks.find({ where: { clientRef: client.id }, order: { createdAt: 'ASC' } }), null, 2));
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
