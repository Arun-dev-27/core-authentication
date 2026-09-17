/**
 * Idempotent seed of core-authentication's own federation client registry, through the TypeORM entities
 * AuthClient (auth_clients), AuthClientOrigin (auth_client_origins) and AuthClientCallback (auth_client_callbacks).
 * Registers the rms-web-dev client used by the core-embed-login React example app.
 *
 * Only adds what is missing; never updates or removes existing rows (use `npm run client -- origins remove ...`).
 * Touches only these three client-registry tables - never user, eligibility or RBAC data.
 *
 *   npm run seed:clients
 */
import 'reflect-metadata';
import dataSource from '@core/database/data-source';
import { AuthClient } from '@core/database/entities/auth/auth-client.entity';
import { type CallbackUriType, AuthClientCallback } from '@core/database/entities/auth/auth-client-callback.entity';
import { AuthClientOrigin } from '@core/database/entities/auth/auth-client-origin.entity';

const CLIENT_ID = 'rms-web-dev';
const ORIGINS = ['http://localhost:5175'];
const CALLBACKS: { uri: string; uriType: CallbackUriType; isPrimary: boolean }[] = [
  { uri: 'http://localhost:4001/auth/core/callback', uriType: 'CALLBACK', isPrimary: true },
  { uri: 'http://localhost:4001/auth/core/logout', uriType: 'BACK_CHANNEL_LOGOUT', isPrimary: true },
  { uri: 'http://localhost:4001/logout/callback', uriType: 'POST_LOGOUT_REDIRECT', isPrimary: true },
];

async function main() {
  await dataSource.initialize();
  await dataSource.transaction(async (manager) => {
    const clients = manager.getRepository(AuthClient);
    let client = await clients.findOneBy({ clientId: CLIENT_ID });
    if (!client) {
      client = await clients.save(
        clients.create({
          clientId: CLIENT_ID,
          name: 'RMS Web (DEV)',
          applicationCode: 'rms',
          applicationName: 'RMS Web',
          businessUnit: 'RMS',
          environment: 'DEV',
          clientType: 'WEB',
          authenticationMode: 'EMBEDDED_OR_REDIRECT',
          status: 'ACTIVE',
          initiateLoginUri: 'http://localhost:4001/auth/core/login',
        }),
      );
      console.log(`created client ${CLIENT_ID}`);
    }

    for (const origin of ORIGINS) {
      const result = await manager
        .createQueryBuilder()
        .insert()
        .into(AuthClientOrigin)
        .values({ clientRef: client.id, origin })
        .orIgnore()
        .returning('id')
        .execute();
      if ((result.raw as unknown[]).length) console.log(`added origin ${origin}`);
    }

    for (const cb of CALLBACKS) {
      const result = await manager
        .createQueryBuilder()
        .insert()
        .into(AuthClientCallback)
        .values({ clientRef: client.id, ...cb })
        .orIgnore()
        .returning('id')
        .execute();
      if ((result.raw as unknown[]).length) console.log(`added ${cb.uriType} ${cb.uri}`);
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
