import type { DataSourceOptions } from 'typeorm';
import type { Env } from '@config/configuration';
import { IDENTITY_DB_ENTITIES } from './entities';

/**
 * The identity_db connection.
 *
 * search_path is pinned to IDENTITY_DB_SCHEMA (miqaat_core) and nothing else, so every unqualified table
 * name in this service - the synced users / user_eligible / mumin_master and the auth_* tables - resolves
 * inside that one schema and can never silently hit a same-named table in `public`.
 *
 * No TypeORM migrations run against this database: the synced tables belong to the Mumin sync service and
 * the auth_* tables are created, only where missing, by `npm run db:ensure-auth-tables`.
 */
export function buildDataSourceOptions(env: Env): DataSourceOptions {
  return {
    type: 'postgres',
    host: env.IDENTITY_DB_HOST,
    port: env.IDENTITY_DB_PORT,
    username: env.IDENTITY_DB_USER,
    password: env.IDENTITY_DB_PASSWORD,
    database: env.IDENTITY_DB_NAME,
    schema: env.IDENTITY_DB_SCHEMA,
    ssl: env.IDENTITY_DB_SSL ? { rejectUnauthorized: true } : false,
    // Never let TypeORM create, alter or drop anything: the entities only map the existing tables.
    synchronize: false,
    migrationsRun: false,
    dropSchema: false,
    logging: false,
    entities: IDENTITY_DB_ENTITIES,
    migrations: [],
    extra: {
      max: 20,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      // The schema name is validated by the env schema (^[a-z_][a-z0-9_]{0,62}$), so it is safe to inline.
      options: `-c search_path=${env.IDENTITY_DB_SCHEMA}`,
    },
  };
}
