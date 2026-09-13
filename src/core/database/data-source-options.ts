import { join } from 'node:path';
import type { DataSourceOptions } from 'typeorm';
import type { Env } from '@config/configuration';

export function buildDataSourceOptions(env: Env): DataSourceOptions {
  return {
    type: 'postgres',
    host: env.AUTH_DB_HOST,
    port: env.AUTH_DB_PORT,
    username: env.AUTH_DB_USER,
    password: env.AUTH_DB_PASSWORD,
    database: env.AUTH_DB_NAME,
    ssl: env.AUTH_DB_SSL ? { rejectUnauthorized: true } : false,
    synchronize: false,
    migrationsRun: false,
    logging: false,
    entities: [],
    migrations: [join(__dirname, 'migrations', '*.{ts,js}')],
    migrationsTableName: 'schema_migrations',
    extra: { max: 20, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000 },
  };
}
