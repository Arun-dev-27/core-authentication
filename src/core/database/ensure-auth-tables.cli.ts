import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { loadEnv, loadEnvFiles } from '@config/configuration';
import { buildDataSourceOptions } from './data-source-options';
import { ensureAuthTables, inspectIdentitySchema } from './identity-schema';

/**
 * Creates the missing auth_* tables in the existing identity_db schema - and nothing else.
 *
 *   npm run db:ensure-auth-tables            create what is missing
 *   npm run db:ensure-auth-tables -- --check report only, change nothing (exit 1 if anything is missing)
 *
 * Safe to run repeatedly. Compiled into dist/, so a deploy can run it without ts-node:
 *   node dist/core/database/ensure-auth-tables.cli.js
 */
async function main() {
  loadEnvFiles();
  const env = loadEnv();
  const checkOnly = process.argv.includes('--check');
  const db = new DataSource(buildDataSourceOptions(env));
  await db.initialize();
  try {
    const target = `${env.IDENTITY_DB_HOST}:${env.IDENTITY_DB_PORT}/${env.IDENTITY_DB_NAME} schema ${env.IDENTITY_DB_SCHEMA}`;
    if (checkOnly) {
      const report = await inspectIdentitySchema(db, env.IDENTITY_DB_SCHEMA);
      print(target, report, []);
      const ok = report.schemaExists && !report.missingSyncedTables.length && !report.missingAuthTables.length && !report.missingColumns.length;
      process.exitCode = ok ? 0 : 1;
      return;
    }
    const { created, report } = await ensureAuthTables(db, env.IDENTITY_DB_SCHEMA);
    print(target, report, created);
    if (report.missingColumns.length) process.exitCode = 1;
  } finally {
    await db.destroy();
  }
}

function print(target: string, report: Awaited<ReturnType<typeof inspectIdentitySchema>>, created: string[]) {
  console.log(`identity_db: ${target}`);
  console.log(`  schema exists:             ${report.schemaExists}`);
  console.log(`  missing synced tables:     ${report.missingSyncedTables.join(', ') || 'none'}`);
  console.log(`  created auth tables:       ${created.join(', ') || 'none'}`);
  console.log(`  missing auth tables:       ${report.missingAuthTables.join(', ') || 'none'}`);
  console.log(`  missing columns:           ${report.missingColumns.join(', ') || 'none'}${report.missingColumns.length ? '  (NOT altered - fix by hand)' : ''}`);
  if (report.possibleEquivalents.length) {
    console.log(`  review, may overlap auth_*: ${report.possibleEquivalents.join(', ')}`);
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
