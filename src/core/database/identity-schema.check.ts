import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { inspectIdentitySchema } from './identity-schema';

/**
 * Refuses to boot against a database that is not a prepared identity_db, instead of failing every login
 * later with an SQL error. Read-only: it never creates anything (that is `npm run db:ensure-auth-tables`).
 */
@Injectable()
export class IdentitySchemaCheck implements OnModuleInit {
  private readonly logger = new Logger(IdentitySchemaCheck.name);

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly config: AppConfig,
  ) {}

  async onModuleInit(): Promise<void> {
    const schema = this.config.env.IDENTITY_DB_SCHEMA;
    const report = await inspectIdentitySchema(this.db, schema);
    const problems = [
      ...(report.schemaExists ? [] : [`schema "${schema}" does not exist`]),
      ...report.missingSyncedTables.map((t) => `synced table ${t} is missing`),
      ...report.missingAuthTables.map((t) => `auth table ${t} is missing (run npm run db:ensure-auth-tables)`),
      ...report.missingColumns.map((c) => `column ${c} is missing`),
    ];
    if (problems.length) throw new Error(`identity_db is not ready: ${problems.join('; ')}`);
    this.logger.log({ msg: 'identity_db schema verified', schema });
  }
}
