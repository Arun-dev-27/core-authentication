import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppConfig } from '@config/config.module';
import { buildDataSourceOptions } from './data-source-options';
import { IDENTITY_DB_ENTITIES } from './entities';
import { IdentitySchemaCheck } from './identity-schema.check';
import { AuthClientRepository } from './repositories/auth-client.repository';
import { AuthSessionRepository } from './repositories/auth-session.repository';
import { IdentityAccountRepository } from './repositories/identity-account.repository';
import { LoginAttemptRepository } from './repositories/login-attempt.repository';

const REPOSITORIES = [IdentityAccountRepository, LoginAttemptRepository, AuthSessionRepository, AuthClientRepository];

/**
 * The identity_db connection, its entities and repositories - available to every module.
 * synchronize and migrations are off: TypeORM never creates or alters a table here.
 */
@Global()
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [AppConfig],
      useFactory: (config: AppConfig) => buildDataSourceOptions(config.env),
    }),
    TypeOrmModule.forFeature(IDENTITY_DB_ENTITIES),
  ],
  providers: [IdentitySchemaCheck, ...REPOSITORIES],
  exports: [TypeOrmModule, ...REPOSITORIES],
})
export class DatabaseModule {}
