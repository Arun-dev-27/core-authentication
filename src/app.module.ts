import { Module } from '@nestjs/common';
import { ConfigModule } from '@config/config.module';
import { AuditModule } from '@core/audit/audit.module';
import { RedisModule } from '@core/cache/redis.module';
import { DatabaseModule } from '@core/database/database.module';
import { HealthModule } from '@core/health/health.module';
import { ClientsModule } from '@modules/clients/clients.module';
import { EmbedModule } from '@modules/embed/embed.module';
import { FederationModule } from '@modules/federation/federation.module';
import { KeysModule } from '@modules/keys/keys.module';
import { PortalModule } from '@modules/portal/portal.module';
import { SessionsModule } from '@modules/sessions/sessions.module';
import { TransactionsModule } from '@modules/transactions/transactions.module';

@Module({
  imports: [
    // app-wide infrastructure
    ConfigModule,
    DatabaseModule,
    RedisModule,
    AuditModule,
    HealthModule,
    // features
    KeysModule,
    ClientsModule,
    TransactionsModule,
    SessionsModule,
    FederationModule,
    EmbedModule,
    PortalModule,
  ],
})
export class AppModule {}
