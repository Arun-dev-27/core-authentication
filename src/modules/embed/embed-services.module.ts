import { Module } from '@nestjs/common';
import { AssertionsModule } from '@modules/assertions/assertions.module';
import { ClientsServicesModule } from '@modules/clients/clients-services.module';
import { CredentialsModule } from '@modules/credentials/credentials.module';
import { FederationServicesModule } from '@modules/federation/federation-services.module';
import { RateLimitModule } from '@modules/rate-limit/rate-limit.module';
import { SessionsServicesModule } from '@modules/sessions/sessions-services.module';
import { TransactionsServicesModule } from '@modules/transactions/transactions-services.module';
import { LoginService } from './services/login.service';

/** Embedded login — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [TransactionsServicesModule, ClientsServicesModule, CredentialsModule, RateLimitModule, SessionsServicesModule, AssertionsModule, FederationServicesModule],
  providers: [LoginService],
  exports: [LoginService],
})
export class EmbedServicesModule {}
