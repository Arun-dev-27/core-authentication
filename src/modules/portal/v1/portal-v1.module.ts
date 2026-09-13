import { Module } from '@nestjs/common';
import { AssertionsModule } from '@modules/assertions/assertions.module';
import { AuthorizationClientModule } from '@modules/authorization-client/authorization-client.module';
import { EmbedServicesModule } from '@modules/embed/embed-services.module';
import { FederationServicesModule } from '@modules/federation/federation-services.module';
import { SessionsServicesModule } from '@modules/sessions/sessions-services.module';
import { TransactionsServicesModule } from '@modules/transactions/transactions-services.module';
import { PortalLoginService } from '../services/portal-login.service';
import { CoreLoginController, PortalController } from './portal.controller';

/** Core Portal application launcher and administrator token issuance — v1 HTTP edge. */
@Module({
  imports: [EmbedServicesModule, TransactionsServicesModule, SessionsServicesModule, FederationServicesModule, AuthorizationClientModule, AssertionsModule],
  controllers: [PortalController, CoreLoginController],
  providers: [PortalLoginService],
})
export class PortalV1Module {}
