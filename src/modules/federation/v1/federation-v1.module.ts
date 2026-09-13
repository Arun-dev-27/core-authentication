import { Module } from '@nestjs/common';
import { AssertionsModule } from '@modules/assertions/assertions.module';
import { AuthorizationClientModule } from '@modules/authorization-client/authorization-client.module';
import { ClientsServicesModule } from '@modules/clients/clients-services.module';
import { SessionsServicesModule } from '@modules/sessions/sessions-services.module';
import { FederationServicesModule } from '../federation-services.module';
import { FederationController } from './federation.controller';

/** Federation logout and back-channel fan-out — v1 HTTP edge. */
@Module({
  imports: [FederationServicesModule, SessionsServicesModule, ClientsServicesModule, AssertionsModule, AuthorizationClientModule],
  controllers: [FederationController],
})
export class FederationV1Module {}
