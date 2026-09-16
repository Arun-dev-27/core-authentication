import { Module } from '@nestjs/common';
import { AssertionsModule } from '@modules/assertions/assertions.module';
import { AuthorizationClientModule } from '@modules/authorization-client/authorization-client.module';
import { ClientsServicesModule } from '@modules/clients/clients-services.module';
import { SessionsServicesModule } from '@modules/sessions/sessions-services.module';
import { LogoutService } from './services/logout.service';

/** Federation logout and back-channel fan-out — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [SessionsServicesModule, ClientsServicesModule, AssertionsModule, AuthorizationClientModule],
  providers: [LogoutService],
  exports: [LogoutService],
})
export class FederationServicesModule {}
