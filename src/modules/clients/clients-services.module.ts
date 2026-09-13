import { Module } from '@nestjs/common';
import { AuthorizationClientModule } from '@modules/authorization-client/authorization-client.module';
import { ClientRegistry } from './services/client-registry.service';

/** Dynamic client registry — version-agnostic services, reused by every /vN edge. */
@Module({
  imports: [AuthorizationClientModule],
  providers: [ClientRegistry],
  exports: [ClientRegistry],
})
export class ClientsServicesModule {}
