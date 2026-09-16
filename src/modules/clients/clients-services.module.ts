import { Module } from '@nestjs/common';
import { ClientRegistry } from './services/client-registry.service';
import { ClientsStoreService } from './services/clients-store.service';

/** Dynamic client registry, backed by core-authentication's own tables — version-agnostic, reused by every /vN edge. */
@Module({
  providers: [ClientRegistry, ClientsStoreService],
  exports: [ClientRegistry],
})
export class ClientsServicesModule {}
