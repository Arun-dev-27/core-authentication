import { Module } from '@nestjs/common';
import { ClientsServicesModule } from './clients-services.module';
import { ClientsV1Module } from './v1/clients-v1.module';

/** Dynamic client registry — feature aggregator. */
@Module({
  imports: [ClientsServicesModule, ClientsV1Module],
  exports: [ClientsServicesModule],
})
export class ClientsModule {}
