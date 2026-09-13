import { Module } from '@nestjs/common';
import { FederationServicesModule } from './federation-services.module';
import { FederationV1Module } from './v1/federation-v1.module';

/** Federation logout and back-channel fan-out — feature aggregator. */
@Module({
  imports: [FederationServicesModule, FederationV1Module],
  exports: [FederationServicesModule],
})
export class FederationModule {}
