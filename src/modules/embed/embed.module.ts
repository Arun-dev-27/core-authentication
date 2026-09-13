import { Module } from '@nestjs/common';
import { EmbedServicesModule } from './embed-services.module';
import { EmbedV1Module } from './v1/embed-v1.module';

/** Embedded login — feature aggregator. */
@Module({
  imports: [EmbedServicesModule, EmbedV1Module],
  exports: [EmbedServicesModule],
})
export class EmbedModule {}
