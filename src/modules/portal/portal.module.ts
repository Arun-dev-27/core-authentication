import { Module } from '@nestjs/common';
import { PortalV1Module } from './v1/portal-v1.module';

/** Core Portal application launcher — feature aggregator. */
@Module({
  imports: [PortalV1Module],
})
export class PortalModule {}
