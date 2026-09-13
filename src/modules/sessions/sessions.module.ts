import { Module } from '@nestjs/common';
import { SessionsServicesModule } from './sessions-services.module';
import { SessionsV1Module } from './v1/sessions-v1.module';

/** Central federation sessions — feature aggregator. */
@Module({
  imports: [SessionsServicesModule, SessionsV1Module],
  exports: [SessionsServicesModule],
})
export class SessionsModule {}
