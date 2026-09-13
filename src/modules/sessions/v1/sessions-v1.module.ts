import { Module } from '@nestjs/common';
import { SessionsServicesModule } from '../sessions-services.module';
import { SessionController } from './session.controller';

/** Central federation sessions — v1 HTTP edge. */
@Module({
  imports: [SessionsServicesModule],
  controllers: [SessionController],
})
export class SessionsV1Module {}
