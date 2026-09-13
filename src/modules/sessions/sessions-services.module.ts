import { Module } from '@nestjs/common';
import { FederationSessionService } from './services/federation-session.service';

/** Central federation sessions — version-agnostic services, reused by every /vN edge. */
@Module({
  providers: [FederationSessionService],
  exports: [FederationSessionService],
})
export class SessionsServicesModule {}
