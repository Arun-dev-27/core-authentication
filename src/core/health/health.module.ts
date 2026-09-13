import { Module } from '@nestjs/common';
import { KeysModule } from '@modules/keys/keys.module';
import { HealthController } from './health.controller';

/** Liveness and readiness probes. */
@Module({
  imports: [KeysModule],
  controllers: [HealthController],
})
export class HealthModule {}
