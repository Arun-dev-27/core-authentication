import { Module } from '@nestjs/common';
import { LoginThrottleService } from './services/login-throttle.service';

/** Distributed brute-force protection. */
@Module({
  providers: [LoginThrottleService],
  exports: [LoginThrottleService],
})
export class RateLimitModule {}
