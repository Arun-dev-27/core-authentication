import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';
import { RedisKeys } from '@common/constants/redis-keys.constants';
import { Errors } from '@common/errors/domain-error';
import { REDIS } from '@core/cache/redis.module';

/**
 * Distributed (Redis) brute-force protection shared by all pods:
 *  - per client IP: every attempt counts (credential stuffing / spraying)
 *  - per identifier: failures count (targeted guessing), reset on success
 * Durable per-account lockout is additionally enforced in the Authentication DB.
 */
@Injectable()
export class LoginThrottleService {
  constructor(
    @Inject(REDIS) private readonly redis: Redis,
    private readonly config: AppConfig,
  ) {}

  async assertAllowed(ip: string, identifierHash: string): Promise<void> {
    const env = this.config.env;
    const ipKey = RedisKeys.ipAttempts(ip);
    const idKey = RedisKeys.identifierFailures(identifierHash);

    const results = await this.redis
      .multi()
      .incr(ipKey)
      .expire(ipKey, env.LOGIN_IP_WINDOW_SECONDS, 'NX')
      .ttl(ipKey)
      .get(idKey)
      .ttl(idKey)
      .exec();
    if (!results) throw Errors.dependencyUnavailable();

    const ipCount = Number(results[0][1]);
    const ipTtl = Number(results[2][1]);
    const idFailures = Number(results[3][1] ?? 0);
    const idTtl = Number(results[4][1]);

    if (ipCount > env.LOGIN_MAX_ATTEMPTS_PER_IP) throw Errors.tooManyAttempts(Math.max(ipTtl, 1));
    if (idFailures >= env.LOGIN_MAX_FAILURES_PER_IDENTIFIER) throw Errors.tooManyAttempts(Math.max(idTtl, 1));
  }

  async recordFailure(identifierHash: string): Promise<void> {
    const key = RedisKeys.identifierFailures(identifierHash);
    await this.redis.multi().incr(key).expire(key, this.config.env.LOGIN_IDENTIFIER_WINDOW_SECONDS, 'NX').exec();
  }

  async recordSuccess(identifierHash: string): Promise<void> {
    await this.redis.del(RedisKeys.identifierFailures(identifierHash));
  }
}
