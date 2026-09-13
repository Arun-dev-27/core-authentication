import { Global, Inject, Injectable, Module, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';

export const REDIS = Symbol('REDIS');

@Injectable()
class RedisLifecycle implements OnModuleDestroy {
  constructor(@Inject(REDIS) private readonly redis: Redis) {}

  async onModuleDestroy(): Promise<void> {
    await this.redis.quit().catch(() => undefined);
  }
}

@Global()
@Module({
  providers: [
    {
      provide: REDIS,
      inject: [AppConfig],
      useFactory: (config: AppConfig) =>
        new Redis(config.env.REDIS_URL, { maxRetriesPerRequest: 2, enableReadyCheck: true, connectTimeout: 5000 }),
    },
    RedisLifecycle,
  ],
  exports: [REDIS],
})
export class RedisModule {}
