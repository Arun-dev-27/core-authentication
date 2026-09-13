import { Controller, Get, HttpStatus, Inject, Res } from '@nestjs/common';
import { VERSION_NEUTRAL } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { InjectDataSource } from '@nestjs/typeorm';
import type { FastifyReply } from 'fastify';
import Redis from 'ioredis';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { REDIS } from '@core/cache/redis.module';
import { KeyStore } from '@modules/keys/services/key-store.service';

@ApiTags('health')
@Controller({ path: 'health', version: VERSION_NEUTRAL })
export class HealthController {
  constructor(
    @InjectDataSource() private readonly db: DataSource,
    @Inject(REDIS) private readonly redis: Redis,
    private readonly keys: KeyStore,
    private readonly config: AppConfig,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Liveness probe' })
  live() {
    return { status: 'ok', service: 'miqaat-identity-federation-service' };
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness: auth DB, Redis and signing keys (authorization service reported, not gating)' })
  async ready(@Res() reply: FastifyReply) {
    const checks = {
      database: await this.probe(() => this.db.query('SELECT 1')),
      redis: await this.probe(() => this.redis.ping()),
      signing_keys: this.keys.isReady() ? 'up' : 'down',
      authorization_service: await this.probe(async () => {
        const res = await fetch(`${this.config.env.AUTHZ_BASE_URL}/health`, { signal: AbortSignal.timeout(1500) });
        if (!res.ok) throw new Error(String(res.status));
      }),
    };
    const ok = checks.database === 'up' && checks.redis === 'up' && checks.signing_keys === 'up';
    void reply.status(ok ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE).send({ status: ok ? 'ready' : 'not_ready', checks });
  }

  private async probe(fn: () => Promise<unknown>): Promise<'up' | 'down'> {
    try {
      await Promise.race([fn(), new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))]);
      return 'up';
    } catch {
      return 'down';
    }
  }
}
