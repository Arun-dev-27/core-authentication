import { Inject, Injectable, Logger } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';
import { RedisKeys } from '@common/constants/redis-keys.constants';
import { CLIENT_ID_PATTERN } from '@common/constants/validation.constants';
import { Errors } from '@common/errors/domain-error';
import { REDIS } from '@core/cache/redis.module';
import { FederationClientConfig } from '@shared/types/federation-client.types';
import { ClientsStoreService } from './clients-store.service';

const NOT_FOUND_MARKER = '__NOT_FOUND__';
const NEGATIVE_TTL_SECONDS = 10;

/**
 * Dynamic client registry backed by core-authentication's own auth_clients tables, with a short Redis
 * cache. This is the authentication trust boundary (which origins may embed the login, receive an
 * assertion for which client_id) - it must not depend on any authorization service, since more than one
 * may exist. Fails closed: if configuration cannot be loaded, sign-in is refused.
 */
@Injectable()
export class ClientRegistry {
  private readonly logger = new Logger(ClientRegistry.name);

  constructor(
    private readonly store: ClientsStoreService,
    private readonly config: AppConfig,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  async get(clientId: unknown): Promise<FederationClientConfig> {
    if (typeof clientId !== 'string' || !CLIENT_ID_PATTERN.test(clientId)) throw Errors.clientNotFound();
    const ttl = this.config.env.CLIENT_CACHE_TTL_SECONDS;
    const key = RedisKeys.clientConfig(clientId);

    if (ttl > 0) {
      const cached = await this.redis.get(key);
      if (cached === NOT_FOUND_MARKER) throw Errors.clientNotFound();
      if (cached) return JSON.parse(cached) as FederationClientConfig;
    }

    let client: FederationClientConfig | null;
    try {
      client = await this.store.findByClientId(clientId);
    } catch (error) {
      this.logger.error({ msg: 'client registry lookup failed', client_id: clientId, err: error instanceof Error ? error.message : error });
      throw Errors.dependencyUnavailable();
    }
    if (!client) {
      if (ttl > 0) await this.redis.set(key, NOT_FOUND_MARKER, 'EX', Math.min(ttl, NEGATIVE_TTL_SECONDS));
      throw Errors.clientNotFound();
    }
    if (ttl > 0) await this.redis.set(key, JSON.stringify(client), 'EX', ttl);
    return client;
  }

  /**
   * Reads the configuration fresh (bypassing the cache) and refreshes it. Used when a transaction is
   * created, the login page opens and a user signs in, so an added or removed origin, callback or status
   * change applies at once.
   */
  async getFresh(clientId: unknown): Promise<FederationClientConfig> {
    if (typeof clientId === 'string' && CLIENT_ID_PATTERN.test(clientId)) await this.invalidate(clientId);
    return this.get(clientId);
  }

  async invalidate(clientId: string): Promise<void> {
    await this.redis.del(RedisKeys.clientConfig(clientId));
  }
}
