import { KeyObject, createPrivateKey } from 'node:crypto';
import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { calculateJwkThumbprint } from 'jose';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { Errors } from '@common/errors/domain-error';
import { SIGNING_KEY_PROVIDER, SigningKeyProvider } from './key-providers';
import { PublicJwk, StoredSigningKey, publishedKeys, toPublicJwk, validateKeyset } from './keyset';

interface LoadedKeys {
  signing: { kid: string; key: KeyObject };
  jwks: { keys: PublicJwk[] };
  fingerprint: string;
  loadedAt: Date;
}

/**
 * Holds the ACTIVE private key in memory (never logged, never serialised) and the public JWKS.
 * Periodically reloads from the provider so rotations propagate to every pod without restarts.
 * On reload failure the last known-good keyset is kept.
 */
@Injectable()
export class KeyStore implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(KeyStore.name);
  private state: LoadedKeys | null = null;
  private timer?: NodeJS.Timeout;

  constructor(
    @Inject(SIGNING_KEY_PROVIDER) private readonly provider: SigningKeyProvider,
    private readonly config: AppConfig,
    @InjectDataSource() private readonly db: DataSource,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.reload();
    this.timer = setInterval(() => {
      this.reload().catch((error: unknown) =>
        this.logger.error({ msg: 'signing key reload failed; keeping last known-good keyset', err: error instanceof Error ? error.message : String(error) }),
      );
    }, this.config.env.KEY_REFRESH_INTERVAL_SECONDS * 1000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async reload(): Promise<void> {
    const keys = await this.provider.load();
    validateKeyset(keys);
    const fingerprint = keys.map((k) => `${k.kid}:${k.status}`).sort().join(',');
    if (this.state?.fingerprint === fingerprint) return;

    const active = keys.find((k) => k.status === 'ACTIVE')!;
    this.state = {
      signing: { kid: active.kid, key: createPrivateKey(active.privateKeyPem) },
      jwks: { keys: publishedKeys(keys).map(toPublicJwk) },
      fingerprint,
      loadedAt: new Date(),
    };
    this.logger.log({ msg: 'signing keyset loaded', provider: this.provider.description, active_kid: active.kid, published: this.state.jwks.keys.map((k) => k.kid) });
    await this.recordMetadata(keys);
  }

  signingKey(): { kid: string; key: KeyObject } {
    if (!this.state) throw Errors.dependencyUnavailable();
    return this.state.signing;
  }

  jwks(): { keys: PublicJwk[] } {
    return this.state?.jwks ?? { keys: [] };
  }

  isReady(): boolean {
    return this.state !== null;
  }

  private async recordMetadata(keys: StoredSigningKey[]): Promise<void> {
    try {
      for (const key of keys) {
        const thumbprint = key.status === 'RETIRED' ? null : await calculateJwkThumbprint(toPublicJwk(key));
        await this.db.query(
          `INSERT INTO signing_key_metadata (kid, alg, status, jwk_thumbprint) VALUES ($1, $2, $3, $4)
           ON CONFLICT (kid) DO UPDATE SET
             status = EXCLUDED.status,
             jwk_thumbprint = COALESCE(EXCLUDED.jwk_thumbprint, signing_key_metadata.jwk_thumbprint),
             status_changed_at = CASE WHEN signing_key_metadata.status <> EXCLUDED.status THEN now() ELSE signing_key_metadata.status_changed_at END`,
          [key.kid, key.alg, key.status, thumbprint],
        );
      }
    } catch (error) {
      this.logger.warn({ msg: 'could not record signing key metadata', err: error instanceof Error ? error.message : String(error) });
    }
  }
}
