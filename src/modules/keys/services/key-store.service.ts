import { KeyObject, createPrivateKey } from 'node:crypto';
import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { calculateJwkThumbprint } from 'jose';
import { Repository } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { Errors } from '@common/errors/domain-error';
import { SigningKeyMetadata } from '@core/database/entities/auth/signing-key-metadata.entity';
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
    @InjectRepository(SigningKeyMetadata) private readonly metadata: Repository<SigningKeyMetadata>,
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
        const existing = await this.metadata.findOneBy({ kid: key.kid });
        if (!existing) {
          await this.metadata.insert({ kid: key.kid, alg: key.alg, status: key.status, jwkThumbprint: thumbprint });
        } else if (existing.status !== key.status || (thumbprint && existing.jwkThumbprint !== thumbprint)) {
          await this.metadata.update(
            { kid: key.kid },
            {
              status: key.status,
              jwkThumbprint: thumbprint ?? existing.jwkThumbprint,
              ...(existing.status !== key.status ? { statusChangedAt: () => 'now()' } : {}),
              updatedAt: () => 'now()',
            },
          );
        }
      }
    } catch (error) {
      this.logger.warn({ msg: 'could not record signing key metadata', err: error instanceof Error ? error.message : String(error) });
    }
  }
}
