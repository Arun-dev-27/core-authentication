import { Module } from '@nestjs/common';
import { AppConfig } from '@config/config.module';
import { createKeyProvider, SIGNING_KEY_PROVIDER } from './services/key-providers';
import { KeyStore } from './services/key-store.service';
import { WellKnownController } from './well-known.controller';

/**
 * Signing keys (private keyset from AWS Secrets Manager / SSM) and the protocol-fixed
 * /.well-known endpoints (JWKS, federation metadata). Not versioned by design.
 */
@Module({
  controllers: [WellKnownController],
  providers: [
    { provide: SIGNING_KEY_PROVIDER, inject: [AppConfig], useFactory: (config: AppConfig) => createKeyProvider(config.env) },
    KeyStore,
  ],
  exports: [KeyStore],
})
export class KeysModule {}
