import { createPrivateKey } from 'node:crypto';
import { AppConfig } from '@config/config.module';
import { Env } from '@config/configuration';
import { AssertionService } from '@modules/assertions/services/assertion.service';
import { createKeyProvider } from '@modules/keys/services/key-providers';
import type { KeyStore } from '@modules/keys/services/key-store.service';
import { validateKeyset } from '@modules/keys/services/keyset';
import { AuthzClient } from './services/authz-client.service';

/**
 * AuthzClient for CLI scripts (legacy migration, dev seeding) running outside the Nest container.
 * Loads the ACTIVE signing key from the configured provider (Secrets Manager / SSM / file) so the
 * script authenticates exactly like the service - with an RS256 service token, never an API key.
 */
export async function createStandaloneAuthzClient(env: Env): Promise<AuthzClient> {
  const keys = await createKeyProvider(env).load();
  validateKeyset(keys);
  const active = keys.find((k) => k.status === 'ACTIVE')!;
  const keyStore = { signingKey: () => ({ kid: active.kid, key: createPrivateKey(active.privateKeyPem) }) } as unknown as KeyStore;
  const config = new AppConfig(env);
  return new AuthzClient(config, new AssertionService(keyStore, config, undefined as never));
}
