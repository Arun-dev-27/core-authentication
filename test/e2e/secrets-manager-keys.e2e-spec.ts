import { DeleteSecretCommand, GetSecretValueCommand, ListSecretVersionIdsCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createLocalJWKSet, decodeProtectedHeader } from 'jose';
import { loadEnv } from '@config/configuration';
import { AssertionService } from '@modules/assertions/services/assertion.service';
import { SecretsManagerKeyProvider } from '@modules/keys/services/key-providers';
import { KeyStore } from '@modules/keys/services/key-store.service';
import { rotateKeyset, validateKeyset } from '@modules/keys/services/keyset';
import { CoreAssertionVerifier, MemoryReplayStore } from '../../examples/bu-reference-app/src/core-assertion-verifier';
import { createApp } from '../../src/bootstrap';

/**
 * RS256 private keyset stored in AWS Secrets Manager (LocalStack), public keys shared via JWKS.
 * Requires: docker compose up -d localstack auth-postgres auth-redis
 */

const ENDPOINT = process.env.LOCALSTACK_ENDPOINT ?? 'http://localhost:4566';
const REGION = 'ap-south-1';
const SECRET_ID = `miqaat/identity/test/signing-keys-${Date.now()}`;

let client: SecretsManagerClient;
let provider: SecretsManagerKeyProvider;
let app: NestFastifyApplication | undefined;

beforeAll(async () => {
  process.env.AWS_ACCESS_KEY_ID = 'test';
  process.env.AWS_SECRET_ACCESS_KEY = 'test';
  const health = await fetch(`${ENDPOINT}/_localstack/health`).then((r) => r.json()).catch(() => null);
  if (!health || !['available', 'running'].includes(health.services?.secretsmanager)) {
    throw new Error(`LocalStack Secrets Manager is not reachable at ${ENDPOINT}; run "docker compose up -d localstack"`);
  }
  client = new SecretsManagerClient({ region: REGION, endpoint: ENDPOINT });
  provider = new SecretsManagerKeyProvider(SECRET_ID, REGION, ENDPOINT);
});

afterAll(async () => {
  await app?.close();
  await client?.send(new DeleteSecretCommand({ SecretId: SECRET_ID, ForceDeleteWithoutRecovery: true })).catch(() => undefined);
});

describe('AWS Secrets Manager signing key provider', () => {
  it('reports a missing secret clearly', async () => {
    await expect(provider.load()).rejects.toThrow('not found');
  });

  it('creates the secret on first save and loads the private keyset back', async () => {
    const keys = rotateKeyset([], 'generate', { bits: 2048 });
    await provider.save(keys);

    const loaded = await provider.load();
    validateKeyset(loaded);
    expect(loaded.map((k) => [k.kid, k.status])).toEqual([[keys[0].kid, 'ACTIVE']]);

    const raw = await client.send(new GetSecretValueCommand({ SecretId: SECRET_ID }));
    expect(raw.SecretString).toContain('BEGIN PRIVATE KEY');
  });

  it('writes a new secret version for every rotation step', async () => {
    await provider.save(rotateKeyset(await provider.load(), 'stage', { bits: 2048 }));
    await provider.save(rotateKeyset(await provider.load(), 'promote'));

    const statuses = (await provider.load()).map((k) => k.status).sort();
    expect(statuses).toEqual(['ACTIVE', 'RETIRING']);

    const versions = await client.send(new ListSecretVersionIdsCommand({ SecretId: SECRET_ID }));
    const stages = (versions.Versions ?? []).flatMap((v) => v.VersionStages ?? []);
    expect(stages).toEqual(expect.arrayContaining(['AWSCURRENT', 'AWSPREVIOUS']));
  });

  it('Identity Federation loads keys from Secrets Manager, shares only public keys, and assertions verify via JWKS', async () => {
    process.env.SIGNING_KEY_PROVIDER = 'secretsmanager';
    process.env.SECRETS_MANAGER_SIGNING_KEYS_SECRET_ID = SECRET_ID;
    process.env.AWS_ENDPOINT_URL = ENDPOINT;
    process.env.AWS_REGION = REGION;
    const env = loadEnv();

    app = await createApp(env);
    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    expect(app.get(KeyStore).isReady()).toBe(true);
    const stored = await provider.load();
    const active = stored.find((k) => k.status === 'ACTIVE')!;

    const jwksRes = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    const jwks = jwksRes.json() as { keys: Record<string, unknown>[] };
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual(stored.map((k) => k.kid).sort());
    expect(jwksRes.body).not.toContain('PRIVATE KEY');
    for (const key of jwks.keys) {
      expect(Object.keys(key).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);
    }

    const issued = await app.get(AssertionService).issue({ itsId: '30337752', clientId: 'rms-web-dev', sid: 'sid_secretsmanager_test', transactionId: 'txn-sm-000001', authTime: Math.floor(Date.now() / 1000) });
    expect(decodeProtectedHeader(issued.assertion).kid).toBe(active.kid);

    const verifier = new CoreAssertionVerifier({
      issuer: new URL(env.ISSUER).origin,
      clientId: 'rms-web-dev',
      jwksUri: 'unused',
      replayStore: new MemoryReplayStore(),
      keyResolver: createLocalJWKSet(jwks as never),
    });
    await expect(verifier.verifyLoginAssertion(issued.assertion, { transactionId: 'txn-sm-000001' })).resolves.toMatchObject({ itsId: '30337752' });
  });
});
