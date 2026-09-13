import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { CreateSecretCommand, GetSecretValueCommand, PutSecretValueCommand, ResourceNotFoundException, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { GetParametersByPathCommand, ParameterType, PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import type { Env } from '@config/configuration';
import { KeysetError, StoredSigningKey } from './keyset';

export const SIGNING_KEY_PROVIDER = Symbol('SIGNING_KEY_PROVIDER');

/**
 * Source of the RS256 keyset. Private keys live ONLY in the provider (AWS Secrets Manager / SSM in
 * production) and in Identity Federation process memory. Public keys are shared exclusively through
 * GET /.well-known/jwks.json.
 */
export interface SigningKeyProvider {
  readonly description: string;
  load(): Promise<StoredSigningKey[]>;
  save(keys: StoredSigningKey[]): Promise<void>;
}

export function createKeyProvider(env: Env): SigningKeyProvider {
  switch (env.SIGNING_KEY_PROVIDER) {
    case 'secretsmanager':
      return new SecretsManagerKeyProvider(env.SECRETS_MANAGER_SIGNING_KEYS_SECRET_ID, env.AWS_REGION, env.AWS_ENDPOINT_URL, env.SIGNING_KEYS_KMS_KEY_ID);
    case 'ssm':
      return new SsmKeyProvider(env.SSM_SIGNING_KEYS_PATH, env.AWS_REGION, env.AWS_ENDPOINT_URL, env.SIGNING_KEYS_KMS_KEY_ID);
    default:
      return new FileKeyProvider(env.SIGNING_KEYS_FILE);
  }
}

/**
 * AWS Secrets Manager provider (recommended).
 *
 * One secret holds the whole keyset:  <SECRETS_MANAGER_SIGNING_KEYS_SECRET_ID>
 *   SecretString = {"keys":[{"kid","alg","status","createdAt",...,"privateKeyPem"}]}
 *
 * Every rotation step writes a new secret version (AWSCURRENT); the previous keyset remains
 * retrievable as AWSPREVIOUS for audit / emergency rollback. Encrypted with a customer-managed KMS key.
 * Runtime IAM (IRSA): secretsmanager:GetSecretValue + kms:Decrypt on this secret only.
 */
export class SecretsManagerKeyProvider implements SigningKeyProvider {
  private readonly client: SecretsManagerClient;

  constructor(
    private readonly secretId: string,
    region: string,
    endpoint?: string,
    private readonly kmsKeyId?: string,
  ) {
    this.client = new SecretsManagerClient({ region, ...(endpoint ? { endpoint } : {}) });
  }

  get description() {
    return `secretsmanager:${this.secretId}`;
  }

  async load(): Promise<StoredSigningKey[]> {
    try {
      const result = await this.client.send(new GetSecretValueCommand({ SecretId: this.secretId }));
      if (!result.SecretString) throw new KeysetError(`secret ${this.secretId} has no SecretString`);
      const parsed = JSON.parse(result.SecretString) as { keys?: StoredSigningKey[] };
      return parsed.keys ?? [];
    } catch (error) {
      if (error instanceof ResourceNotFoundException) {
        throw new KeysetError(`signing key secret ${this.secretId} not found; run "npm run keys:generate"`);
      }
      throw error;
    }
  }

  async save(keys: StoredSigningKey[]): Promise<void> {
    const SecretString = JSON.stringify({ keys });
    try {
      await this.client.send(new PutSecretValueCommand({ SecretId: this.secretId, SecretString }));
    } catch (error) {
      if (!(error instanceof ResourceNotFoundException)) throw error;
      await this.client.send(
        new CreateSecretCommand({
          Name: this.secretId,
          SecretString,
          KmsKeyId: this.kmsKeyId,
          Description: 'Miqaat Identity Federation RS256 signing keyset (private keys). Public keys are published via JWKS.',
          Tags: [
            { Key: 'service', Value: 'miqaat-identity-federation' },
            { Key: 'data-classification', Value: 'secret' },
          ],
        }),
      );
    }
  }
}

/**
 * AWS SSM Parameter Store provider (alternative).
 * One SecureString per key:  <SSM_SIGNING_KEYS_PATH>/<kid>
 */
export class SsmKeyProvider implements SigningKeyProvider {
  private readonly client: SSMClient;

  constructor(
    private readonly path: string,
    region: string,
    endpoint?: string,
    private readonly kmsKeyId?: string,
  ) {
    this.client = new SSMClient({ region, ...(endpoint ? { endpoint } : {}) });
  }

  get description() {
    return `ssm:${this.path}`;
  }

  async load(): Promise<StoredSigningKey[]> {
    const keys: StoredSigningKey[] = [];
    let nextToken: string | undefined;
    do {
      const page = await this.client.send(
        new GetParametersByPathCommand({ Path: this.path, Recursive: false, WithDecryption: true, NextToken: nextToken, MaxResults: 10 }),
      );
      for (const parameter of page.Parameters ?? []) {
        if (!parameter.Value) continue;
        if (parameter.Type !== ParameterType.SECURE_STRING) {
          throw new KeysetError(`SSM parameter ${parameter.Name} must be a SecureString`);
        }
        keys.push(JSON.parse(parameter.Value) as StoredSigningKey);
      }
      nextToken = page.NextToken;
    } while (nextToken);
    return keys;
  }

  async save(keys: StoredSigningKey[]): Promise<void> {
    for (const key of keys) {
      await this.client.send(
        new PutParameterCommand({
          Name: `${this.path}/${key.kid}`,
          Value: JSON.stringify(key),
          Type: ParameterType.SECURE_STRING,
          KeyId: this.kmsKeyId,
          Overwrite: true,
          Tier: 'Advanced',
          Description: `Miqaat Identity Federation RS256 signing key (${key.status})`,
        }),
      );
    }
  }
}

/**
 * LOCAL DEVELOPMENT / TESTS ONLY. Keyset JSON file outside source control (.keys/ is git-ignored).
 * Production configuration validation refuses this provider.
 */
export class FileKeyProvider implements SigningKeyProvider {
  private readonly path: string;

  constructor(path: string) {
    this.path = resolve(path);
  }

  get description() {
    return `file:${this.path}`;
  }

  async load(): Promise<StoredSigningKey[]> {
    if (!existsSync(this.path)) {
      throw new KeysetError(`signing keyset not found at ${this.path}; run "npm run keys:generate"`);
    }
    const parsed = JSON.parse(readFileSync(this.path, 'utf8')) as { keys?: StoredSigningKey[] };
    return parsed.keys ?? [];
  }

  async save(keys: StoredSigningKey[]): Promise<void> {
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify({ keys }, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
    try {
      chmodSync(this.path, 0o600);
    } catch {
      /* best effort on Windows */
    }
  }
}
