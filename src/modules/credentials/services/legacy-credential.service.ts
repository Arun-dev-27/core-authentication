import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { decrypt } from './legacy-decrypt';

/**
 * Decrypt-and-compare against the live legacy MMS password, for accounts whose local scrypt hash
 * does not match (typically: the password was changed in MMS after the last sync, or the account
 * was never migrated).
 *
 * Off unless LEGACY_LOGIN_ENABLED is set, and refused outright in production by config validation,
 * because MHP_User_Login.Password is reversible by design. The connection is created lazily on the
 * first legacy fallback and is opened READ-ONLY; nothing here ever writes to MMS.
 *
 * Why this reads MMS rather than a mirrored copy: mirroring the ciphertext into the Authentication
 * DB would put a reversible credential next to the scrypt hash that replaced it, which is strictly
 * weaker than storing nothing. The mirrored `mhp_*` flags are safe to copy; the password is not.
 */
@Injectable()
export class LegacyCredentialService implements OnModuleDestroy {
  private readonly logger = new Logger(LegacyCredentialService.name);
  private legacy: DataSource | null = null;
  private connecting: Promise<DataSource | null> | null = null;

  constructor(private readonly config: AppConfig) {}

  get enabled(): boolean {
    return this.config.env.LEGACY_LOGIN_ENABLED && Boolean(this.config.env.LEGACY_DB_HOST);
  }

  async onModuleDestroy(): Promise<void> {
    if (this.legacy?.isInitialized) await this.legacy.destroy();
    this.legacy = null;
  }

  /**
   * True when `password` matches the legacy ciphertext for this legacy user id.
   *
   * Returns false for every "cannot tell" case (disabled, unreachable, no row, undecryptable) so a
   * caller can only ever be more restrictive by consulting it. The ciphertext and the decrypted
   * plaintext are never logged or returned.
   */
  async verify(legacyUserId: number, password: string): Promise<boolean> {
    if (!this.enabled) return false;
    const db = await this.connect();
    if (!db) return false;

    let rows: { Password: string | null }[];
    try {
      rows = (await db.query('SELECT TOP 1 Password FROM MHP_User_Login WHERE UserId = @0', [legacyUserId])) as {
        Password: string | null;
      }[];
    } catch (error) {
      // A legacy outage must not become a login outage for everyone else: fall through as "no match".
      this.logger.warn({ msg: 'legacy password lookup failed', legacy_user_id: legacyUserId, err: message(error) });
      return false;
    }

    const ciphertext = rows[0]?.Password;
    if (!ciphertext) return false;
    const plaintext = decrypt(ciphertext);
    if (!plaintext) return false;
    return timingSafeStringEquals(plaintext, password);
  }

  private async connect(): Promise<DataSource | null> {
    if (this.legacy?.isInitialized) return this.legacy;
    // Concurrent logins must not each open their own pool.
    this.connecting ??= this.initialize();
    try {
      return await this.connecting;
    } finally {
      this.connecting = null;
    }
  }

  private async initialize(): Promise<DataSource | null> {
    const env = this.config.env;
    const source = new DataSource({
      type: 'mssql',
      host: env.LEGACY_DB_HOST,
      port: env.LEGACY_DB_PORT,
      username: env.LEGACY_DB_USER,
      password: env.LEGACY_DB_PASSWORD,
      database: env.LEGACY_DB_NAME,
      synchronize: false,
      migrationsRun: false,
      logging: false,
      entities: [],
      options: { encrypt: env.LEGACY_DB_ENCRYPT, trustServerCertificate: true, readOnlyIntent: true },
      extra: { requestTimeout: 5_000, connectionTimeout: 5_000 },
    });
    try {
      await source.initialize();
      this.logger.log({ msg: 'legacy MMS connection established (read-only intent)', database: env.LEGACY_DB_NAME });
      this.legacy = source;
      return source;
    } catch (error) {
      this.logger.warn({ msg: 'legacy MMS unavailable; legacy password fallback inactive', err: message(error) });
      return null;
    }
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Length-independent comparison, so a failed legacy compare leaks nothing about the stored value. */
function timingSafeStringEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
