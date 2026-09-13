import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { Errors } from '@common/errors/domain-error';
import { currentCorrelationId } from '@common/logging/request-context';
import { sha256Hex } from '@common/utils/crypto.util';
import { queryOne } from '@core/database/sql';
import { AuthenticatedUser, IdentityType } from '@shared/types/auth.types';
import { PasswordHasher } from './password-hasher';

/** Row of the Authentication DB `users` table (ITS ID is the primary key; password_hash is scrypt). */
interface UserRow {
  its_id: string;
  identity_type: IdentityType;
  username: string;
  name: string | null;
  password_hash: string | null;
  status: 'ACTIVE' | 'LOCKED' | 'DISABLED';
  failed_login_count: number;
  locked_until: Date | null;
}

const COLUMNS = 'its_id, identity_type, username, name, password_hash, status, failed_login_count, locked_until';

export interface AttemptContext {
  ip: string;
  clientId: string | null;
}

export function normalizeIdentifier(identifier: string, type: IdentityType): string {
  const trimmed = identifier.trim();
  return type === 'NON_ITS' ? trimmed.toLowerCase() : trimmed;
}

export function identifierHash(identifier: string, type: IdentityType): string {
  return sha256Hex(`${type}:${normalizeIdentifier(identifier, type)}`);
}

function toUser(row: UserRow): AuthenticatedUser {
  return { id: row.its_id, itsId: row.its_id, identityType: row.identity_type, username: row.username, displayName: row.name };
}

/**
 * Verifies credentials against the Authentication DB `users` table.
 * Uniform failure (INVALID_CREDENTIALS) and equalised timing for unknown accounts;
 * account status is only revealed after a correct password.
 */
@Injectable()
export class CredentialService {
  private readonly logger = new Logger(CredentialService.name);
  readonly hasher = new PasswordHasher();

  constructor(
    @InjectDataSource() private readonly db: DataSource,
    private readonly config: AppConfig,
  ) {}

  async verify(identifier: string, type: IdentityType, password: string, ctx: AttemptContext): Promise<AuthenticatedUser> {
    const normalized = normalizeIdentifier(identifier, type);
    const idHash = identifierHash(identifier, type);
    const row = await queryOne<UserRow>(
      this.db,
      type === 'ITS'
        ? `SELECT ${COLUMNS} FROM users WHERE its_id = $1 AND identity_type = 'ITS'`
        : `SELECT ${COLUMNS} FROM users WHERE username = $1 AND identity_type = 'NON_ITS'`,
      [normalized],
    );

    if (!row || !row.password_hash) {
      await this.hasher.verify(password, await this.hasher.getDummyHash());
      await this.recordAttempt(idHash, null, ctx, false, 'INVALID_CREDENTIALS');
      throw Errors.invalidCredentials();
    }

    if (row.locked_until && new Date(row.locked_until).getTime() > Date.now()) {
      const retryAfter = Math.ceil((new Date(row.locked_until).getTime() - Date.now()) / 1000);
      await this.hasher.verify(password, row.password_hash);
      await this.recordAttempt(idHash, row.its_id, ctx, false, 'ACCOUNT_TEMPORARILY_LOCKED');
      throw Errors.tooManyAttempts(retryAfter);
    }

    const valid = await this.hasher.verify(password, row.password_hash);
    if (!valid) {
      await this.db.query(
        `UPDATE users SET
           failed_login_count = failed_login_count + 1,
           last_failed_login_at = now(),
           locked_until = CASE WHEN failed_login_count + 1 >= $2 THEN now() + make_interval(secs => $3) ELSE locked_until END
         WHERE its_id = $1`,
        [row.its_id, this.config.env.LOGIN_MAX_FAILURES_PER_IDENTIFIER, this.config.env.LOGIN_ACCOUNT_LOCK_SECONDS],
      );
      await this.recordAttempt(idHash, row.its_id, ctx, false, 'INVALID_CREDENTIALS');
      throw Errors.invalidCredentials();
    }

    if (row.status !== 'ACTIVE') {
      await this.recordAttempt(idHash, row.its_id, ctx, false, `ACCOUNT_${row.status}`);
      throw Errors.accountUnavailable();
    }

    await this.db.query(`UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE its_id = $1`, [row.its_id]);
    if (this.hasher.needsRehash(row.password_hash)) {
      const upgraded = await this.hasher.hash(password);
      await this.db.query(`UPDATE users SET password_hash = $2, password_algo = 'scrypt' WHERE its_id = $1`, [row.its_id, upgraded]);
    }
    await this.recordAttempt(idHash, row.its_id, ctx, true, null);
    return toUser(row);
  }

  /** Re-validates that a session's user may still sign in to applications (SSO continuation). */
  async getActiveUser(itsId: string): Promise<AuthenticatedUser | null> {
    const row = await queryOne<UserRow>(this.db, `SELECT ${COLUMNS} FROM users WHERE its_id = $1`, [itsId]);
    if (!row || row.status !== 'ACTIVE') return null;
    return toUser(row);
  }

  private async recordAttempt(idHash: string, itsId: string | null, ctx: AttemptContext, success: boolean, reason: string | null) {
    try {
      await this.db.query(
        `INSERT INTO auth_login_attempts (identifier_hash, its_id, client_id, ip_address, success, failure_reason, correlation_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [idHash, itsId, ctx.clientId, ctx.ip, success, reason, currentCorrelationId() ?? null],
      );
    } catch (error) {
      this.logger.error({ msg: 'login attempt write failed', err: error instanceof Error ? error.message : String(error) });
    }
  }
}
