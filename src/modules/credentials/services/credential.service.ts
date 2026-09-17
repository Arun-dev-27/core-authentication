import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { Errors } from '@common/errors/domain-error';
import { currentCorrelationId } from '@common/logging/request-context';
import { sha256Hex } from '@common/utils/crypto.util';
import { queryOne } from '@core/database/sql';
import { AuthenticatedUser, IdentityType } from '@shared/types/auth.types';
import { LegacyCredentialService } from './legacy-credential.service';
import { MhpEligibilityReason, checkMhpEligibility } from './mhp-eligibility';
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
  legacy_user_id: number | null;
  mhp_eligible: boolean;
  mhp_status_id: number | null;
  mhp_allow_login: boolean | null;
  mhp_synced_at: Date | null;
}

const COLUMNS =
  'its_id, identity_type, username, name, password_hash, status, failed_login_count, locked_until, ' +
  'legacy_user_id, mhp_eligible, mhp_status_id, mhp_allow_login, mhp_synced_at';

/**
 * Per-call policy, so the SAME verify() serves both flows without one changing the other.
 * Embedded Login (any login that ends in an RS256 client assertion) passes
 * requireMhpEligibility; portal login does not and behaves exactly as before.
 */
export interface VerifyPolicy {
  requireMhpEligibility: boolean;
  /**
   * 'scrypt'         verify against users.password_hash (the long-standing behaviour).
   * 'legacy-decrypt' decrypt MHP_User_Login.Password in MMS and compare it to the submitted
   *                  password, and nothing else. The local hash is not consulted at all.
   */
  passwordSource: 'scrypt' | 'legacy-decrypt';
}

const PORTAL_POLICY: VerifyPolicy = { requireMhpEligibility: false, passwordSource: 'scrypt' };

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
    private readonly legacy: LegacyCredentialService,
  ) {}

  async verify(
    identifier: string,
    type: IdentityType,
    password: string,
    ctx: AttemptContext,
    policy: VerifyPolicy = PORTAL_POLICY,
  ): Promise<AuthenticatedUser> {
    const normalized = normalizeIdentifier(identifier, type);
    const idHash = identifierHash(identifier, type);
    const row = await queryOne<UserRow>(
      this.db,
      type === 'ITS'
        ? `SELECT ${COLUMNS} FROM users WHERE its_id = $1 AND identity_type = 'ITS'`
        : `SELECT ${COLUMNS} FROM users WHERE username = $1 AND identity_type = 'NON_ITS'`,
      [normalized],
    );

    // Under 'legacy-decrypt' the only credential that counts is the MMS ciphertext, so a row with
    // no local hash is still a candidate. Under 'scrypt' a missing hash is still an outright reject.
    const usesLegacyPassword = policy.passwordSource === 'legacy-decrypt';
    if (!row || (!row.password_hash && !usesLegacyPassword)) {
      await this.hasher.verify(password, await this.hasher.getDummyHash());
      await this.recordAttempt(idHash, null, ctx, false, 'INVALID_CREDENTIALS');
      throw Errors.invalidCredentials();
    }

    // MHP eligibility gate, ahead of the password exactly as the flow specifies. The client sees
    // the same INVALID_CREDENTIALS as an unknown account, and a dummy hash keeps the timing of a
    // rejected-but-existing account indistinguishable - otherwise this endpoint would answer
    // "is this ITS ID eligible?" for anyone who asked.
    if (policy.requireMhpEligibility && this.config.env.MHP_ELIGIBILITY_REQUIRED) {
      const gate = checkMhpEligibility(
        {
          mhpEligible: row.mhp_eligible,
          mhpStatusId: row.mhp_status_id,
          mhpAllowLogin: row.mhp_allow_login,
          mhpSyncedAt: row.mhp_synced_at,
        },
        this.config.env.MHP_ACTIVE_STATUS_ID,
      );
      if (!gate.ok) {
        await this.hasher.verify(password, row.password_hash ?? (await this.hasher.getDummyHash()));
        await this.recordAttempt(idHash, row.its_id, ctx, false, gate.reason satisfies MhpEligibilityReason);
        throw Errors.invalidCredentials();
      }
    }

    if (row.locked_until && new Date(row.locked_until).getTime() > Date.now()) {
      const retryAfter = Math.ceil((new Date(row.locked_until).getTime() - Date.now()) / 1000);
      await this.hasher.verify(password, row.password_hash ?? (await this.hasher.getDummyHash()));
      await this.recordAttempt(idHash, row.its_id, ctx, false, 'ACCOUNT_TEMPORARILY_LOCKED');
      throw Errors.tooManyAttempts(retryAfter);
    }

    let valid: boolean;
    if (usesLegacyPassword) {
      // Embedded Login: decrypt MHP_User_Login.Password and compare, and nothing else. The legacy
      // row is addressed by legacy_user_id when the account carries one, otherwise by the ITS ID
      // itself - migrate:legacy writes its_id = MHP_User_Login.UserId, so the two are the same
      // number for every account that came from MMS.
      const legacyUserId = row.legacy_user_id ?? (/^\d+$/.test(row.its_id) ? Number(row.its_id) : null);
      if (legacyUserId === null) {
        // No way to address a legacy row, so there is no password to compare against.
        await this.hasher.verify(password, await this.hasher.getDummyHash());
        await this.recordAttempt(idHash, row.its_id, ctx, false, 'LEGACY_ACCOUNT_UNRESOLVABLE');
        throw Errors.invalidCredentials();
      }
      if (!this.legacy.enabled) {
        // Fails closed rather than silently falling back to the hash: a deployment that cannot
        // reach MMS must not quietly authenticate Embedded Login by another route.
        await this.hasher.verify(password, await this.hasher.getDummyHash());
        await this.recordAttempt(idHash, row.its_id, ctx, false, 'LEGACY_SOURCE_UNAVAILABLE');
        throw Errors.invalidCredentials();
      }
      valid = await this.legacy.verify(legacyUserId, password);
    } else {
      valid = await this.hasher.verify(password, row.password_hash ?? (await this.hasher.getDummyHash()));
      if (!row.password_hash) valid = false;
    }
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
    if (usesLegacyPassword) {
      // MMS stays the source of truth for this path, so the local hash is deliberately left alone.
      await this.recordAttempt(idHash, row.its_id, ctx, true, 'LEGACY_PASSWORD_VERIFIED');
      return toUser(row);
    }
    if (row.password_hash && this.hasher.needsRehash(row.password_hash)) {
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
