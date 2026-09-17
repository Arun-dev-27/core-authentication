import { Injectable, Logger } from '@nestjs/common';
import { AppConfig } from '@config/config.module';
import { Errors } from '@common/errors/domain-error';
import { currentCorrelationId } from '@common/logging/request-context';
import { safeEqual, sha256Hex } from '@common/utils/crypto.util';
import { IdentityAccountRepository, type LoginAccount } from '@core/database/repositories/identity-account.repository';
import { LoginAttemptRepository } from '@core/database/repositories/login-attempt.repository';
import { AuthenticatedUser, IdentityType } from '@shared/types/auth.types';
import { decrypt } from './legacy-decrypt';

/**
 * Legacy tables -> identity_db entities:
 *   MHP_USER_LOGIN          -> IdentityUser  (users)
 *   mumin_mast_cal_grades   -> MuminMaster   (mumin_master)
 *   MHP_User_Login_Eligible -> UserEligible  (user_eligible)
 * The queries themselves live in IdentityAccountRepository.
 */

/** mumin_id is a PostgreSQL integer. Anything else cannot be an account, and must not reach the query as a cast error. */
const MUMIN_ID = /^[0-9]{1,10}$/;
const INT4_MAX = 2_147_483_647;

/** Reason written to auth_login_attempts for a wrong password; also what the durable lockout counts. */
const WRONG_PASSWORD = 'INVALID_PASSWORD';

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

/** "10110101" -> 10110101; null when it cannot be a mumin_id. Leading zeros are not significant for an integer column. */
export function toMuminId(identifier: string): number | null {
  const trimmed = identifier.trim();
  if (!MUMIN_ID.test(trimmed)) return null;
  const value = Number(trimmed);
  return value > 0 && value <= INT4_MAX ? value : null;
}

function toUser(row: LoginAccount): AuthenticatedUser {
  const itsId = String(row.muminId);
  return { id: itsId, itsId, identityType: 'ITS', username: itsId, displayName: row.fullname?.trim() || null };
}

/**
 * Authenticates an existing ITS member against identity_db - the synced login tables are read, never written.
 *
 * Order of checks, and why it differs from the legacy page:
 *   1. account    users JOIN mumin_master with Status_ID = 3 (not found / inactive -> INVALID_CREDENTIALS)
 *   2. lockout    durable, from auth_login_attempts
 *   3. password   Decrypt(users.password) compared with the submitted password
 *   4. Allow_Login ISNULL(Allow_Login, 1)                    -> ACCOUNT_UNAVAILABLE
 *   5. eligible   count(user_eligible) > 0 when the login restriction is on -> LOGIN_RESTRICTED + configured message
 *
 * The legacy page checks eligibility before the password. Here the restriction message is shown only after a
 * correct password, so the endpoint cannot be used to learn which ITS IDs are eligible or allowed to log in.
 * The account still gets exactly the same outcome.
 */
@Injectable()
export class CredentialService {
  private readonly logger = new Logger(CredentialService.name);

  constructor(
    private readonly accounts: IdentityAccountRepository,
    private readonly attempts: LoginAttemptRepository,
    private readonly config: AppConfig,
  ) {}

  async verify(identifier: string, type: IdentityType, password: string, ctx: AttemptContext): Promise<AuthenticatedUser> {
    const idHash = identifierHash(identifier, type);
    // identity_db only holds ITS members; there is no Non-ITS credential to check.
    const muminId = type === 'ITS' ? toMuminId(identifier) : null;
    if (muminId === null) {
      await this.recordAttempt(idHash, null, ctx, false, type === 'ITS' ? 'MALFORMED_ITS_ID' : 'IDENTITY_TYPE_NOT_SUPPORTED');
      throw Errors.invalidCredentials();
    }
    const itsId = String(muminId);

    const row = await this.accounts.findLoginAccount(muminId, this.config.env.MHP_ACTIVE_STATUS_ID);
    if (!row || !row.password) {
      // Same decrypt-and-compare work as a real account, so an unknown ID is not faster to reject.
      safeEqual(decrypt('00'), password);
      await this.recordAttempt(idHash, itsId, ctx, false, row ? 'NO_PASSWORD' : 'ACCOUNT_NOT_FOUND_OR_INACTIVE');
      throw Errors.invalidCredentials();
    }

    const retryAfter = await this.lockedFor(itsId);
    if (retryAfter > 0) {
      await this.recordAttempt(idHash, itsId, ctx, false, 'ACCOUNT_TEMPORARILY_LOCKED');
      throw Errors.tooManyAttempts(retryAfter);
    }

    const plaintext = decrypt(row.password);
    if (!plaintext || !safeEqual(plaintext, password)) {
      await this.recordAttempt(idHash, itsId, ctx, false, WRONG_PASSWORD);
      throw Errors.invalidCredentials();
    }

    if (!row.allowLogin) {
      await this.recordAttempt(idHash, itsId, ctx, false, 'LOGIN_NOT_ALLOWED');
      throw Errors.accountUnavailable();
    }

    if (this.config.env.LOGIN_RESTRICTION_ENABLED && !(await this.accounts.isEligible(muminId))) {
      await this.recordAttempt(idHash, itsId, ctx, false, 'NOT_ELIGIBLE');
      throw Errors.loginRestricted(this.config.env.LOGIN_RESTRICTION_MESSAGE);
    }

    await this.recordAttempt(idHash, itsId, ctx, true, null);
    return toUser(row);
  }

  /**
   * Re-validates that a session's user may still sign in to applications (SSO continuation): same account,
   * status, Allow_Login and eligibility rules as a password login, without the password.
   */
  async getActiveUser(itsId: string): Promise<AuthenticatedUser | null> {
    const muminId = toMuminId(itsId);
    if (muminId === null) return null;
    const row = await this.accounts.findLoginAccount(muminId, this.config.env.MHP_ACTIVE_STATUS_ID);
    if (!row || !row.password || !row.allowLogin) return null;
    if (this.config.env.LOGIN_RESTRICTION_ENABLED && !(await this.accounts.isEligible(muminId))) return null;
    return toUser(row);
  }

  /**
   * Seconds until this account may try again, or 0. Wrong-password attempts are counted from
   * auth_login_attempts (this service's own table), since the synced users table must not be written to.
   * A successful login resets the count.
   */
  private async lockedFor(itsId: string): Promise<number> {
    const env = this.config.env;
    const { failures, secondsSinceLast } = await this.attempts.recentFailures(itsId, WRONG_PASSWORD, env.LOGIN_ACCOUNT_LOCK_SECONDS);
    if (failures < env.LOGIN_MAX_FAILURES_PER_IDENTIFIER) return 0;
    return Math.max(1, Math.ceil(env.LOGIN_ACCOUNT_LOCK_SECONDS - (secondsSinceLast ?? 0)));
  }

  private async recordAttempt(idHash: string, itsId: string | null, ctx: AttemptContext, success: boolean, reason: string | null) {
    try {
      await this.attempts.record({
        identifierHash: idHash,
        itsId,
        clientId: ctx.clientId,
        ipAddress: ctx.ip,
        success,
        failureReason: reason,
        correlationId: currentCorrelationId() ?? null,
      });
    } catch (error) {
      this.logger.error({ msg: 'login attempt write failed', err: error instanceof Error ? error.message : String(error) });
    }
  }
}
