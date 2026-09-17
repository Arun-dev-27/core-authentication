/**
 * The legacy MMS eligibility gate for Embedded Login, as a pure decision.
 *
 * Checked in the order the flow specifies, and short-circuiting on the first failure:
 *
 *   1. eligible      row present in MHP_User_Login_Eligible
 *   2. account       the legacy login account exists / was synced at all
 *   3. status        mumin_mast_Cal_grades.Status_ID = MHP_ACTIVE_STATUS_ID (3)
 *   4. allow login   MHP_User_Login.Allow_Login is true
 *
 * The password is deliberately NOT part of this: credential verification happens after the gate,
 * so this stays a pure function over mirrored flags and can be tested without a database.
 *
 * Every outcome is a distinct reason for the audit log, but the caller must surface a single
 * uniform error to the client. Reporting "not eligible" before a password has been checked would
 * otherwise turn the login endpoint into an eligibility oracle for any ITS ID.
 */

export type MhpEligibilityReason =
  | 'MHP_NOT_ELIGIBLE'
  | 'MHP_ACCOUNT_MISSING'
  | 'MHP_STATUS_NOT_ACTIVE'
  | 'MHP_LOGIN_NOT_ALLOWED';

/** The mirrored MMS flags, as stored on the `users` row. */
export interface MhpFlags {
  mhpEligible: boolean;
  mhpStatusId: number | null;
  mhpAllowLogin: boolean | null;
  mhpSyncedAt: Date | null;
}

export type MhpEligibilityResult = { ok: true } | { ok: false; reason: MhpEligibilityReason };

export function checkMhpEligibility(flags: MhpFlags, activeStatusId: number): MhpEligibilityResult {
  // 1. Eligibility list first, exactly as the existing migration selects on it.
  if (!flags.mhpEligible) return { ok: false, reason: 'MHP_NOT_ELIGIBLE' };

  // 2. An account that has never been synced has no status or Allow_Login to judge, and must not
  //    be waved through on the strength of the eligibility flag alone.
  if (flags.mhpSyncedAt === null) return { ok: false, reason: 'MHP_ACCOUNT_MISSING' };

  // 3. Status_ID = 3. A null status is "unknown", not "active".
  if (flags.mhpStatusId !== activeStatusId) return { ok: false, reason: 'MHP_STATUS_NOT_ACTIVE' };

  // 4. Allow_Login. Null is a legacy "not set", which is not consent to log in.
  if (flags.mhpAllowLogin !== true) return { ok: false, reason: 'MHP_LOGIN_NOT_ALLOWED' };

  return { ok: true };
}
