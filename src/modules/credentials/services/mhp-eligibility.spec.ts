import { MhpFlags, checkMhpEligibility } from './mhp-eligibility';

const ACTIVE = 3;
const passing: MhpFlags = { mhpEligible: true, mhpStatusId: ACTIVE, mhpAllowLogin: true, mhpSyncedAt: new Date() };

describe('checkMhpEligibility', () => {
  it('passes a user who is eligible, synced, active and allowed to log in', () => {
    expect(checkMhpEligibility(passing, ACTIVE)).toEqual({ ok: true });
  });

  it('refuses a user absent from MHP_User_Login_Eligible', () => {
    expect(checkMhpEligibility({ ...passing, mhpEligible: false }, ACTIVE)).toEqual({ ok: false, reason: 'MHP_NOT_ELIGIBLE' });
  });

  it('refuses a user that has never been synced, even if flagged eligible', () => {
    expect(checkMhpEligibility({ ...passing, mhpSyncedAt: null }, ACTIVE)).toEqual({ ok: false, reason: 'MHP_ACCOUNT_MISSING' });
  });

  it.each([
    ['a non-active status', 1],
    ['status 0', 0],
    ['status 4', 4],
  ])('refuses %s', (_label, status) => {
    expect(checkMhpEligibility({ ...passing, mhpStatusId: status as number }, ACTIVE)).toEqual({ ok: false, reason: 'MHP_STATUS_NOT_ACTIVE' });
  });

  it('treats an unknown (null) status as not active rather than not-checked', () => {
    expect(checkMhpEligibility({ ...passing, mhpStatusId: null }, ACTIVE)).toEqual({ ok: false, reason: 'MHP_STATUS_NOT_ACTIVE' });
  });

  it.each([
    ['Allow_Login = 0', false],
    ['Allow_Login not set', null],
  ])('refuses %s', (_label, allow) => {
    expect(checkMhpEligibility({ ...passing, mhpAllowLogin: allow as boolean | null }, ACTIVE)).toEqual({
      ok: false,
      reason: 'MHP_LOGIN_NOT_ALLOWED',
    });
  });

  it('honours a configured active status other than 3', () => {
    expect(checkMhpEligibility({ ...passing, mhpStatusId: 7 }, 7)).toEqual({ ok: true });
    expect(checkMhpEligibility(passing, 7)).toEqual({ ok: false, reason: 'MHP_STATUS_NOT_ACTIVE' });
  });

  // The order is part of the contract: the audit log must name the FIRST thing that was wrong,
  // so a rejection can be explained to an operator without guessing.
  it('reports the earliest failing check when several are wrong at once', () => {
    const allWrong: MhpFlags = { mhpEligible: false, mhpStatusId: 1, mhpAllowLogin: false, mhpSyncedAt: null };
    expect(checkMhpEligibility(allWrong, ACTIVE)).toEqual({ ok: false, reason: 'MHP_NOT_ELIGIBLE' });
    expect(checkMhpEligibility({ ...allWrong, mhpEligible: true }, ACTIVE)).toEqual({ ok: false, reason: 'MHP_ACCOUNT_MISSING' });
    expect(checkMhpEligibility({ ...allWrong, mhpEligible: true, mhpSyncedAt: new Date() }, ACTIVE)).toEqual({
      ok: false,
      reason: 'MHP_STATUS_NOT_ACTIVE',
    });
    expect(checkMhpEligibility({ ...allWrong, mhpEligible: true, mhpSyncedAt: new Date(), mhpStatusId: ACTIVE }, ACTIVE)).toEqual({
      ok: false,
      reason: 'MHP_LOGIN_NOT_ALLOWED',
    });
  });
});
