import { AppConfig } from '@config/config.module';
import type { Env } from '@config/configuration';
import type { LoginAccount } from '@core/database/repositories/identity-account.repository';
import { CredentialService, toMuminId } from './credential.service';

const ITS = '10110101';
const PASSWORD = 'Test@001';
/** Legacy reversible form of PASSWORD, as identity_db users.password stores it. */
const CIPHERTEXT = 'z&+K|kYu1ta@CdvY';
const CTX = { ip: '203.0.113.7', clientId: 'rms-web-dev' };
const RESTRICTED = 'Not eligible - contact your Jamaat office';

const config = (over: Partial<Env> = {}) =>
  new AppConfig({
    NODE_ENV: 'test',
    ISSUER: 'https://identity.example.com',
    LOGIN_RESTRICTION_ENABLED: true,
    LOGIN_RESTRICTION_MESSAGE: RESTRICTED,
    MHP_ACTIVE_STATUS_ID: 3,
    LOGIN_MAX_FAILURES_PER_IDENTIFIER: 5,
    LOGIN_ACCOUNT_LOCK_SECONDS: 900,
    ...over,
  } as Env);

const account = (over: Partial<LoginAccount> = {}): LoginAccount => ({
  personId: '696625',
  muminId: 10110101,
  statusId: 3,
  status: 'Active',
  fullname: 'Test Member 101',
  password: CIPHERTEXT,
  allowLogin: true,
  ...over,
});

function build(opts: { account?: LoginAccount | null; eligible?: boolean; failures?: number; env?: Partial<Env> } = {}) {
  const accounts = {
    findLoginAccount: jest.fn(async () => (opts.account === null ? null : (opts.account ?? account()))),
    isEligible: jest.fn(async () => opts.eligible ?? true),
  };
  const attempts = {
    record: jest.fn(async () => undefined),
    recentFailures: jest.fn(async () => ({ failures: opts.failures ?? 0, secondsSinceLast: 10 })),
  };
  return { svc: new CredentialService(accounts as never, attempts as never, config(opts.env)), accounts, attempts };
}

const reasonsOf = (attempts: { record: jest.Mock }) => attempts.record.mock.calls.map(([a]) => (a as { failureReason: string | null }).failureReason);

describe('CredentialService (existing identity_db, via repositories)', () => {
  it('authenticates an existing, active, eligible user by decrypting users.password', async () => {
    const { svc, attempts } = build();
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX)).resolves.toEqual({
      id: ITS,
      itsId: ITS,
      identityType: 'ITS',
      username: ITS,
      displayName: 'Test Member 101',
    });
    expect(reasonsOf(attempts)).toEqual([null]);
    expect(attempts.record).toHaveBeenCalledWith(expect.objectContaining({ itsId: ITS, success: true, clientId: 'rms-web-dev', ipAddress: '203.0.113.7' }));
  });

  it('looks the account up by integer mumin_id with the active status id, and eligibility by mumin_id', async () => {
    const { svc, accounts } = build();
    await svc.verify(ITS, 'ITS', PASSWORD, CTX);
    expect(accounts.findLoginAccount).toHaveBeenCalledWith(10110101, 3);
    expect(accounts.isEligible).toHaveBeenCalledWith(10110101);
  });

  it('rejects a wrong password as INVALID_CREDENTIALS', async () => {
    const { svc, attempts } = build();
    await expect(svc.verify(ITS, 'ITS', 'Test@002', CTX)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(reasonsOf(attempts)).toEqual(['INVALID_PASSWORD']);
  });

  it('rejects an unknown or inactive (Status_ID <> 3) account as INVALID_CREDENTIALS', async () => {
    const { svc, attempts } = build({ account: null });
    await expect(svc.verify('10119999', 'ITS', PASSWORD, CTX)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(reasonsOf(attempts)).toEqual(['ACCOUNT_NOT_FOUND_OR_INACTIVE']);
  });

  it('rejects an account whose stored password cannot be decrypted', async () => {
    const { svc } = build({ account: account({ password: '•' }) });
    await expect(svc.verify(ITS, 'ITS', '', CTX)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('refuses Allow_Login = false only after a correct password', async () => {
    const wrong = build({ account: account({ allowLogin: false }) });
    await expect(wrong.svc.verify(ITS, 'ITS', 'nope', CTX)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const right = build({ account: account({ allowLogin: false }) });
    await expect(right.svc.verify(ITS, 'ITS', PASSWORD, CTX)).rejects.toMatchObject({ code: 'ACCOUNT_UNAVAILABLE' });
    expect(reasonsOf(right.attempts)).toEqual(['LOGIN_NOT_ALLOWED']);
  });

  it('shows the configured login restriction message to a non-eligible user, only after a correct password', async () => {
    const wrong = build({ eligible: false });
    await expect(wrong.svc.verify(ITS, 'ITS', 'nope', CTX)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const right = build({ eligible: false });
    await expect(right.svc.verify(ITS, 'ITS', PASSWORD, CTX)).rejects.toMatchObject({ code: 'LOGIN_RESTRICTED', message: RESTRICTED, status: 403 });
    expect(reasonsOf(right.attempts)).toEqual(['NOT_ELIGIBLE']);
  });

  it('skips the eligibility lookup when the login restriction is disabled', async () => {
    const { svc, accounts } = build({ eligible: false, env: { LOGIN_RESTRICTION_ENABLED: false } });
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX)).resolves.toMatchObject({ itsId: ITS });
    expect(accounts.isEligible).not.toHaveBeenCalled();
  });

  it('locks the account after too many wrong passwords, even with the right one', async () => {
    const { svc, attempts } = build({ failures: 5 });
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX)).rejects.toMatchObject({ code: 'TOO_MANY_ATTEMPTS' });
    expect(attempts.recentFailures).toHaveBeenCalledWith(ITS, 'INVALID_PASSWORD', 900);
    expect(reasonsOf(attempts)).toEqual(['ACCOUNT_TEMPORARILY_LOCKED']);
  });

  it.each(['abc', '1011010a', '', '99999999999', '0'])('rejects the malformed ITS ID %p without looking up an account', async (id) => {
    const { svc, accounts } = build();
    await expect(svc.verify(id, 'ITS', PASSWORD, CTX)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(accounts.findLoginAccount).not.toHaveBeenCalled();
  });

  it('rejects NON_ITS sign-in: identity_db holds ITS members only', async () => {
    const { svc } = build();
    await expect(svc.verify('guest@example.com', 'NON_ITS', PASSWORD, CTX)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  describe('getActiveUser (SSO continuation)', () => {
    it('returns the user while still active, login-allowed and eligible', async () => {
      await expect(build().svc.getActiveUser(ITS)).resolves.toMatchObject({ itsId: ITS });
    });
    it.each([
      ['no longer active', { account: null }],
      ['Allow_Login revoked', { account: account({ allowLogin: false }) }],
      ['no longer eligible', { eligible: false }],
    ])('returns null when %s', async (_label, scenario) => {
      await expect(build(scenario).svc.getActiveUser(ITS)).resolves.toBeNull();
    });
  });

  it('toMuminId normalizes an ITS ID to the integer mumin_id', () => {
    expect(toMuminId(' 10110101 ')).toBe(10110101);
    expect(toMuminId('010110101')).toBe(10110101);
    expect(toMuminId('2147483648')).toBeNull();
  });
});
