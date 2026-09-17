import { AppConfig } from '@config/config.module';
import type { Env } from '@config/configuration';
import { DomainError } from '@common/errors/domain-error';
import { CredentialService } from './credential.service';
import { PasswordHasher } from './password-hasher';

const PASSWORD = 'CorrectHorse-9';
const ITS = '31267890';
const EMBEDDED = { requireMhpEligibility: true };
const PORTAL = { requireMhpEligibility: false };
const CTX = { ip: '203.0.113.7', clientId: 'rms-web-dev' };

const config = (over: Partial<Env> = {}) =>
  new AppConfig({
    NODE_ENV: 'test',
    ISSUER: 'https://identity.example.com',
    MHP_ELIGIBILITY_REQUIRED: true,
    MHP_ACTIVE_STATUS_ID: 3,
    LOGIN_MAX_FAILURES_PER_IDENTIFIER: 5,
    LOGIN_ACCOUNT_LOCK_SECONDS: 900,
    ...over,
  } as Env);

/** A synced, eligible, active, login-allowed account with a matching scrypt hash. */
async function row(over: Record<string, unknown> = {}) {
  const hasher = new PasswordHasher();
  return {
    its_id: ITS,
    identity_type: 'ITS',
    username: ITS,
    name: 'Demo Admin',
    password_hash: await hasher.hash(PASSWORD),
    status: 'ACTIVE',
    failed_login_count: 0,
    locked_until: null,
    legacy_user_id: null,
    mhp_eligible: true,
    mhp_status_id: 3,
    mhp_allow_login: true,
    mhp_synced_at: new Date(),
    ...over,
  };
}

function build(userRow: unknown | null, opts: { legacyEnabled?: boolean; legacyMatches?: boolean; env?: Partial<Env> } = {}) {
  const queries: string[] = [];
  const db = {
    query: jest.fn(async (sql: string) => {
      queries.push(sql);
      if (/^\s*SELECT/i.test(sql) && /FROM users/i.test(sql)) return userRow ? [userRow] : [];
      return [];
    }),
  };
  const legacy = {
    enabled: opts.legacyEnabled ?? false,
    verify: jest.fn(async () => opts.legacyMatches ?? false),
  };
  const svc = new CredentialService(db as never, config(opts.env), legacy as never);
  return { svc, db, legacy, queries };
}

const reasonsOf = (db: { query: jest.Mock }) =>
  db.query.mock.calls
    .filter(([sql]) => /auth_login_attempts/i.test(sql))
    .map(([, params]) => (params as unknown[])[5]);

async function expectInvalid(p: Promise<unknown>) {
  await expect(p).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
}

describe('CredentialService - MHP eligibility gate on Embedded Login', () => {
  it('lets an eligible user through with the right password', async () => {
    const { svc } = build(await row());
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED)).resolves.toMatchObject({ itsId: ITS });
  });

  it.each([
    ['not in MHP_User_Login_Eligible', { mhp_eligible: false }, 'MHP_NOT_ELIGIBLE'],
    ['never synced from MMS', { mhp_synced_at: null }, 'MHP_ACCOUNT_MISSING'],
    ['Status_ID is not 3', { mhp_status_id: 1 }, 'MHP_STATUS_NOT_ACTIVE'],
    ['Status_ID unknown', { mhp_status_id: null }, 'MHP_STATUS_NOT_ACTIVE'],
    ['Allow_Login = 0', { mhp_allow_login: false }, 'MHP_LOGIN_NOT_ALLOWED'],
  ])('refuses a user %s, even with the correct password', async (_label, over, reason) => {
    const { svc, db } = build(await row(over));
    await expectInvalid(svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED));
    // Uniform error to the client, precise reason in the audit trail.
    expect(reasonsOf(db)).toContain(reason);
  });

  it('never reveals the gate to the client: same code as an unknown account', async () => {
    const unknown = build(null);
    const ineligible = build(await row({ mhp_eligible: false }));
    const a = await unknown.svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED).catch((e: DomainError) => e);
    const b = await ineligible.svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED).catch((e: DomainError) => e);
    expect((a as DomainError).code).toBe((b as DomainError).code);
    expect((a as DomainError).message).toBe((b as DomainError).message);
    expect((a as DomainError).status).toBe((b as DomainError).status);
  });

  it('refuses an ineligible user before their password can be judged', async () => {
    // A wrong password and a failing gate must be indistinguishable, and the gate must not
    // increment the failure counter as though the password were the problem.
    const { svc, db } = build(await row({ mhp_eligible: false }));
    await expectInvalid(svc.verify(ITS, 'ITS', 'totally-wrong', CTX, EMBEDDED));
    const updates = db.query.mock.calls.filter(([sql]) => /failed_login_count = failed_login_count \+ 1/.test(sql));
    expect(updates).toHaveLength(0);
  });

  it('still enforces the password for an eligible user', async () => {
    const { svc } = build(await row());
    await expectInvalid(svc.verify(ITS, 'ITS', 'wrong-password', CTX, EMBEDDED));
  });

  it('still enforces account status after the gate and the password', async () => {
    const { svc } = build(await row({ status: 'DISABLED' }));
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED)).rejects.toMatchObject({ code: 'ACCOUNT_UNAVAILABLE' });
  });
});

describe('CredentialService - the existing flows are unchanged', () => {
  it('portal login ignores the gate entirely', async () => {
    const { svc } = build(await row({ mhp_eligible: false, mhp_status_id: 1, mhp_allow_login: false, mhp_synced_at: null }));
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX, PORTAL)).resolves.toMatchObject({ itsId: ITS });
  });

  it('defaults to the portal policy when no policy is passed', async () => {
    const { svc } = build(await row({ mhp_eligible: false }));
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX)).resolves.toMatchObject({ itsId: ITS });
  });

  it('MHP_ELIGIBILITY_REQUIRED=false disables the gate even for Embedded Login', async () => {
    const { svc } = build(await row({ mhp_eligible: false }), { env: { MHP_ELIGIBILITY_REQUIRED: false } });
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED)).resolves.toMatchObject({ itsId: ITS });
  });
});

describe('CredentialService - legacy password fallback', () => {
  it('is not consulted while the scrypt hash still matches', async () => {
    const { svc, legacy } = build(await row({ legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED)).resolves.toMatchObject({ itsId: ITS });
    expect(legacy.verify).not.toHaveBeenCalled();
  });

  it('accepts a password that only the legacy ciphertext matches, then upgrades to scrypt', async () => {
    const { svc, legacy, db } = build(await row({ legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    await expect(svc.verify(ITS, 'ITS', 'changed-in-mms', CTX, EMBEDDED)).resolves.toMatchObject({ itsId: ITS });
    expect(legacy.verify).toHaveBeenCalledWith(4242, 'changed-in-mms');
    const upgrades = db.query.mock.calls.filter(([sql]) => /SET password_hash = \$2, password_algo = 'scrypt'/.test(sql));
    expect(upgrades).toHaveLength(1);
    expect(reasonsOf(db)).toContain('LEGACY_PASSWORD_UPGRADED');
  });

  it('authenticates a never-migrated account that has no scrypt hash at all', async () => {
    const { svc, legacy } = build(await row({ password_hash: null, legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    await expect(svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED)).resolves.toMatchObject({ itsId: ITS });
    expect(legacy.verify).toHaveBeenCalled();
  });

  it('refuses a null-hash account when the legacy fallback is disabled', async () => {
    const { svc, legacy } = build(await row({ password_hash: null, legacy_user_id: 4242 }), { legacyEnabled: false });
    await expectInvalid(svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED));
    expect(legacy.verify).not.toHaveBeenCalled();
  });

  it('is never consulted for an account with no legacy link', async () => {
    const { svc, legacy } = build(await row({ legacy_user_id: null }), { legacyEnabled: true, legacyMatches: true });
    await expectInvalid(svc.verify(ITS, 'ITS', 'wrong-password', CTX, EMBEDDED));
    expect(legacy.verify).not.toHaveBeenCalled();
  });

  it('does not let the legacy fallback bypass the eligibility gate', async () => {
    const { svc, legacy } = build(await row({ mhp_eligible: false, legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    await expectInvalid(svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED));
    expect(legacy.verify).not.toHaveBeenCalled();
  });
});
