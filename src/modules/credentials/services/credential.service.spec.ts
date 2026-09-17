import { AppConfig } from '@config/config.module';
import type { Env } from '@config/configuration';
import { DomainError } from '@common/errors/domain-error';
import { CredentialService } from './credential.service';
import { PasswordHasher } from './password-hasher';

const PASSWORD = 'CorrectHorse-9';
const ITS = '31267890';
// The gate is independent of which credential is checked, so the gate tests use the scrypt
// source and keep asserting on a local hash.
const EMBEDDED = { requireMhpEligibility: true, passwordSource: 'scrypt' } as const;
const EMBEDDED_LEGACY = { requireMhpEligibility: true, passwordSource: 'legacy-decrypt' } as const;
const PORTAL = { requireMhpEligibility: false, passwordSource: 'scrypt' } as const;
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

describe("CredentialService - Embedded Login with passwordSource 'legacy-decrypt'", () => {
  it('authenticates purely on the decrypted MMS password, ignoring the local hash', async () => {
    const { svc, legacy } = build(await row({ legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    // Not the scrypt password: only the legacy compare can be what accepted this.
    await expect(svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED_LEGACY)).resolves.toMatchObject({ itsId: ITS });
    expect(legacy.verify).toHaveBeenCalledWith(4242, 'i');
  });

  it('refuses a password the legacy ciphertext does not match, even if the scrypt hash does', async () => {
    const { svc, legacy } = build(await row({ legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: false });
    await expectInvalid(svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED_LEGACY));
    expect(legacy.verify).toHaveBeenCalled();
  });

  it('never consults the local hash on this path', async () => {
    const { svc } = build(await row({ password_hash: null, legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    await expect(svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED_LEGACY)).resolves.toMatchObject({ itsId: ITS });
  });

  it('addresses the legacy row by ITS ID when the account carries no legacy_user_id', async () => {
    const { svc, legacy } = build(await row({ legacy_user_id: null }), { legacyEnabled: true, legacyMatches: true });
    await expect(svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED_LEGACY)).resolves.toMatchObject({ itsId: ITS });
    expect(legacy.verify).toHaveBeenCalledWith(Number(ITS), 'i');
  });

  it('refuses a NON_ITS account, whose identifier cannot address a legacy row', async () => {
    const { svc, db, legacy } = build(
      await row({ its_id: 'NITS-BD796FB3', identity_type: 'NON_ITS', username: 'guest@example.com', legacy_user_id: null }),
      { legacyEnabled: true, legacyMatches: true },
    );
    await expectInvalid(svc.verify('guest@example.com', 'NON_ITS', 'i', CTX, EMBEDDED_LEGACY));
    expect(legacy.verify).not.toHaveBeenCalled();
    expect(reasonsOf(db)).toContain('LEGACY_ACCOUNT_UNRESOLVABLE');
  });

  it('fails closed when MMS is unavailable rather than falling back to the hash', async () => {
    const { svc, db } = build(await row({ legacy_user_id: 4242 }), { legacyEnabled: false });
    // The scrypt password would be accepted under the other source; here it must not be.
    await expectInvalid(svc.verify(ITS, 'ITS', PASSWORD, CTX, EMBEDDED_LEGACY));
    expect(reasonsOf(db)).toContain('LEGACY_SOURCE_UNAVAILABLE');
  });

  it('does not rewrite the local hash, since MMS stays the source of truth', async () => {
    const { svc, db } = build(await row({ legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    await svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED_LEGACY);
    const writes = db.query.mock.calls.filter(([sql]) => /SET password_hash/.test(sql));
    expect(writes).toHaveLength(0);
    expect(reasonsOf(db)).toContain('LEGACY_PASSWORD_VERIFIED');
  });

  it('still applies the eligibility gate before the decrypt', async () => {
    const { svc, legacy } = build(await row({ mhp_eligible: false, legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: true });
    await expectInvalid(svc.verify(ITS, 'ITS', 'i', CTX, EMBEDDED_LEGACY));
    expect(legacy.verify).not.toHaveBeenCalled();
  });

  it('leaves portal login on scrypt even while Embedded Login uses the legacy source', async () => {
    const { svc, legacy } = build(await row({ legacy_user_id: 4242 }), { legacyEnabled: true, legacyMatches: false });
    await expect(svc.verify(ITS, 'ITS', PASSWORD, CTX, PORTAL)).resolves.toMatchObject({ itsId: ITS });
    expect(legacy.verify).not.toHaveBeenCalled();
  });
});
