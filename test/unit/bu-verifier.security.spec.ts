import { createHmac } from 'node:crypto';
import { JWK, KeyLike, SignJWT, UnsecuredJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose';
import { AssertionVerificationError, BACKCHANNEL_LOGOUT_EVENT, CoreAssertionVerifier, MemoryReplayStore } from '../../examples/bu-reference-app/src/core-assertion-verifier';

const ISSUER = 'https://identity.miqaat.test';
const CLIENT = 'rms-web-prod';
const KID = 'miqaat-key-2026-09-test01';

let privateKey: KeyLike;
let publicJwk: JWK;
let otherPrivateKey: KeyLike;

let trustedPublicKey: KeyLike;

beforeAll(async () => {
  ({ privateKey, publicKey: trustedPublicKey } = await generateKeyPair('RS256', { modulusLength: 2048 }));
  ({ privateKey: otherPrivateKey } = await generateKeyPair('RS256', { modulusLength: 2048 }));
});

/** Local JWKS containing only the trusted public key. */
async function keys(kid = KID) {
  publicJwk = { ...(await exportJWK(trustedPublicKey)), kid, alg: 'RS256', use: 'sig' };
  return createLocalJWKSet({ keys: [publicJwk] });
}

function verifier(resolver: Awaited<ReturnType<typeof keys>>, store = new MemoryReplayStore()) {
  return new CoreAssertionVerifier({ issuer: ISSUER, clientId: CLIENT, jwksUri: 'https://unused.test/jwks', replayStore: store, keyResolver: resolver });
}

function claims(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { sid: 'sid_abcdefghijklmnop', txn: 'txn-123456', auth_time: now, ...overrides };
}

async function sign(opts: { payload?: Record<string, unknown>; header?: Record<string, unknown>; iss?: string; aud?: string | string[]; iat?: number; exp?: number; jti?: string; sub?: string; key?: KeyLike } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT(claims(opts.payload))
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: KID, ...(opts.header ?? {}) } as never)
    .setIssuer(opts.iss ?? ISSUER)
    .setSubject(opts.sub ?? 'ITS12345')
    .setAudience(opts.aud ?? CLIENT)
    .setJti(opts.jti ?? `jti-${Math.random().toString(36).slice(2)}-${Date.now()}`)
    .setIssuedAt(opts.iat ?? now)
    .setExpirationTime(opts.exp ?? now + 60);
  return jwt.sign(opts.key ?? privateKey);
}

async function expectCode(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toBeInstanceOf(AssertionVerificationError);
  await expect(promise).rejects.toMatchObject({ code });
}

describe('BU assertion verifier - security', () => {
  it('accepts a valid assertion and exposes sub only after verification', async () => {
    const v = verifier(await keys());
    const token = await sign();
    const result = await v.verifyLoginAssertion(token, { transactionId: 'txn-123456' });
    expect(result).toMatchObject({ itsId: 'ITS12345', sid: 'sid_abcdefghijklmnop', transactionId: 'txn-123456' });
  });

  it('rejects replay of the same jti', async () => {
    const v = verifier(await keys());
    const token = await sign();
    await v.verifyLoginAssertion(token, { transactionId: 'txn-123456' });
    await expectCode(v.verifyLoginAssertion(token, { transactionId: 'txn-123456' }), 'REPLAYED');
  });

  it('rejects alg=none (unsecured JWT)', async () => {
    const v = verifier(await keys());
    const unsecured = new UnsecuredJWT(claims()).setIssuer(ISSUER).setAudience(CLIENT).setSubject('ITS12345').setJti('jti-none-000000000').setIssuedAt().setExpirationTime('60s').encode();
    // compact form "header.payload." has an empty signature
    await expectCode(v.verifyLoginAssertion(unsecured, { transactionId: 'txn-123456' }), 'MALFORMED');
    await expectCode(v.verifyLoginAssertion(`${unsecured}AAAA`, { transactionId: 'txn-123456' }), 'ALG_NOT_ALLOWED');
  });

  it('rejects HS256 algorithm-confusion tokens signed with the public key', async () => {
    const v = verifier(await keys());
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: KID })).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(JSON.stringify({ ...claims(), iss: ISSUER, aud: CLIENT, sub: 'ITS12345', jti: 'jti-hs256-0000000000', iat: now, exp: now + 60 })).toString('base64url');
    const sig = createHmac('sha256', JSON.stringify(publicJwk)).update(`${header}.${payload}`).digest('base64url');
    await expectCode(v.verifyLoginAssertion(`${header}.${payload}.${sig}`, { transactionId: 'txn-123456' }), 'ALG_NOT_ALLOWED');
  });

  it('rejects a token signed by a different key with the trusted kid', async () => {
    const v = verifier(await keys());
    await expectCode(v.verifyLoginAssertion(await sign({ key: otherPrivateKey }), { transactionId: 'txn-123456' }), 'SIGNATURE_INVALID');
  });

  it('rejects unknown kid and missing kid', async () => {
    const v = verifier(await keys());
    await expectCode(v.verifyLoginAssertion(await sign({ header: { kid: 'miqaat-key-unknown-1' } }), { transactionId: 'txn-123456' }), 'UNKNOWN_KID');
    const noKid = await new SignJWT(claims()).setProtectedHeader({ alg: 'RS256', typ: 'JWT' }).setIssuer(ISSUER).setAudience(CLIENT).setSubject('ITS12345').setJti('jti-nokid-00000000').setIssuedAt().setExpirationTime('60s').sign(privateKey);
    await expectCode(v.verifyLoginAssertion(noKid, { transactionId: 'txn-123456' }), 'KID_MISSING');
  });

  it('enforces exact issuer and audience (no array containment, no other clients)', async () => {
    const v = verifier(await keys());
    await expectCode(v.verifyLoginAssertion(await sign({ iss: 'https://evil.test' }), { transactionId: 'txn-123456' }), 'ISSUER_MISMATCH');
    await expectCode(v.verifyLoginAssertion(await sign({ aud: 'ams-web-prod' }), { transactionId: 'txn-123456' }), 'AUDIENCE_MISMATCH');
    await expectCode(v.verifyLoginAssertion(await sign({ aud: [CLIENT, 'ams-web-prod'] }), { transactionId: 'txn-123456' }), 'AUDIENCE_MISMATCH');
  });

  it('rejects expired, future-dated and long-lived assertions', async () => {
    const v = verifier(await keys());
    const now = Math.floor(Date.now() / 1000);
    await expectCode(v.verifyLoginAssertion(await sign({ iat: now - 300, exp: now - 240 }), { transactionId: 'txn-123456' }), 'EXPIRED');
    await expectCode(v.verifyLoginAssertion(await sign({ iat: now + 600, exp: now + 660 }), { transactionId: 'txn-123456' }), 'IAT_INVALID');
    await expectCode(v.verifyLoginAssertion(await sign({ iat: now, exp: now + 3600 }), { transactionId: 'txn-123456' }), 'LIFETIME_TOO_LONG');
  });

  it('binds the assertion to the transaction and requires all claims', async () => {
    const v = verifier(await keys());
    await expectCode(v.verifyLoginAssertion(await sign(), { transactionId: 'txn-OTHER' }), 'TRANSACTION_MISMATCH');
    await expectCode(v.verifyLoginAssertion(await sign({ payload: { sid: undefined } }), { transactionId: 'txn-123456' }), 'CLAIM_INVALID_SID');
  });

  it('rejects tampered payloads and non-JWS input', async () => {
    const v = verifier(await keys());
    const [h, p, s] = (await sign()).split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), sub: 'ITS99999' })).toString('base64url');
    await expectCode(v.verifyLoginAssertion(`${h}.${forged}.${s}`, { transactionId: 'txn-123456' }), 'SIGNATURE_INVALID');
    await expectCode(v.verifyLoginAssertion({ sub: 'ITS12345' }, { transactionId: 'txn-123456' }), 'MALFORMED');
    await expectCode(v.verifyLoginAssertion('a.b', { transactionId: 'txn-123456' }), 'MALFORMED');
  });

  describe('back-channel logout token', () => {
    async function logoutToken(extra: Record<string, unknown> = {}, typ = 'logout+jwt') {
      return new SignJWT({ sid: 'sid_abcdefghijklmnop', events: { [BACKCHANNEL_LOGOUT_EVENT]: {} }, ...extra })
        .setProtectedHeader({ alg: 'RS256', typ, kid: KID })
        .setIssuer(ISSUER)
        .setAudience(CLIENT)
        .setSubject('ITS12345')
        .setJti(`jti-logout-${Math.random().toString(36).slice(2)}`)
        .setIssuedAt()
        .setExpirationTime('120s')
        .sign(privateKey);
    }

    it('accepts a valid logout token once', async () => {
      const v = verifier(await keys());
      const token = await logoutToken();
      await expect(v.verifyLogoutToken(token)).resolves.toMatchObject({ sid: 'sid_abcdefghijklmnop' });
      await expectCode(v.verifyLogoutToken(token), 'REPLAYED');
    });

    it('rejects a login assertion presented as a logout token (typ confusion) and vice versa', async () => {
      const v = verifier(await keys());
      await expectCode(v.verifyLogoutToken(await sign()), 'TYP_INVALID');
      await expectCode(v.verifyLoginAssertion(await logoutToken(), { transactionId: 'txn-123456' }), 'TYP_INVALID');
    });

    it('requires the logout event and forbids nonce', async () => {
      const v = verifier(await keys());
      await expectCode(v.verifyLogoutToken(await logoutToken({ events: {} })), 'LOGOUT_EVENT_MISSING');
      await expectCode(v.verifyLogoutToken(await logoutToken({ nonce: 'n' })), 'NONCE_NOT_ALLOWED');
    });
  });
});
