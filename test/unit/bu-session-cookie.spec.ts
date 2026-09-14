import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EncryptJWT } from 'jose';
import { CoreAssertionClaims, SESSION_COOKIE_TYP, SessionCookieCipher } from '../../examples/bu-reference-app/src/session-cookie-cipher';

const APP_ORIGIN = 'http://localhost:4001';
const CLIENT_ID = 'rms-web-dev';
const KEY = Buffer.alloc(32, 7).toString('base64url');
const LOCAL_ID = 'a'.repeat(43);
const now = Math.floor(Date.now() / 1000);
const core: CoreAssertionClaims = {
  iss: 'http://localhost:3001',
  sub: '30337752',
  aud: CLIENT_ID,
  sid: 'sid_-IajPVFnfiF9ZfIAkzk9KVTU',
  jti: 'ca19907b-5d3e-4c1a-9b8e-2f6d0a1b3c4d',
  txn: 'txn_C6BfjesJxPz4wcQa5E5vonw6',
  auth_time: now - 5,
  iat: now - 5,
  exp: now + 55,
};
// Same shape and size as a real RS256 assertion (header.payload.342-byte signature).
const b64 = (value: unknown) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const CORE_ASSERTION = `${b64({ alg: 'RS256', typ: 'JWT', kid: 'miqaat-key-2026-09-886608' })}.${b64(core)}.${Buffer.alloc(384, 1).toString('base64url')}`;

const cipher = (overrides: Partial<Parameters<typeof SessionCookieCipher.load>[0]> = {}) =>
  SessionCookieCipher.load({ issuer: APP_ORIGIN, audience: CLIENT_ID, keyBase64url: KEY, keyFile: '', ...overrides });

describe('BU encrypted session cookie', () => {
  it('round-trips the core assertion, its claims and the local session id, unreadable to the browser', async () => {
    const c = cipher();
    const token = await c.seal(LOCAL_ID, core, CORE_ASSERTION, 3600);
    expect(token.split('.')).toHaveLength(5);
    expect(token.length).toBeLessThan(4000);
    const ciphertext = Buffer.from(token.split('.')[3], 'base64url').toString('latin1');
    expect(ciphertext).not.toContain(core.sub);
    expect(token).not.toContain(CORE_ASSERTION.split('.')[1]);
    const opened = await c.open(token);
    expect(opened).toMatchObject({ lid: LOCAL_ID, core, core_assertion: CORE_ASSERTION });
    expect(opened!.exp - opened!.iat).toBe(3600);
  });

  it('refuses to seal something that is not a compact JWS', async () => {
    await expect(cipher().seal(LOCAL_ID, core, 'not-a-token', 3600)).rejects.toThrow('compact JWS');
  });

  it('rejects a tampered cookie', async () => {
    const parts = (await cipher().seal(LOCAL_ID, core, CORE_ASSERTION, 3600)).split('.');
    parts[3] = (parts[3][0] === 'A' ? 'B' : 'A') + parts[3].slice(1);
    await expect(cipher().open(parts.join('.'))).resolves.toBeNull();
  });

  it('rejects a cookie sealed with another key', async () => {
    const token = await cipher().seal(LOCAL_ID, core, CORE_ASSERTION, 3600);
    await expect(cipher({ keyBase64url: Buffer.alloc(32, 9).toString('base64url') }).open(token)).resolves.toBeNull();
  });

  it("rejects another application's cookie", async () => {
    const token = await cipher().seal(LOCAL_ID, core, CORE_ASSERTION, 3600);
    await expect(cipher({ audience: 'ams-web-dev' }).open(token)).resolves.toBeNull();
    await expect(cipher({ issuer: 'http://localhost:4002' }).open(token)).resolves.toBeNull();
  });

  const encrypt = (payload: Record<string, unknown>, iat: number, exp: number) =>
    new EncryptJWT(payload)
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: SESSION_COOKIE_TYP })
      .setIssuer(APP_ORIGIN)
      .setAudience(CLIENT_ID)
      .setIssuedAt(iat)
      .setExpirationTime(exp)
      .encrypt(Buffer.from(KEY, 'base64url'));

  it('rejects an expired cookie', async () => {
    const expired = await encrypt({ lid: LOCAL_ID, core: { ...core }, core_assertion: CORE_ASSERTION }, now - 7200, now - 60);
    await expect(cipher().open(expired)).resolves.toBeNull();
  });

  it('rejects a cookie whose core_assertion is missing or malformed', async () => {
    await expect(cipher().open(await encrypt({ lid: LOCAL_ID, core: { ...core } }, now, now + 3600))).resolves.toBeNull();
    await expect(cipher().open(await encrypt({ lid: LOCAL_ID, core: { ...core }, core_assertion: 'a.b' }, now, now + 3600))).resolves.toBeNull();
  });

  it('rejects garbage and oversized values', async () => {
    for (const value of [undefined, '', 'not-a-jwe', 'x'.repeat(5000), LOCAL_ID]) await expect(cipher().open(value)).resolves.toBeNull();
  });

  it('generates a development key once and reuses it', async () => {
    const keyFile = join(mkdtempSync(join(tmpdir(), 'bu-session-')), 'rms-web-dev-session.key');
    const token = await cipher({ keyBase64url: undefined, keyFile }).seal(LOCAL_ID, core, CORE_ASSERTION, 3600);
    await expect(cipher({ keyBase64url: undefined, keyFile }).open(token)).resolves.toMatchObject({ lid: LOCAL_ID, core_assertion: CORE_ASSERTION });
  });

  it('refuses keys that are not 32 bytes', () => {
    expect(() => cipher({ keyBase64url: Buffer.alloc(16).toString('base64url') })).toThrow('32 bytes');
  });
});
