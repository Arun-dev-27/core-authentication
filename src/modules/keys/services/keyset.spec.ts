import { StoredSigningKey, generateSigningKey, publishedKeys, rotateKeyset, toPublicJwk, validateKeyset } from './keyset';

describe('keyset rotation (NEXT -> ACTIVE -> RETIRING -> RETIRED)', () => {
  const t0 = new Date('2026-09-13T10:00:00Z');
  const opts = { bits: 2048 };

  it('bootstraps exactly one ACTIVE key', () => {
    const keys = rotateKeyset([], 'generate', { ...opts, now: t0 });
    expect(keys).toHaveLength(1);
    expect(keys[0].status).toBe('ACTIVE');
    expect(keys[0].kid).toMatch(/^miqaat-key-2026-09-[a-f0-9]{6}$/);
  });

  it('runs a full rotation and keeps old keys verifiable until retired', () => {
    let keys = rotateKeyset([], 'generate', { ...opts, now: t0 });
    const original = keys[0].kid;

    keys = rotateKeyset(keys, 'stage', { ...opts, now: t0 });
    const staged = keys.find((k) => k.status === 'NEXT')!.kid;
    expect(publishedKeys(keys).map((k) => k.kid).sort()).toEqual([original, staged].sort());
    expect(keys.find((k) => k.status === 'ACTIVE')!.kid).toBe(original);

    keys = rotateKeyset(keys, 'promote', { now: new Date('2026-09-14T10:00:00Z') });
    expect(keys.find((k) => k.status === 'ACTIVE')!.kid).toBe(staged);
    expect(keys.find((k) => k.kid === original)!.status).toBe('RETIRING');
    expect(publishedKeys(keys)).toHaveLength(2);

    // too early: stays RETIRING
    keys = rotateKeyset(keys, 'retire', { now: new Date('2026-09-14T10:30:00Z'), minRetiringSeconds: 3600 });
    expect(keys.find((k) => k.kid === original)!.status).toBe('RETIRING');

    keys = rotateKeyset(keys, 'retire', { now: new Date('2026-09-14T11:00:01Z'), minRetiringSeconds: 3600 });
    expect(keys.find((k) => k.kid === original)!.status).toBe('RETIRED');
    expect(publishedKeys(keys).map((k) => k.kid)).toEqual([staged]);
  });

  it('refuses invalid transitions and keysets', () => {
    const keys = rotateKeyset([], 'generate', opts);
    expect(() => rotateKeyset(keys, 'promote')).toThrow('no NEXT key');
    expect(() => rotateKeyset(keys, 'generate')).toThrow('already exists');
    const staged = rotateKeyset(keys, 'stage', opts);
    expect(() => rotateKeyset(staged, 'stage', opts)).toThrow('already staged');

    const twoActive: StoredSigningKey[] = [keys[0], { ...generateSigningKey('ACTIVE', new Date(), 2048), kid: 'miqaat-key-other' }];
    expect(() => validateKeyset(twoActive)).toThrow('exactly one ACTIVE');
    expect(() => validateKeyset([{ ...keys[0], kid: keys[0].kid }, { ...keys[0], status: 'NEXT' }])).toThrow('duplicate kid');
  });

  it('rejects RSA keys below 2048 bits', () => {
    const weak = generateSigningKey('ACTIVE', new Date(), 1024);
    expect(() => validateKeyset([weak])).toThrow('minimum is 2048');
  });

  it('exports only public RSA parameters to JWKS', () => {
    const jwk = toPublicJwk(generateSigningKey('ACTIVE', new Date(), 2048)) as unknown as Record<string, unknown>;
    expect(Object.keys(jwk).sort()).toEqual(['alg', 'e', 'kid', 'kty', 'n', 'use']);
    for (const privateParam of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(jwk[privateParam]).toBeUndefined();
  });
});
