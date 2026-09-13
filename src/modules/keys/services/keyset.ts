import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto';

export const KEY_STATUSES = ['NEXT', 'ACTIVE', 'RETIRING', 'RETIRED'] as const;
export type KeyStatus = (typeof KEY_STATUSES)[number];

/** Shape persisted in AWS SSM (one SecureString per kid) or the local dev keyset file. */
export interface StoredSigningKey {
  kid: string;
  alg: 'RS256';
  status: KeyStatus;
  createdAt: string;
  activatedAt?: string;
  retiringAt?: string;
  retiredAt?: string;
  privateKeyPem: string;
}

export interface PublicJwk {
  kty: 'RSA';
  kid: string;
  use: 'sig';
  alg: 'RS256';
  n: string;
  e: string;
}

const KID_PATTERN = /^[A-Za-z0-9._-]{8,128}$/;
export const MIN_RSA_BITS = 2048;
export const DEFAULT_RSA_BITS = 3072;

export class KeysetError extends Error {}

export function newKid(now = new Date()): string {
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `miqaat-key-${now.getUTCFullYear()}-${month}-${randomBytes(3).toString('hex')}`;
}

export function generateSigningKey(status: KeyStatus, now = new Date(), bits = DEFAULT_RSA_BITS): StoredSigningKey {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicExponent: 0x10001,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return {
    kid: newKid(now),
    alg: 'RS256',
    status,
    createdAt: now.toISOString(),
    ...(status === 'ACTIVE' ? { activatedAt: now.toISOString() } : {}),
    privateKeyPem: privateKey,
  };
}

/** Public parameters only - `d`, `p`, `q`, `dp`, `dq`, `qi` are never copied. */
export function toPublicJwk(key: StoredSigningKey): PublicJwk {
  const publicKey = createPublicKey(createPrivateKey(key.privateKeyPem));
  const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; n?: string; e?: string };
  if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) throw new KeysetError(`key ${key.kid} is not an RSA key`);
  return { kty: 'RSA', kid: key.kid, use: 'sig', alg: 'RS256', n: jwk.n, e: jwk.e };
}

export function validateKeyset(keys: StoredSigningKey[]): void {
  const kids = new Set<string>();
  for (const key of keys) {
    if (!KID_PATTERN.test(key.kid)) throw new KeysetError(`invalid kid format: ${key.kid}`);
    if (kids.has(key.kid)) throw new KeysetError(`duplicate kid: ${key.kid}`);
    kids.add(key.kid);
    if (key.alg !== 'RS256') throw new KeysetError(`key ${key.kid} must use RS256`);
    if (!KEY_STATUSES.includes(key.status)) throw new KeysetError(`key ${key.kid} has invalid status`);
    if (key.status !== 'RETIRED') {
      const bits = createPrivateKey(key.privateKeyPem).asymmetricKeyDetails?.modulusLength ?? 0;
      if (bits < MIN_RSA_BITS) throw new KeysetError(`key ${key.kid} is ${bits} bits; minimum is ${MIN_RSA_BITS}`);
    }
  }
  const active = keys.filter((k) => k.status === 'ACTIVE').length;
  if (active !== 1) throw new KeysetError(`keyset must contain exactly one ACTIVE key (found ${active})`);
  if (keys.filter((k) => k.status === 'NEXT').length > 1) throw new KeysetError('keyset may contain at most one NEXT key');
}

/** Keys published in JWKS: NEXT (pre-distribution), ACTIVE (signing), RETIRING (verifying in-flight tokens). */
export function publishedKeys(keys: StoredSigningKey[]): StoredSigningKey[] {
  return keys.filter((k) => k.status === 'NEXT' || k.status === 'ACTIVE' || k.status === 'RETIRING');
}

export type RotationAction = 'generate' | 'stage' | 'promote' | 'retire';

export interface RotationOptions {
  now?: Date;
  /** A RETIRING key stays published at least this long (>= max token lifetime + verifier JWKS cache). */
  minRetiringSeconds?: number;
  bits?: number;
}

/**
 * Rotation state machine: NEXT -> ACTIVE -> RETIRING -> RETIRED
 *
 *  generate : bootstrap an empty keyset with one ACTIVE key
 *  stage    : create a NEXT key (published in JWKS, not yet signing)
 *  promote  : NEXT -> ACTIVE and ACTIVE -> RETIRING (run only after verifiers' JWKS caches have refreshed)
 *  retire   : RETIRING -> RETIRED once minRetiringSeconds has elapsed (removed from JWKS)
 */
export function rotateKeyset(keys: StoredSigningKey[], action: RotationAction, options: RotationOptions = {}): StoredSigningKey[] {
  const now = options.now ?? new Date();
  const iso = now.toISOString();
  const next = keys.map((k) => ({ ...k }));

  switch (action) {
    case 'generate': {
      if (next.length > 0) throw new KeysetError('keyset already exists; use stage/promote to rotate');
      next.push(generateSigningKey('ACTIVE', now, options.bits));
      break;
    }
    case 'stage': {
      if (next.some((k) => k.status === 'NEXT')) throw new KeysetError('a NEXT key is already staged');
      next.push(generateSigningKey('NEXT', now, options.bits));
      break;
    }
    case 'promote': {
      const staged = next.find((k) => k.status === 'NEXT');
      if (!staged) throw new KeysetError('no NEXT key to promote; run stage first');
      for (const key of next) {
        if (key.status === 'ACTIVE') {
          key.status = 'RETIRING';
          key.retiringAt = iso;
        }
      }
      staged.status = 'ACTIVE';
      staged.activatedAt = iso;
      break;
    }
    case 'retire': {
      const minMs = (options.minRetiringSeconds ?? 3600) * 1000;
      for (const key of next) {
        if (key.status === 'RETIRING' && key.retiringAt && now.getTime() - new Date(key.retiringAt).getTime() >= minMs) {
          key.status = 'RETIRED';
          key.retiredAt = iso;
        }
      }
      break;
    }
  }
  validateKeyset(next);
  return next;
}
