import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** 256-bit URL-safe random token (session handles, CSRF tokens). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Prefixed random identifier (sid, jti) - not secret, but unguessable. */
export function randomId(prefix: string, bytes = 18): string {
  return `${prefix}_${randomBytes(bytes).toString('base64url')}`;
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function safeEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(sha256Hex(a), 'hex');
  const right = Buffer.from(sha256Hex(b), 'hex');
  return timingSafeEqual(left, right) && a.length === b.length;
}
