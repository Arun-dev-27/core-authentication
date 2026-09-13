import { ScryptOptions, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';

/**
 * scrypt password hashing (memory-hard; Node core, no native addon).
 * Encoded format:  scrypt$ln=<log2 N>,r=<r>,p=<p>$<salt base64url>$<hash base64url>
 */
const CURRENT = { ln: 15, r: 8, p: 1, keylen: 32, saltBytes: 16 };
const MAX_PASSWORD_LENGTH = 256;

function scrypt(password: string, salt: Buffer, keylen: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password.normalize('NFC'), salt, keylen, options, (error, key) => (error ? reject(error) : resolve(key)));
  });
}

interface Parsed {
  ln: number;
  r: number;
  p: number;
  salt: Buffer;
  hash: Buffer;
}

function parse(encoded: string): Parsed | null {
  const match = /^scrypt\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/.exec(encoded);
  if (!match) return null;
  const [, ln, r, p, salt, hash] = match;
  return { ln: Number(ln), r: Number(r), p: Number(p), salt: Buffer.from(salt, 'base64url'), hash: Buffer.from(hash, 'base64url') };
}

export class PasswordHasher {
  static readonly algorithm = 'scrypt';
  private dummyHash?: Promise<string>;

  async hash(password: string): Promise<string> {
    if (typeof password !== 'string' || password.length === 0 || password.length > MAX_PASSWORD_LENGTH) {
      throw new Error('password length out of range');
    }
    const salt = randomBytes(CURRENT.saltBytes);
    const key = await scrypt(password, salt, CURRENT.keylen, { N: 2 ** CURRENT.ln, r: CURRENT.r, p: CURRENT.p, maxmem: 128 * 1024 * 1024 });
    return `scrypt$ln=${CURRENT.ln},r=${CURRENT.r},p=${CURRENT.p}$${salt.toString('base64url')}$${key.toString('base64url')}`;
  }

  async verify(password: string, encoded: string | null | undefined): Promise<boolean> {
    if (typeof password !== 'string' || password.length === 0 || password.length > MAX_PASSWORD_LENGTH) return false;
    const parsed = encoded ? parse(encoded) : null;
    if (!parsed || parsed.ln < 14 || parsed.ln > 20) {
      // Still spend comparable CPU so a missing/invalid hash is not distinguishable by timing.
      await this.verify(password, await this.getDummyHash()).catch(() => false);
      return false;
    }
    const key = await scrypt(password, parsed.salt, parsed.hash.length, { N: 2 ** parsed.ln, r: parsed.r, p: parsed.p, maxmem: 256 * 1024 * 1024 });
    return key.length === parsed.hash.length && timingSafeEqual(key, parsed.hash);
  }

  needsRehash(encoded: string): boolean {
    const parsed = parse(encoded);
    return !parsed || parsed.ln < CURRENT.ln || parsed.r !== CURRENT.r || parsed.p !== CURRENT.p;
  }

  /** Used for unknown accounts to equalise response time. */
  getDummyHash(): Promise<string> {
    this.dummyHash ??= this.hash(randomBytes(24).toString('base64url'));
    return this.dummyHash;
  }
}
