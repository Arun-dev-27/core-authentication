import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { EncryptJWT, jwtDecrypt } from 'jose';

export const SESSION_COOKIE_TYP = 'session+jwt';

const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const MAX_COOKIE_LENGTH = 4096;

/** Claims of the verified Core assertion, copied exactly as Identity Federation issued them. */
export interface CoreAssertionClaims {
  iss: string;
  sub: string;
  aud: string;
  sid: string;
  jti: string;
  txn: string;
  auth_time: number;
  iat: number;
  exp: number;
}

export interface SessionCookiePayload {
  /** Local session id: the Redis session is the revocation list (local and back-channel logout delete it). */
  lid: string;
  core: CoreAssertionClaims;
  /** The verified compact RS256 assertion, unchanged. Already expired and its jti spent: kept for traceability, never re-accepted. */
  core_assertion: string;
  /** Cookie issue time and expiry (the application session lifetime, not the assertion's). */
  iat: number;
  exp: number;
}

export interface SessionCookieCipherOptions {
  /** This application's origin: outer `iss` of the cookie. */
  issuer: string;
  /** This application's client_id: outer `aud`, so a cookie of one application is refused by another. */
  audience: string;
  /** 32 random bytes, base64url (SESSION_ENC_KEY). Required when NODE_ENV=production. */
  keyBase64url?: string;
  /** Development fallback: generated once, git-ignored. */
  keyFile: string;
}

/**
 * The application's session cookie: the verified assertion (compact token and its claims) encrypted with the
 * application's OWN key (JWE compact, alg dir, enc A256GCM). The browser can neither read nor modify it;
 * the Identity signing key is never involved.
 */
export class SessionCookieCipher {
  private constructor(
    private readonly key: Uint8Array,
    private readonly kid: string,
    private readonly issuer: string,
    private readonly audience: string,
  ) {}

  static load(options: SessionCookieCipherOptions): SessionCookieCipher {
    let encoded = options.keyBase64url;
    if (!encoded) {
      if (process.env.NODE_ENV === 'production') throw new Error('SESSION_ENC_KEY is required in production');
      if (!existsSync(options.keyFile)) {
        mkdirSync(dirname(options.keyFile), { recursive: true });
        writeFileSync(options.keyFile, randomBytes(32).toString('base64url'), { mode: 0o600 });
      }
      encoded = readFileSync(options.keyFile, 'utf8').trim();
    }
    const key = Buffer.from(encoded, 'base64url');
    if (key.length !== 32) throw new Error('session encryption key must be 32 bytes (base64url)');
    const kid = createHash('sha256').update(key).digest('base64url').slice(0, 16);
    return new SessionCookieCipher(new Uint8Array(key), kid, options.issuer, options.audience);
  }

  async seal(localSessionId: string, core: CoreAssertionClaims, coreAssertion: string, ttlSeconds: number): Promise<string> {
    if (!COMPACT_JWS.test(coreAssertion)) throw new Error('core_assertion must be a compact JWS');
    const token = await new EncryptJWT({ lid: localSessionId, core: { ...core }, core_assertion: coreAssertion })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM', typ: SESSION_COOKIE_TYP, kid: this.kid })
      .setIssuer(this.issuer)
      .setAudience(this.audience)
      .setIssuedAt()
      .setExpirationTime(`${ttlSeconds}s`)
      .encrypt(this.key);
    // Browsers drop cookies over ~4 KB silently; fail loudly instead.
    if (token.length > MAX_COOKIE_LENGTH - 100) throw new Error(`session cookie too large (${token.length} characters)`);
    return token;
  }

  /** Returns null for anything that is not an intact, unexpired cookie of this application. */
  async open(token: unknown): Promise<SessionCookiePayload | null> {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_COOKIE_LENGTH) return null;
    try {
      const { payload } = await jwtDecrypt(token, this.key, {
        issuer: this.issuer,
        audience: this.audience,
        typ: SESSION_COOKIE_TYP,
        keyManagementAlgorithms: ['dir'],
        contentEncryptionAlgorithms: ['A256GCM'],
        requiredClaims: ['iat', 'exp'],
      });
      const core = payload.core as CoreAssertionClaims | undefined;
      const assertion = payload.core_assertion;
      if (typeof payload.lid !== 'string' || !core || typeof core.sub !== 'string' || typeof core.sid !== 'string') return null;
      if (typeof assertion !== 'string' || !COMPACT_JWS.test(assertion)) return null;
      return { lid: payload.lid, core, core_assertion: assertion, iat: payload.iat as number, exp: payload.exp as number };
    } catch {
      return null;
    }
  }
}
