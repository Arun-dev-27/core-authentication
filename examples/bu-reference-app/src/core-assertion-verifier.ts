/**
 * Business Unit backend verifier for Miqaat Core assertions and back-channel logout tokens.
 * Framework-agnostic; copy into any Node.js BU backend (RMS, AMS, VMS, ...).
 *
 * Verification order (login assertion):
 *  1. shape check (compact JWS, bounded size)
 *  2. protected header: alg MUST be RS256, kid MUST be present, typ MUST be JWT
 *  3. key selection by kid from the Core JWKS (cached; refetched on unknown kid with cooldown)
 *  4. RS256 signature
 *  5. iss exact, aud exact (single string equal to this client_id), exp, iat (not in the future), max age
 *  6. short lifetime (exp - iat)
 *  7. txn binding to the transaction this browser started
 *  8. sid / sub format
 *  9. one-time use of jti (replay protection)
 * Only after all of the above is `sub` (ITS ID) returned to the caller.
 */
import { createRemoteJWKSet, decodeProtectedHeader, errors, JWTPayload, JWTVerifyGetKey, jwtVerify } from 'jose';

export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ITS_ID = /^[A-Za-z0-9._-]{1,64}$/;
const SID = /^[A-Za-z0-9._~-]{8,128}$/;

export interface ReplayStore {
  /** Atomically records the jti; returns false if it was already used. */
  claim(key: string, ttlSeconds: number): Promise<boolean>;
}

export interface VerifierOptions {
  issuer: string;
  clientId: string;
  jwksUri: string;
  replayStore: ReplayStore;
  clockToleranceSeconds?: number;
  maxAssertionLifetimeSeconds?: number;
  /** Test hook: supply a key resolver instead of fetching the remote JWKS. */
  keyResolver?: JWTVerifyGetKey;
}

export interface VerifiedAssertion {
  itsId: string;
  sid: string;
  jti: string;
  transactionId: string;
  authTime: number;
  issuedAt: number;
  expiresAt: number;
}

export class AssertionVerificationError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AssertionVerificationError';
  }
}

export class CoreAssertionVerifier {
  private readonly keys: JWTVerifyGetKey;
  private readonly tolerance: number;
  private readonly maxLifetime: number;

  constructor(private readonly options: VerifierOptions) {
    this.keys =
      options.keyResolver ??
      createRemoteJWKSet(new URL(options.jwksUri), { cacheMaxAge: 10 * 60_000, cooldownDuration: 30_000, timeoutDuration: 5_000 });
    this.tolerance = options.clockToleranceSeconds ?? 5;
    this.maxLifetime = options.maxAssertionLifetimeSeconds ?? 120;
  }

  async verifyLoginAssertion(token: unknown, expected: { transactionId: string }): Promise<VerifiedAssertion> {
    const payload = await this.verifySignedJwt(token, 'JWT', ['sub', 'sid', 'jti', 'txn', 'iat', 'exp', 'auth_time'], this.maxLifetime);

    if ((payload.exp as number) - (payload.iat as number) > this.maxLifetime) {
      throw new AssertionVerificationError('LIFETIME_TOO_LONG', 'assertion lifetime exceeds policy');
    }
    if (typeof payload.txn !== 'string' || payload.txn !== expected.transactionId) {
      throw new AssertionVerificationError('TRANSACTION_MISMATCH', 'assertion is not bound to this login transaction');
    }
    if (typeof payload.sid !== 'string' || !SID.test(payload.sid)) throw new AssertionVerificationError('SID_INVALID', 'invalid sid');
    if (typeof payload.sub !== 'string' || !ITS_ID.test(payload.sub)) throw new AssertionVerificationError('SUBJECT_INVALID', 'invalid sub');
    if (typeof payload.auth_time !== 'number') throw new AssertionVerificationError('AUTH_TIME_INVALID', 'invalid auth_time');

    await this.claimJti('assertion', payload);
    return {
      itsId: payload.sub,
      sid: payload.sid,
      jti: payload.jti as string,
      transactionId: payload.txn,
      authTime: payload.auth_time,
      issuedAt: payload.iat as number,
      expiresAt: payload.exp as number,
    };
  }

  async verifyLogoutToken(token: unknown): Promise<{ itsId: string | undefined; sid: string; jti: string }> {
    const payload = await this.verifySignedJwt(token, 'logout+jwt', ['iat', 'exp', 'jti', 'events', 'sid'], 300);
    const events = payload.events as Record<string, unknown> | undefined;
    if (!events || typeof events !== 'object' || typeof events[BACKCHANNEL_LOGOUT_EVENT] !== 'object') {
      throw new AssertionVerificationError('LOGOUT_EVENT_MISSING', 'logout token lacks the back-channel logout event');
    }
    if ('nonce' in payload) throw new AssertionVerificationError('NONCE_NOT_ALLOWED', 'logout token must not contain a nonce');
    if (typeof payload.sid !== 'string' || !SID.test(payload.sid)) throw new AssertionVerificationError('SID_INVALID', 'invalid sid');
    await this.claimJti('logout', payload);
    return { itsId: payload.sub, sid: payload.sid, jti: payload.jti as string };
  }

  private async verifySignedJwt(token: unknown, typ: string, requiredClaims: string[], maxAgeSeconds: number): Promise<JWTPayload> {
    if (typeof token !== 'string' || token.length > 8192 || !COMPACT_JWS.test(token)) {
      throw new AssertionVerificationError('MALFORMED', 'token is not a compact JWS');
    }
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new AssertionVerificationError('MALFORMED', 'unreadable protected header');
    }
    if (header.alg !== 'RS256') throw new AssertionVerificationError('ALG_NOT_ALLOWED', 'only RS256 is accepted');
    if (typeof header.kid !== 'string' || header.kid.length === 0) throw new AssertionVerificationError('KID_MISSING', 'kid is required');
    if (header.typ !== typ) throw new AssertionVerificationError('TYP_INVALID', `typ must be ${typ}`);

    try {
      const { payload } = await jwtVerify(token, this.keys, {
        issuer: this.options.issuer,
        audience: this.options.clientId,
        algorithms: ['RS256'],
        typ,
        clockTolerance: this.tolerance,
        maxTokenAge: `${maxAgeSeconds}s`,
        requiredClaims,
      });
      // Exact audience: a single string, not an array that merely contains this client.
      if (payload.aud !== this.options.clientId) {
        throw new AssertionVerificationError('AUDIENCE_MISMATCH', 'aud must equal this client_id exactly');
      }
      return payload;
    } catch (error) {
      throw CoreAssertionVerifier.mapError(error);
    }
  }

  private async claimJti(kind: string, payload: JWTPayload): Promise<void> {
    if (typeof payload.jti !== 'string' || payload.jti.length < 16 || payload.jti.length > 128) {
      throw new AssertionVerificationError('JTI_INVALID', 'invalid jti');
    }
    const ttl = Math.max(1, (payload.exp as number) - Math.floor(Date.now() / 1000) + this.tolerance);
    const fresh = await this.options.replayStore.claim(`${kind}:${payload.jti}`, ttl);
    if (!fresh) throw new AssertionVerificationError('REPLAYED', 'token has already been used');
  }

  private static mapError(error: unknown): AssertionVerificationError {
    if (error instanceof AssertionVerificationError) return error;
    if (error instanceof errors.JWTExpired) return new AssertionVerificationError('EXPIRED', 'token has expired');
    if (error instanceof errors.JWTClaimValidationFailed) {
      const claim = error.claim;
      const code = claim === 'aud' ? 'AUDIENCE_MISMATCH' : claim === 'iss' ? 'ISSUER_MISMATCH' : claim === 'iat' ? 'IAT_INVALID' : claim === 'typ' ? 'TYP_INVALID' : `CLAIM_INVALID_${String(claim).toUpperCase()}`;
      return new AssertionVerificationError(code, `claim validation failed: ${claim}`);
    }
    if (error instanceof errors.JWKSNoMatchingKey) return new AssertionVerificationError('UNKNOWN_KID', 'no matching key in JWKS');
    if (error instanceof errors.JWSSignatureVerificationFailed) return new AssertionVerificationError('SIGNATURE_INVALID', 'signature verification failed');
    if (error instanceof errors.JOSEAlgNotAllowed) return new AssertionVerificationError('ALG_NOT_ALLOWED', 'algorithm not allowed');
    if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return new AssertionVerificationError('JWKS_UNAVAILABLE', 'verification keys unavailable');
    return new AssertionVerificationError('INVALID_TOKEN', 'token could not be verified');
  }
}

/** Redis-backed one-time-use store (SET NX EX) shared by all BU backend instances. */
export class RedisReplayStore implements ReplayStore {
  constructor(
    private readonly redis: { set(key: string, value: string, ex: 'EX', ttl: number, nx: 'NX'): Promise<'OK' | null> },
    private readonly prefix: string,
  ) {}

  async claim(key: string, ttlSeconds: number): Promise<boolean> {
    return (await this.redis.set(`${this.prefix}:${key}`, '1', 'EX', ttlSeconds, 'NX')) === 'OK';
  }
}

export class MemoryReplayStore implements ReplayStore {
  private readonly seen = new Map<string, number>();

  async claim(key: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now();
    for (const [k, expiry] of this.seen) if (expiry < now) this.seen.delete(k);
    if (this.seen.has(key)) return false;
    this.seen.set(key, now + ttlSeconds * 1000);
    return true;
  }
}
