import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { SignJWT } from 'jose';
import { AppConfig } from '@config/config.module';
import { RedisKeys } from '@common/constants/redis-keys.constants';
import { REDIS } from '@core/cache/redis.module';
import { KeyStore } from '@modules/keys/services/key-store.service';

export interface AssertionInput {
  itsId: string;
  clientId: string;
  sid: string;
  transactionId: string;
  authTime: number;
}

export interface IssuedAssertion {
  /** Compact JWS: header.payload.signature */
  assertion: string;
  jti: string;
  iat: number;
  exp: number;
}

export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
/** Service token this service presents to other Core APIs (private_key_jwt style). */
export const SERVICE_TOKEN_TYP = 'client-authentication+jwt';
/** Administrator access token (RFC 9068). */
export const ACCESS_TOKEN_TYP = 'at+jwt';

/**
 * Issues every RS256 token of the federation, all verifiable through /.well-known/jwks.json.
 * Distinct `typ` + `aud` per token kind prevent one kind being accepted as another.
 * Claims are deliberately minimal: identity + binding only. No roles, permissions, profile data or credentials.
 */
@Injectable()
export class AssertionService {
  constructor(
    private readonly keys: KeyStore,
    private readonly config: AppConfig,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  /** Login assertion for one Business Unit client (typ JWT, aud = client_id, 60 s). */
  async issue(input: AssertionInput): Promise<IssuedAssertion> {
    const { kid, key } = this.keys.signingKey();
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + this.config.env.ASSERTION_TTL_SECONDS;
    const jti = randomUUID();

    const assertion = await new SignJWT({ sid: input.sid, txn: input.transactionId, auth_time: input.authTime })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid })
      .setIssuer(this.config.issuer)
      .setSubject(input.itsId)
      .setAudience(input.clientId)
      .setJti(jti)
      .setIssuedAt(iat)
      .setExpirationTime(exp)
      .sign(key);

    // Traceability marker only (no token material). Verifiers enforce replay protection on their side.
    await this.redis.set(RedisKeys.issuedJti(jti), `${input.clientId}|${input.sid}`, 'EX', this.config.env.ASSERTION_TTL_SECONDS);
    return { assertion, jti, iat, exp };
  }

  /** OpenID Back-Channel Logout 1.0 style logout token, verified by BUs against the same JWKS. */
  async issueLogoutToken(input: { itsId: string; clientId: string; sid: string }): Promise<{ token: string; jti: string }> {
    const { kid, key } = this.keys.signingKey();
    const iat = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    const token = await new SignJWT({ sid: input.sid, events: { [BACKCHANNEL_LOGOUT_EVENT]: {} } })
      .setProtectedHeader({ alg: 'RS256', typ: 'logout+jwt', kid })
      .setIssuer(this.config.issuer)
      .setSubject(input.itsId)
      .setAudience(input.clientId)
      .setJti(jti)
      .setIssuedAt(iat)
      .setExpirationTime(iat + 120)
      .sign(key);
    return { token, jti };
  }

  /**
   * Single-use service token proving this service's identity to the Authorization service
   * (iss = sub = SERVICE_PRINCIPAL_ID, aud = AUTHZ_AUDIENCE). Minted per request; replaces API keys.
   */
  async issueServiceToken(audience = this.config.env.AUTHZ_AUDIENCE): Promise<string> {
    const { kid, key } = this.keys.signingKey();
    const principal = this.config.env.SERVICE_PRINCIPAL_ID;
    const iat = Math.floor(Date.now() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', typ: SERVICE_TOKEN_TYP, kid })
      .setIssuer(principal)
      .setSubject(principal)
      .setAudience(audience)
      .setJti(randomUUID())
      .setIssuedAt(iat)
      .setExpirationTime(iat + this.config.env.SERVICE_TOKEN_TTL_SECONDS)
      .sign(key);
  }

  /**
   * Access token for one API audience. Carries the person and, after POST /select-scope, the active workspace
   * (role_id, scope_type, scope_id) - never permissions; the Authorization service resolves those per request.
   */
  async issueAccessToken(input: {
    itsId: string;
    sid: string;
    audience: string;
    scope?: { role_id: string; scope_type: string; scope_id: string | null };
  }): Promise<{ token: string; jti: string; expiresIn: number }> {
    const { kid, key } = this.keys.signingKey();
    const iat = Math.floor(Date.now() / 1000);
    const expiresIn = this.config.env.ACCESS_TOKEN_TTL_SECONDS;
    const jti = randomUUID();
    const scopeClaims = input.scope ? { role_id: input.scope.role_id, scope_type: input.scope.scope_type, scope_id: input.scope.scope_id } : {};
    const token = await new SignJWT({ token_use: 'access', sid: input.sid, ...scopeClaims })
      .setProtectedHeader({ alg: 'RS256', typ: ACCESS_TOKEN_TYP, kid })
      .setIssuer(this.config.issuer)
      .setSubject(input.itsId)
      .setAudience(input.audience)
      .setJti(jti)
      .setIssuedAt(iat)
      .setExpirationTime(iat + expiresIn)
      .sign(key);
    return { token, jti, expiresIn };
  }
}
