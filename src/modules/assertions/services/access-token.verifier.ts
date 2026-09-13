import { Injectable } from '@nestjs/common';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { AppConfig } from '@config/config.module';
import { Errors } from '@common/errors/domain-error';
import { KeyStore } from '@modules/keys/services/key-store.service';
import { ActiveScopeClaim } from '@shared/types/federation-client.types';
import { ACCESS_TOKEN_TYP } from './assertion.service';

const COMPACT_JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SCOPE_TYPES = ['CORE', 'BUSINESS_UNIT', 'UTILITY'];

export interface VerifiedAccessToken {
  itsId: string;
  sid?: string;
  jti: string;
  scope?: ActiveScopeClaim;
}

/**
 * Verifies administrator access tokens addressed to THIS service (aud = issuer), using the same public
 * keys published in JWKS. Used for administrator-initiated federation logout instead of a shared admin key.
 */
@Injectable()
export class AccessTokenVerifier {
  constructor(
    private readonly keys: KeyStore,
    private readonly config: AppConfig,
  ) {}

  async verify(authorization: string | undefined): Promise<VerifiedAccessToken> {
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) throw Errors.unauthorized();
    const token = authorization.slice(7).trim();
    if (token.length > 8192 || !COMPACT_JWS.test(token)) throw Errors.unauthorized();
    try {
      const { payload } = await jwtVerify(token, createLocalJWKSet(this.keys.jwks() as never), {
        issuer: this.config.issuer,
        audience: this.config.issuer,
        algorithms: ['RS256'],
        typ: ACCESS_TOKEN_TYP,
        clockTolerance: 5,
        maxTokenAge: `${this.config.env.ACCESS_TOKEN_TTL_SECONDS}s`,
        requiredClaims: ['sub', 'jti', 'iat', 'exp'],
      });
      if (payload.aud !== this.config.issuer || payload.token_use !== 'access' || typeof payload.sub !== 'string') throw Errors.unauthorized();
      let scope: ActiveScopeClaim | undefined;
      if (payload.role_id !== undefined) {
        const scopeId = payload.scope_id ?? null;
        const valid =
          typeof payload.role_id === 'string' &&
          UUID.test(payload.role_id) &&
          typeof payload.scope_type === 'string' &&
          SCOPE_TYPES.includes(payload.scope_type) &&
          (payload.scope_type === 'CORE' ? scopeId === null : typeof scopeId === 'string' && UUID.test(scopeId));
        if (!valid) throw Errors.unauthorized();
        scope = { role_id: payload.role_id as string, scope_type: payload.scope_type as ActiveScopeClaim['scope_type'], scope_id: scopeId as string | null };
      }
      return { itsId: payload.sub, sid: typeof payload.sid === 'string' ? payload.sid : undefined, jti: payload.jti as string, ...(scope ? { scope } : {}) };
    } catch {
      throw Errors.unauthorized();
    }
  }
}
