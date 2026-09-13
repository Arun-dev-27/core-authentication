import { createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { calculateJwkThumbprint, exportJWK, JWK, SignJWT } from 'jose';

export const SERVICE_TOKEN_TYP = 'client-authentication+jwt';

/**
 * This backend's own identity towards Core APIs - replaces API keys.
 *
 *  - the RSA private key stays with the BU (production: loaded from the BU's own secret manager;
 *    local dev: generated once into a git-ignored file)
 *  - the public key is published at GET /.well-known/jwks.json and registered in the Authorization
 *    service as the principal's jwks_uri
 *  - each request carries a fresh single-use token: iss = sub = principal id, aud = Authorization audience
 */
export class ServiceCredentials {
  private constructor(
    readonly principalId: string,
    private readonly privateKey: KeyObject,
    private readonly publicJwk: JWK,
  ) {}

  static async load(principalId: string, keyFile: string): Promise<ServiceCredentials> {
    if (!existsSync(keyFile)) {
      if (process.env.NODE_ENV === 'production') throw new Error(`service key not found at ${keyFile}`);
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 3072,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
      });
      mkdirSync(dirname(keyFile), { recursive: true });
      writeFileSync(keyFile, privateKey, { mode: 0o600 });
    }
    const privateKey = createPrivateKey(readFileSync(keyFile, 'utf8'));
    const exported = await exportJWK(createPublicKey(privateKey));
    const kid = `${principalId}-${(await calculateJwkThumbprint(exported)).slice(0, 16)}`;
    return new ServiceCredentials(principalId, privateKey, { kty: 'RSA', n: exported.n, e: exported.e, kid, alg: 'RS256', use: 'sig' });
  }

  jwks(): { keys: JWK[] } {
    return { keys: [this.publicJwk] };
  }

  mint(audience: string, ttlSeconds = 120): Promise<string> {
    const iat = Math.floor(Date.now() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', typ: SERVICE_TOKEN_TYP, kid: this.publicJwk.kid! })
      .setIssuer(this.principalId)
      .setSubject(this.principalId)
      .setAudience(audience)
      .setJti(randomUUID())
      .setIssuedAt(iat)
      .setExpirationTime(iat + ttlSeconds)
      .sign(this.privateKey);
  }
}
