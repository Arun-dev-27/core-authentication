import type Redis from 'ioredis';
import type { ServiceCredentials } from './service-credentials';

export interface EffectiveAccess {
  its_id: string;
  client_id: string;
  access: 'GRANTED' | 'DENIED';
  reason?: string;
  application?: { code: string; name: string };
  environment?: string;
  roles: { role_id: string; role_name: string; scope_type: 'CORE' | 'BUSINESS_UNIT' | 'UTILITY'; scope_id: string | null }[];
  modules: { code: string; name: string; permissions: string[] }[];
  permissions: string[];
}

/**
 * Server-side calls from a BU backend to the Core Identity Authorization Service.
 * Authenticated with a single-use RS256 service token per request (verified against this backend's JWKS) - no API key.
 * Short Redis cache (default 30s) keeps business APIs fast; every failure DENIES (fail closed).
 * Identity Federation is never called for business requests.
 */
export class AuthorizationClient {
  constructor(
    private readonly baseUrl: string,
    private readonly credentials: Promise<ServiceCredentials>,
    private readonly audience: string,
    private readonly clientId: string,
    private readonly redis: Redis,
    private readonly cacheTtlSeconds = 30,
  ) {}

  async check(itsId: string, permission: string, module?: string): Promise<{ allowed: boolean; reason?: string }> {
    const key = `bu:${this.clientId}:authz:check:${itsId}:${module ?? '*'}:${permission}`;
    const cached = await this.redis.get(key);
    if (cached) return JSON.parse(cached) as { allowed: boolean; reason?: string };
    try {
      const result = await this.post<{ allowed: boolean; reason?: string }>('/authorization/check', { its_id: itsId, client_id: this.clientId, permission, module });
      const decision = { allowed: result.allowed === true, reason: result.reason };
      await this.redis.set(key, JSON.stringify(decision), 'EX', this.cacheTtlSeconds);
      return decision;
    } catch {
      return { allowed: false, reason: 'AUTHORIZATION_UNAVAILABLE' };
    }
  }

  async effective(itsId: string): Promise<EffectiveAccess> {
    const key = `bu:${this.clientId}:authz:effective:${itsId}`;
    const cached = await this.redis.get(key);
    if (cached) return JSON.parse(cached) as EffectiveAccess;
    const result = await this.post<EffectiveAccess>('/authorization/effective-permissions', { its_id: itsId, client_id: this.clientId });
    await this.redis.set(key, JSON.stringify(result), 'EX', this.cacheTtlSeconds);
    return result;
  }

  async forget(itsId: string): Promise<void> {
    const keys = await this.redis.keys(`bu:${this.clientId}:authz:*:${itsId}*`);
    if (keys.length) await this.redis.del(...keys);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const token = await (await this.credentials).mint(this.audience);
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) throw new Error(`authorization service responded ${res.status}`);
    return (await res.json()) as T;
  }
}
