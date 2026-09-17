import { Inject, Injectable, Logger } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';
import { RedisKeys } from '@common/constants/redis-keys.constants';
import { SESSION_HANDLE_PATTERN } from '@common/constants/validation.constants';
import { randomId, randomToken, sha256Hex } from '@common/utils/crypto.util';
import { AuditService } from '@core/audit/audit.service';
import { AuthSessionRepository } from '@core/database/repositories/auth-session.repository';
import { REDIS } from '@core/cache/redis.module';
import type { AuthenticatedUser } from '@shared/types/auth.types';
import { FederationSession } from '@shared/types/session.types';
import {
  bindingAuditMetadata,
  checkSessionBinding,
  normalizeIp,
  normalizeUserAgent,
  type SessionBindingContext,
  type SessionBindingFailure,
} from '@common/security/session-binding';

/**
 * Central federation session.
 *
 * Two identifiers by design:
 *  - handle : 256-bit opaque secret, only in the HttpOnly cookie; Redis indexes it by SHA-256.
 *  - sid    : non-secret session id placed in assertions/logout tokens so BUs can correlate.
 * Knowing a `sid` (e.g. from an assertion) therefore never lets anyone hijack the session.
 */
export type FederationSessionFailure = 'INVALID_HANDLE' | 'NOT_FOUND' | SessionBindingFailure;

@Injectable()
export class FederationSessionService {
  private readonly logger = new Logger(FederationSessionService.name);

  constructor(
    @Inject(REDIS) private readonly redis: Redis,
    private readonly store: AuthSessionRepository,
    private readonly config: AppConfig,
    private readonly audit: AuditService,
  ) {}

  async create(user: AuthenticatedUser, ctx: { ip: string; userAgent?: string; authMethod: string }): Promise<{ session: FederationSession; handle: string }> {
    const env = this.config.env;
    const now = Date.now();
    const handle = randomToken(32);
    const session: FederationSession = {
      sid: randomId('sid'),
      its_id: user.itsId,
      identity_type: user.identityType,
      display_name: user.displayName,
      auth_method: ctx.authMethod,
      auth_time: Math.floor(now / 1000),
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + env.SESSION_IDLE_TTL_SECONDS * 1000).toISOString(),
      absolute_expires_at: new Date(now + env.SESSION_ABSOLUTE_TTL_SECONDS * 1000).toISOString(),
      is_active: true,
      handle_hash: sha256Hex(handle),
      ip_address: normalizeIp(ctx.ip),
      user_agent: normalizeUserAgent(ctx.userAgent),
    };

    await this.redis
      .multi()
      .set(RedisKeys.session(session.sid), JSON.stringify(session), 'EX', env.SESSION_IDLE_TTL_SECONDS)
      .set(RedisKeys.sessionHandle(session.handle_hash), session.sid, 'EX', env.SESSION_IDLE_TTL_SECONDS)
      .sadd(RedisKeys.userSessions(user.itsId), session.sid)
      .expire(RedisKeys.userSessions(user.itsId), env.SESSION_ABSOLUTE_TTL_SECONDS)
      .exec();

    await this.store.create({
      sid: session.sid,
      itsId: user.itsId,
      authMethod: ctx.authMethod,
      createdAt: new Date(session.created_at),
      expiresAt: new Date(session.expires_at),
      absoluteExpiresAt: new Date(session.absolute_expires_at),
      ipAddress: ctx.ip,
      userAgent: ctx.userAgent?.slice(0, 512) ?? null,
    });
    return { session, handle };
  }

  /**
   * The single path from a `federation_session` cookie to a session, for every caller.
   *
   * Handle shape, index lookup, active/absolute-expiry (in `get`) and binding to the originating
   * IP + User-Agent are all enforced here. Requiring `ctx` in the signature is what keeps that
   * guarantee: a new call site cannot resolve a session without supplying the request it came from.
   */
  async getByHandle(handle: string | undefined, ctx: SessionBindingContext): Promise<FederationSession | null> {
    const result = await this.resolveByHandle(handle, ctx);
    return result.ok ? result.session : null;
  }

  /** Same checks as `getByHandle`, keeping the reason so a caller can audit the refusal. */
  async resolveByHandle(
    handle: string | undefined,
    ctx: SessionBindingContext,
  ): Promise<{ ok: true; session: FederationSession } | { ok: false; reason: FederationSessionFailure; audit?: Record<string, unknown> }> {
    if (!handle || !SESSION_HANDLE_PATTERN.test(handle)) return { ok: false, reason: 'INVALID_HANDLE' };
    const handleHash = sha256Hex(handle);
    const sid = await this.redis.get(RedisKeys.sessionHandle(handleHash));
    if (!sid) return { ok: false, reason: 'NOT_FOUND' };
    const session = await this.get(sid);
    if (!session || session.handle_hash !== handleHash) return { ok: false, reason: 'NOT_FOUND' };

    const stored = { ipAddress: session.ip_address, userAgent: session.user_agent };
    const binding = checkSessionBinding(stored, ctx);
    if (!binding.ok) {
      const audit = bindingAuditMetadata(binding.reason, stored, ctx);
      this.logger.warn({ msg: 'federation session rejected', sid: session.sid, ...audit });
      await this.audit.record({
        eventType: 'FEDERATION_SESSION_BINDING_REJECTED',
        outcome: 'FAILURE',
        itsId: session.its_id,
        sid: session.sid,
        metadata: audit,
      });
      return { ok: false, reason: binding.reason, audit };
    }
    return { ok: true, session };
  }

  async get(sid: string): Promise<FederationSession | null> {
    const raw = await this.redis.get(RedisKeys.session(sid));
    if (!raw) return null;
    const session = JSON.parse(raw) as FederationSession;
    if (!session.is_active || Date.parse(session.absolute_expires_at) <= Date.now()) return null;
    return session;
  }

  /** Sliding idle expiry, capped by the absolute lifetime. Returns remaining cookie max-age (s). */
  async touch(session: FederationSession): Promise<number> {
    const now = Date.now();
    const absolute = Date.parse(session.absolute_expires_at);
    const expires = Math.min(now + this.config.env.SESSION_IDLE_TTL_SECONDS * 1000, absolute);
    const ttl = Math.max(1, Math.floor((expires - now) / 1000));
    session.expires_at = new Date(expires).toISOString();
    await this.redis
      .multi()
      .set(RedisKeys.session(session.sid), JSON.stringify(session), 'EX', ttl)
      .expire(RedisKeys.sessionHandle(session.handle_hash), ttl)
      .expire(RedisKeys.sessionClients(session.sid), ttl)
      .exec();
    await this.store.touch(session.sid, new Date(session.expires_at));
    return ttl;
  }

  async addClient(session: FederationSession, clientId: string): Promise<void> {
    const ttl = Math.max(1, Math.floor((Date.parse(session.absolute_expires_at) - Date.now()) / 1000));
    await this.redis.multi().sadd(RedisKeys.sessionClients(session.sid), clientId).expire(RedisKeys.sessionClients(session.sid), ttl).exec();
    await this.store.recordClientAssertion(session.sid, clientId);
  }

  async clients(sid: string): Promise<string[]> {
    const fromRedis = await this.redis.smembers(RedisKeys.sessionClients(sid));
    if (fromRedis.length > 0) return fromRedis.sort();
    return this.store.clientIds(sid);
  }

  /** Revokes a session everywhere. Returns what was revoked (for back-channel fan-out) or null if already gone. */
  async revoke(sid: string, reason: string): Promise<{ sid: string; its_id: string; clients: string[] } | null> {
    const raw = await this.redis.get(RedisKeys.session(sid));
    const stored = await this.store.findRevocationState(sid);
    if (!raw && (!stored || stored.revokedAt)) return null;

    const session = raw ? (JSON.parse(raw) as FederationSession) : null;
    const itsId = session?.its_id ?? stored!.itsId;
    const clients = await this.clients(sid);

    const tx = this.redis.multi().del(RedisKeys.session(sid)).del(RedisKeys.sessionClients(sid)).srem(RedisKeys.userSessions(itsId), sid);
    if (session) tx.del(RedisKeys.sessionHandle(session.handle_hash));
    await tx.exec();

    await this.store.revoke(sid, reason);
    this.logger.log({ msg: 'federation session revoked', sid, its_id: itsId, reason, clients: clients.length });
    return { sid, its_id: itsId, clients };
  }

  async revokeAllForUser(itsId: string, reason: string) {
    const fromRedis = await this.redis.smembers(RedisKeys.userSessions(itsId));
    const fromDb = await this.store.activeSidsForUser(itsId);
    const sids = [...new Set([...fromRedis, ...fromDb])];
    const revoked = [];
    for (const sid of sids) {
      const result = await this.revoke(sid, reason);
      if (result) revoked.push(result);
    }
    return revoked;
  }
}
