import { Inject, Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import Redis from 'ioredis';
import { DataSource } from 'typeorm';
import { AppConfig } from '@config/config.module';
import { RedisKeys } from '@common/constants/redis-keys.constants';
import { SESSION_HANDLE_PATTERN } from '@common/constants/validation.constants';
import { randomId, randomToken, sha256Hex } from '@common/utils/crypto.util';
import { REDIS } from '@core/cache/redis.module';
import type { AuthenticatedUser } from '@shared/types/auth.types';
import { FederationSession } from '@shared/types/session.types';

/**
 * Central federation session.
 *
 * Two identifiers by design:
 *  - handle : 256-bit opaque secret, only in the HttpOnly cookie; Redis indexes it by SHA-256.
 *  - sid    : non-secret session id placed in assertions/logout tokens so BUs can correlate.
 * Knowing a `sid` (e.g. from an assertion) therefore never lets anyone hijack the session.
 */
@Injectable()
export class FederationSessionService {
  private readonly logger = new Logger(FederationSessionService.name);

  constructor(
    @Inject(REDIS) private readonly redis: Redis,
    @InjectDataSource() private readonly db: DataSource,
    private readonly config: AppConfig,
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
    };

    await this.redis
      .multi()
      .set(RedisKeys.session(session.sid), JSON.stringify(session), 'EX', env.SESSION_IDLE_TTL_SECONDS)
      .set(RedisKeys.sessionHandle(session.handle_hash), session.sid, 'EX', env.SESSION_IDLE_TTL_SECONDS)
      .sadd(RedisKeys.userSessions(user.itsId), session.sid)
      .expire(RedisKeys.userSessions(user.itsId), env.SESSION_ABSOLUTE_TTL_SECONDS)
      .exec();

    await this.db.query(
      `INSERT INTO auth_sessions (sid, its_id, auth_method, created_at, expires_at, absolute_expires_at, last_seen_at, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8)`,
      [session.sid, user.itsId, ctx.authMethod, session.created_at, session.expires_at, session.absolute_expires_at, ctx.ip, ctx.userAgent?.slice(0, 512) ?? null],
    );
    return { session, handle };
  }

  async getByHandle(handle: string | undefined): Promise<FederationSession | null> {
    if (!handle || !SESSION_HANDLE_PATTERN.test(handle)) return null;
    const handleHash = sha256Hex(handle);
    const sid = await this.redis.get(RedisKeys.sessionHandle(handleHash));
    if (!sid) return null;
    const session = await this.get(sid);
    if (!session || session.handle_hash !== handleHash) return null;
    return session;
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
    await this.db.query(`UPDATE auth_sessions SET expires_at = $2, last_seen_at = now() WHERE sid = $1`, [session.sid, session.expires_at]);
    return ttl;
  }

  async addClient(session: FederationSession, clientId: string): Promise<void> {
    const ttl = Math.max(1, Math.floor((Date.parse(session.absolute_expires_at) - Date.now()) / 1000));
    await this.redis.multi().sadd(RedisKeys.sessionClients(session.sid), clientId).expire(RedisKeys.sessionClients(session.sid), ttl).exec();
    await this.db.query(
      `INSERT INTO auth_session_clients (sid, client_id) VALUES ($1, $2)
       ON CONFLICT (sid, client_id) DO UPDATE SET last_assertion_at = now(), assertion_count = auth_session_clients.assertion_count + 1`,
      [session.sid, clientId],
    );
  }

  async clients(sid: string): Promise<string[]> {
    const fromRedis = await this.redis.smembers(RedisKeys.sessionClients(sid));
    if (fromRedis.length > 0) return fromRedis.sort();
    const rows = (await this.db.query(`SELECT client_id FROM auth_session_clients WHERE sid = $1 ORDER BY client_id`, [sid])) as { client_id: string }[];
    return rows.map((r) => r.client_id);
  }

  /** Revokes a session everywhere. Returns what was revoked (for back-channel fan-out) or null if already gone. */
  async revoke(sid: string, reason: string): Promise<{ sid: string; its_id: string; clients: string[] } | null> {
    const raw = await this.redis.get(RedisKeys.session(sid));
    const dbRow = (await this.db.query(`SELECT its_id, revoked_at FROM auth_sessions WHERE sid = $1`, [sid])) as { its_id: string; revoked_at: Date | null }[];
    if (!raw && (!dbRow[0] || dbRow[0].revoked_at)) return null;

    const session = raw ? (JSON.parse(raw) as FederationSession) : null;
    const itsId = session?.its_id ?? dbRow[0].its_id;
    const clients = await this.clients(sid);

    const tx = this.redis.multi().del(RedisKeys.session(sid)).del(RedisKeys.sessionClients(sid)).srem(RedisKeys.userSessions(itsId), sid);
    if (session) tx.del(RedisKeys.sessionHandle(session.handle_hash));
    await tx.exec();

    await this.db.query(`UPDATE auth_sessions SET revoked_at = now(), revoke_reason = $2 WHERE sid = $1 AND revoked_at IS NULL`, [sid, reason.slice(0, 64)]);
    this.logger.log({ msg: 'federation session revoked', sid, its_id: itsId, reason, clients: clients.length });
    return { sid, its_id: itsId, clients };
  }

  async revokeAllForUser(itsId: string, reason: string) {
    const fromRedis = await this.redis.smembers(RedisKeys.userSessions(itsId));
    const fromDb = (await this.db.query(
      `SELECT sid FROM auth_sessions WHERE its_id = $1 AND revoked_at IS NULL AND absolute_expires_at > now()`,
      [itsId],
    )) as { sid: string }[];
    const sids = [...new Set([...fromRedis, ...fromDb.map((r) => r.sid)])];
    const revoked = [];
    for (const sid of sids) {
      const result = await this.revoke(sid, reason);
      if (result) revoked.push(result);
    }
    return revoked;
  }
}
