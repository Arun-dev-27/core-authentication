import { randomBytes } from 'node:crypto';
import type Redis from 'ioredis';

export interface LocalSession {
  its_id: string;
  /** Central federation session id from the assertion - used for back-channel logout. */
  sid: string;
  auth_time: number;
  created_at: string;
}

/**
 * The application's OWN session (e.g. rms_session). Independent of the federation session:
 * created after assertion verification, destroyed by local logout or back-channel logout.
 *
 * Keys:  bu:<client_id>:session:<id>   JSON LocalSession   TTL
 *        bu:<client_id>:sid:<sid>      SET of local ids    TTL
 */
export class LocalSessionStore {
  constructor(
    private readonly redis: Redis,
    private readonly clientId: string,
    private readonly ttlSeconds = 8 * 3600,
  ) {}

  async create(input: Omit<LocalSession, 'created_at'>): Promise<string> {
    const id = randomBytes(32).toString('base64url');
    const session: LocalSession = { ...input, created_at: new Date().toISOString() };
    await this.redis
      .multi()
      .set(this.key(id), JSON.stringify(session), 'EX', this.ttlSeconds)
      .sadd(this.sidKey(input.sid), id)
      .expire(this.sidKey(input.sid), this.ttlSeconds)
      .exec();
    return id;
  }

  async get(id: string | undefined): Promise<LocalSession | null> {
    if (!id || !/^[A-Za-z0-9_-]{43}$/.test(id)) return null;
    const raw = await this.redis.get(this.key(id));
    return raw ? (JSON.parse(raw) as LocalSession) : null;
  }

  async destroy(id: string | undefined): Promise<LocalSession | null> {
    const session = await this.get(id);
    if (!session || !id) return null;
    await this.redis.multi().del(this.key(id)).srem(this.sidKey(session.sid), id).exec();
    return session;
  }

  async destroyBySid(sid: string): Promise<number> {
    const ids = await this.redis.smembers(this.sidKey(sid));
    if (ids.length === 0) return 0;
    await this.redis.del(...ids.map((id) => this.key(id)), this.sidKey(sid));
    return ids.length;
  }

  private key(id: string) {
    return `bu:${this.clientId}:session:${id}`;
  }

  private sidKey(sid: string) {
    return `bu:${this.clientId}:sid:${sid}`;
  }
}
