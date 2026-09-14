import { Inject, Injectable } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfig } from '@config/config.module';
import { RedisKeys } from '@common/constants/redis-keys.constants';
import { STATE_PATTERN, TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';
import { DomainError, Errors } from '@common/errors/domain-error';
import { randomId, randomToken } from '@common/utils/crypto.util';
import { REDIS } from '@core/cache/redis.module';
import { LoginTransaction } from '@shared/types/transaction.types';

/** Atomic PENDING -> COMPLETED so a transaction can produce at most one assertion. */
const COMPLETE_SCRIPT = `
local v = redis.call('GET', KEYS[1])
if not v then return nil end
local o = cjson.decode(v)
if o['status'] ~= 'PENDING' then return 'USED' end
o['status'] = 'COMPLETED'
redis.call('SET', KEYS[1], cjson.encode(o), 'KEEPTTL')
return v`;

/**
 * Binds a transaction to a federation session and extends it to the session lifetime.
 * ARGV: sid, ttl seconds, overwrite ('1' after a fresh sign-in, '0' to require the same session).
 */
const BIND_SESSION_SCRIPT = `
local v = redis.call('GET', KEYS[1])
if not v then return nil end
local o = cjson.decode(v)
local bound = o['sid']
if ARGV[3] ~= '1' and type(bound) == 'string' and bound ~= ARGV[1] then return 'MISMATCH' end
o['sid'] = ARGV[1]
redis.call('SET', KEYS[1], cjson.encode(o), 'EX', tonumber(ARGV[2]))
return 'OK'`;

@Injectable()
export class TransactionService {
  constructor(
    @Inject(REDIS) private readonly redis: Redis,
    private readonly config: AppConfig,
  ) {}

  static generateId(): string {
    return randomId('txn');
  }

  async create(input: Omit<LoginTransaction, 'csrf' | 'status' | 'created_at' | 'expires_at'>): Promise<LoginTransaction> {
    if (!TRANSACTION_ID_PATTERN.test(input.transaction_id)) throw Errors.invalidRequest('transaction_id is malformed');
    if (input.display !== 'portal' && (!input.state || !STATE_PATTERN.test(input.state))) {
      throw Errors.invalidRequest('state is required (8-512 visible ASCII characters)');
    }

    const ttl = this.config.env.TRANSACTION_TTL_SECONDS;
    const now = new Date();
    const txn: LoginTransaction = {
      ...input,
      csrf: randomToken(),
      status: 'PENDING',
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + ttl * 1000).toISOString(),
    };
    const key = RedisKeys.transaction(input.transaction_id);
    const created = await this.redis.set(key, JSON.stringify(txn), 'EX', ttl, 'NX');
    if (created === 'OK') return txn;

    // Same parameters (e.g. iframe reload) resume the pending transaction; a completed one is reported as used;
    // anything else is a conflict.
    const existing = await this.get(input.transaction_id);
    const sameRequest =
      existing !== null &&
      existing.client_id === input.client_id &&
      existing.state === input.state &&
      existing.display === input.display &&
      existing.embed_origin === input.embed_origin &&
      existing.callback_uri === input.callback_uri;
    if (sameRequest && existing.status === 'PENDING') return existing;
    if (sameRequest) throw Errors.transactionUsed();
    throw new DomainError('TRANSACTION_CONFLICT', 'transaction_id is already in use', 409);
  }

  async get(transactionId: unknown): Promise<LoginTransaction | null> {
    if (typeof transactionId !== 'string' || !TRANSACTION_ID_PATTERN.test(transactionId)) return null;
    const raw = await this.redis.get(RedisKeys.transaction(transactionId));
    return raw ? (JSON.parse(raw) as LoginTransaction) : null;
  }

  /** Seconds until the transaction expires; 0 when it no longer exists. */
  async remainingSeconds(transactionId: string): Promise<number> {
    if (!TRANSACTION_ID_PATTERN.test(transactionId)) return 0;
    return Math.max(0, await this.redis.ttl(RedisKeys.transaction(transactionId)));
  }

  /** Loads a PENDING transaction bound to the expected client, or throws. */
  async requirePending(transactionId: unknown, clientId: string | null): Promise<LoginTransaction> {
    const txn = await this.get(transactionId);
    if (!txn) throw Errors.transactionInvalid();
    if (txn.status !== 'PENDING') throw Errors.transactionUsed();
    if (txn.client_id !== clientId) throw Errors.transactionInvalid();
    return txn;
  }

  async complete(transactionId: string): Promise<LoginTransaction> {
    const result = (await this.redis.eval(COMPLETE_SCRIPT, 1, RedisKeys.transaction(transactionId))) as string | null;
    if (result === null) throw Errors.transactionInvalid();
    if (result === 'USED') throw Errors.transactionUsed();
    return { ...(JSON.parse(result) as LoginTransaction), status: 'COMPLETED' };
  }

  /**
   * Portal pages keep using their transaction's CSRF token after sign-in (select/switch workspace, logout), so the
   * transaction must live as long as the session instead of TRANSACTION_TTL_SECONDS. Returns false when the
   * transaction is gone or bound to a different session.
   */
  async bindToSession(transactionId: string, session: { sid: string; absolute_expires_at: string }, overwrite = false): Promise<boolean> {
    const ttl = Math.floor((Date.parse(session.absolute_expires_at) - Date.now()) / 1000);
    if (ttl <= 0) return false;
    const result = await this.redis.eval(BIND_SESSION_SCRIPT, 1, RedisKeys.transaction(transactionId), session.sid, String(ttl), overwrite ? '1' : '0');
    return result === 'OK';
  }
}
