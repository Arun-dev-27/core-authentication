import Redis from 'ioredis';

/**
 * Redis key design (Identity Federation). All keys have a TTL unless noted.
 *
 *  federation:txn:<transaction_id>               JSON login transaction                 TTL TRANSACTION_TTL_SECONDS
 *  federation:session:<sid>                      JSON central federation session        TTL min(idle, absolute remaining)
 *  federation:session-handle:<sha256(handle)>    sid (cookie handle -> session index)   same TTL as session
 *  federation:user-sessions:<its_id>             SET of sids for a user                 TTL SESSION_ABSOLUTE_TTL_SECONDS
 *  federation:session-clients:<sid>              SET of client_ids that got assertions  same TTL as session
 *  federation:jti:<jti>                          issued-assertion marker (traceability) TTL ASSERTION_TTL_SECONDS
 *  federation:client-cfg:<client_id>             cached client configuration JSON       TTL CLIENT_CACHE_TTL_SECONDS
 *  ratelimit:login:ip:<ip>                       attempt counter                        TTL LOGIN_IP_WINDOW_SECONDS
 *  ratelimit:login:id:<sha256(identifier)>       failure counter                        TTL LOGIN_IDENTIFIER_WINDOW_SECONDS
 */
export const RedisKeys = {
  transaction: (txn: string) => `federation:txn:${txn}`,
  session: (sid: string) => `federation:session:${sid}`,
  sessionHandle: (handleHash: string) => `federation:session-handle:${handleHash}`,
  userSessions: (itsId: string) => `federation:user-sessions:${itsId}`,
  sessionClients: (sid: string) => `federation:session-clients:${sid}`,
  issuedJti: (jti: string) => `federation:jti:${jti}`,
  clientConfig: (clientId: string) => `federation:client-cfg:${clientId}`,
  ipAttempts: (ip: string) => `ratelimit:login:ip:${ip}`,
  identifierFailures: (identifierHash: string) => `ratelimit:login:id:${identifierHash}`,
};
