import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyRequest } from 'fastify';

/**
 * Session binding: a session cookie is only honoured from the same IP address and User-Agent it was
 * established with. One implementation, used by every session-based flow in this service, so the two
 * cookies cannot drift apart in what they enforce.
 *
 * Trade-off, deliberately accepted: a client whose IP changes mid-session (cellular <-> WiFi, CGNAT
 * rotation) or whose browser self-updates its UA string is signed out and must authenticate again.
 */

/** Comparison/storage width for a User-Agent; matches the `user_agent` column writes. */
export const USER_AGENT_MAX_LENGTH = 512;

/** What a session recorded when it was created. */
export interface StoredSessionBinding {
  ipAddress: string | null;
  userAgent: string | null;
}

/** What the current request presents. */
export interface SessionBindingContext {
  ip: string | null;
  userAgent: string | null;
}

export type SessionBindingFailure = 'IP_MISMATCH' | 'USER_AGENT_MISMATCH' | 'BINDING_MISSING';

export type SessionBindingResult = { ok: true } | { ok: false; reason: SessionBindingFailure };

/**
 * The request's client IP.
 *
 * Reads Fastify's `req.ip`, which resolves `X-Forwarded-For` **only** when the server was built with
 * `trustProxy` (driven by TRUST_PROXY); otherwise it is the raw socket address. So a client that is not
 * behind our trusted proxy cannot move this value by sending its own `X-Forwarded-For`. Parsing that
 * header here instead would trust exactly the input an attacker controls, which is why we never do.
 */
export function requestIp(req: FastifyRequest): string | null {
  return normalizeIp(req.ip);
}

export function requestUserAgent(req: FastifyRequest): string | null {
  return normalizeUserAgent(req.headers['user-agent']);
}

export function bindingContextOf(req: FastifyRequest): SessionBindingContext {
  return { ip: requestIp(req), userAgent: requestUserAgent(req) };
}

/**
 * Canonical IP text, so the same peer compares equal however it was written: an IPv4-mapped IPv6
 * address (`::ffff:203.0.113.7`) matches the plain IPv4 form Postgres `inet` gives back, a scope id is
 * dropped, and brackets/case are normalised.
 */
export function normalizeIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let ip = value.trim().toLowerCase();
  if (!ip) return null;
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const mappedV4 = /^(?:::ffff:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip);
  if (mappedV4) return mappedV4[1];
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

export function normalizeUserAgent(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const ua = value.trim();
  return ua.length > 0 ? ua.slice(0, USER_AGENT_MAX_LENGTH) : null;
}

/** Length is not secret (it is observable from the header), the bytes are compared without early exit. */
function equalsConstantTime(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Fails closed. A session row missing either recorded value, or a request presenting neither, cannot be
 * shown to belong to this caller, so it is refused rather than allowed through unchecked.
 */
export function checkSessionBinding(stored: StoredSessionBinding, current: SessionBindingContext): SessionBindingResult {
  const storedIp = normalizeIp(stored.ipAddress);
  const storedUserAgent = normalizeUserAgent(stored.userAgent);
  const currentIp = normalizeIp(current.ip);
  const currentUserAgent = normalizeUserAgent(current.userAgent);

  if (!storedIp || !storedUserAgent || !currentIp || !currentUserAgent) return { ok: false, reason: 'BINDING_MISSING' };
  if (!equalsConstantTime(storedIp, currentIp)) return { ok: false, reason: 'IP_MISMATCH' };
  if (!equalsConstantTime(storedUserAgent, currentUserAgent)) return { ok: false, reason: 'USER_AGENT_MISMATCH' };
  return { ok: true };
}

/** `203.0.113.7` -> `203.0.113.x`; `2001:db8:1:2::1` -> `2001:db8:1:x`. Never the whole address. */
export function maskIp(value: unknown): string | null {
  const ip = normalizeIp(value);
  if (!ip) return null;
  if (ip.includes(':')) {
    const groups = ip.split(':').filter((g) => g.length > 0).slice(0, 3);
    return `${groups.join(':')}:x`;
  }
  const octets = ip.split('.');
  if (octets.length !== 4) return 'x';
  return `${octets.slice(0, 3).join('.')}.x`;
}

/**
 * Short stable digest of a User-Agent. Two requests can be told apart, and a mismatch can be chased
 * across log lines, without the full string ever being written down.
 */
export function userAgentFingerprint(value: unknown): string | null {
  const ua = normalizeUserAgent(value);
  if (!ua) return null;
  return createHash('sha256').update(ua).digest('hex').slice(0, 12);
}

/** Masked, log-safe description of why a binding check failed. Carries no token, cookie or full UA. */
export function bindingAuditMetadata(
  reason: SessionBindingFailure,
  stored: StoredSessionBinding,
  current: SessionBindingContext,
): Record<string, unknown> {
  return {
    reason,
    stored_ip: maskIp(stored.ipAddress),
    current_ip: maskIp(current.ip),
    stored_ua_fp: userAgentFingerprint(stored.userAgent),
    current_ua_fp: userAgentFingerprint(current.userAgent),
  };
}
