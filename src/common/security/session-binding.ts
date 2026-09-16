import { createHash, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
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

/**
 * Which factors a session is pinned to.
 *
 *   'ip+ua'  both the originating IP and the User-Agent must match (the default).
 *   'ua'     User-Agent only. For platforms that never hand the application a trustworthy client
 *            IP: Render sits behind Cloudflare and exposes only a Cloudflare edge address, which is
 *            shared by unrelated clients and changes between requests -- pinning to it rejects the
 *            legitimate user while doing nothing to stop a thief on that same edge.
 */
export type SessionBindingMode = 'ip+ua' | 'ua';

let bindingMode: SessionBindingMode = 'ip+ua';

/** Called once from bootstrap, before the server accepts traffic. */
export function configureSessionBinding(mode: SessionBindingMode): void {
  bindingMode = mode;
}

export function sessionBindingMode(): SessionBindingMode {
  return bindingMode;
}

export type SessionBindingResult = { ok: true } | { ok: false; reason: SessionBindingFailure };

/**
 * The request's client IP.
 *
 * Reads Fastify's `req.ip`, which resolves `X-Forwarded-For` **only** when the server was built with
 * `trustProxy` (driven by TRUST_PROXY); otherwise it is the raw socket address. So a client that is not
 * behind our trusted proxy cannot move this value by sending its own `X-Forwarded-For`. Parsing that
 * header here instead would trust exactly the input an attacker controls, which is why we never do.
 */
/**
 * Optional edge header the client IP is read from, set once at startup from CLIENT_IP_HEADER.
 *
 * Module state rather than a threaded parameter on purpose: this is start-up configuration, and
 * keeping it here means every existing `bindingContextOf(req)` call site enforces the same rule
 * without being rewritten (and without any of them being able to opt out).
 */
let clientIpHeader: string | null = null;

/** Called once from bootstrap, before the server accepts traffic. */
export function configureClientIpHeader(name: string | null): void {
  clientIpHeader = name ? name.toLowerCase() : null;
}

/**
 * The request's client IP.
 *
 * With CLIENT_IP_HEADER set, that header wins. This is ONLY safe for a header the edge proxy
 * overwrites on every request (Cloudflare's `cf-connecting-ip`); for anything a client may
 * append to, it would hand the client control of its own identity.
 *
 * Otherwise this reads Fastify's `req.ip`, which resolves X-Forwarded-For only as far as
 * TRUST_PROXY allows; with TRUST_PROXY unset it is the raw socket peer. Parsing X-Forwarded-For
 * here directly would trust exactly the input an attacker controls, which is why we never do.
 */
export function requestIp(req: FastifyRequest): string | null {
  if (clientIpHeader) {
    const raw = req.headers[clientIpHeader];
    const value = Array.isArray(raw) ? raw[0] : raw;
    // Take the first entry in case the edge writes a list; a single address is the normal case.
    const first = typeof value === 'string' ? value.split(',')[0] : undefined;
    const fromHeader = normalizeIp(first);
    if (fromHeader) return fromHeader;
  }
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
  if (mappedV4) ip = mappedV4[1];
  else if (ip === '::1') ip = '127.0.0.1';
  // Validated, not merely tidied: anything that is not a real address is rejected, so a garbage
  // CLIENT_IP_HEADER falls back to req.ip instead of becoming a comparable "IP" of its own.
  return isIP(ip) === 0 ? null : ip;
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

  // The User-Agent is required in both modes; the IP only when it is part of the binding.
  if (!storedUserAgent || !currentUserAgent) return { ok: false, reason: 'BINDING_MISSING' };
  if (bindingMode === 'ip+ua') {
    if (!storedIp || !currentIp) return { ok: false, reason: 'BINDING_MISSING' };
    if (!equalsConstantTime(storedIp, currentIp)) return { ok: false, reason: 'IP_MISMATCH' };
  }
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
