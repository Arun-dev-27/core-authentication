import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';
import { isIP } from 'node:net';
import { z } from 'zod';

const bool = z.enum(['true', 'false']).transform((v) => v === 'true');
const seconds = (fallback: number) => z.coerce.number().int().positive().default(fallback);

/**
 * Proxy trust used to derive the client IP (`req.ip`), which session binding compares against.
 *
 *   false            direct exposure; the IP is the socket peer.
 *   <n>              number of trusted proxy hops in front of this service (Render / ALB / nginx: 1).
 *   <cidr>[,<cidr>]  trust exactly these proxy addresses.
 *
 * Plain `true` is refused on purpose. It makes Fastify take the LEFT-most X-Forwarded-For entry, and
 * that entry is whatever the client chose to send: a caller holding a stolen session cookie could set
 * `X-Forwarded-For: <victim ip>` and walk straight through the IP check. A hop count instead resolves
 * to the address our own trusted proxy observed, which the client cannot forge.
 */
/** proxy-addr's named ranges, accepted verbatim by Fastify's trustProxy. */
const PROXY_PRESETS = new Set(['loopback', 'linklocal', 'uniquelocal']);

/** A single trusted-proxy entry: a preset, a bare IP, or an IP with a valid prefix length. */
function isTrustedProxyEntry(entry: string): boolean {
  if (PROXY_PRESETS.has(entry.toLowerCase())) return true;
  const parts = entry.split('/');
  if (parts.length > 2) return false;
  const family = isIP(parts[0]);
  if (family === 0) return false;
  if (parts.length === 1) return true;
  if (!/^\d+$/.test(parts[1])) return false;
  const bits = Number(parts[1]);
  return bits >= 0 && bits <= (family === 4 ? 32 : 128);
}

const trustProxy = z
  .string()
  .default('false')
  .transform((raw, ctx): boolean | number | string[] => {
    const value = raw.trim();
    if (value === '' || value.toLowerCase() === 'false') return false;
    if (value.toLowerCase() === 'true') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'must be false, a hop count (e.g. 1), or a comma-separated list of trusted proxy CIDRs; "true" would trust a client-supplied X-Forwarded-For',
      });
      return z.NEVER;
    }
    if (/^\d+$/.test(value)) {
      const hops = Number(value);
      if (hops < 1 || hops > 10) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'hop count must be between 1 and 10' });
        return z.NEVER;
      }
      return hops;
    }
    const cidrs = value.split(',').map((part) => part.trim()).filter((part) => part.length > 0);
    if (cidrs.length === 0 || !cidrs.every(isTrustedProxyEntry)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'must be false, a hop count, or a comma-separated list of trusted proxy IPs/CIDRs (or loopback/linklocal/uniquelocal)',
      });
      return z.NEVER;
    }
    return cidrs;
  });

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().default(3001),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    /**
     * Factors a session cookie is pinned to. Keep 'ip+ua' wherever the platform gives the app the
     * real client IP. Use 'ua' behind an edge that does not (Render/Cloudflare), where the visible
     * address is a shared, rotating edge IP.
     */
    SESSION_BINDING: z.enum(['ip+ua', 'ua']).default('ip+ua'),
    TRUST_PROXY: trustProxy,
    /**
     * Header carrying the real client IP, when an edge proxy provides one it overwrites on every
     * request (Cloudflare, and therefore Render: `cf-connecting-ip`). Leave unset when the service
     * is not behind such an edge; a header a client can append to must never be used here.
     */
    CLIENT_IP_HEADER: z
      .string()
      .regex(/^[a-z0-9-]{3,64}$/i)
      .optional()
      .transform((v) => (v ? v.toLowerCase() : undefined)),
    SWAGGER_ENABLED: bool.default('true'),

    ISSUER: z.string().url(),

    AUTH_DB_HOST: z.string().min(1),
    AUTH_DB_PORT: z.coerce.number().int().positive().default(5432),
    AUTH_DB_USER: z.string().min(1),
    AUTH_DB_PASSWORD: z.string().min(1),
    AUTH_DB_NAME: z.string().min(1),
    AUTH_DB_SSL: bool.default('false'),

    REDIS_URL: z.string().url(),

    AUTHZ_BASE_URL: z.string().url(),
    CLIENT_CACHE_TTL_SECONDS: z.coerce.number().int().min(0).default(30),

    // Service-to-service authentication without API keys: this service signs short-lived RS256 service tokens
    // (typ client-authentication+jwt, iss = sub = SERVICE_PRINCIPAL_ID) that the Authorization service verifies via our JWKS.
    AUTHZ_AUDIENCE: z.string().min(3).max(200).default('miqaat-core-authorization'),
    SERVICE_PRINCIPAL_ID: z.string().regex(/^[a-z0-9][a-z0-9-]{2,63}$/).default('identity-federation'),
    SERVICE_TOKEN_TTL_SECONDS: z.coerce.number().int().min(30).max(300).default(120),

    // Access tokens (typ at+jwt) issued by POST /login and POST /select-scope; carry only the active workspace.
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(600),

    SIGNING_KEY_PROVIDER: z.enum(['file', 'secretsmanager', 'ssm']).default('file'),
    SIGNING_KEYS_FILE: z.string().default('./.keys/signing-keys.json'),
    SECRETS_MANAGER_SIGNING_KEYS_SECRET_ID: z.string().regex(/^[A-Za-z0-9/_+=.@-]{1,512}$/).default('miqaat/identity/dev/signing-keys'),
    SSM_SIGNING_KEYS_PATH: z.string().regex(/^\/[A-Za-z0-9_.\-/]+[^/]$/).default('/miqaat/identity/dev/signing-keys'),
    SIGNING_KEYS_KMS_KEY_ID: z.string().optional().transform((v) => (v ? v : undefined)),
    AWS_REGION: z.string().default('ap-south-1'),
    /** LocalStack / VPC endpoint override. Must be unset in production (the SDK default endpoints are used). */
    AWS_ENDPOINT_URL: z
      .string()
      .optional()
      .transform((v) => (v ? v : undefined))
      .pipe(z.string().url().optional()),
    KEY_REFRESH_INTERVAL_SECONDS: seconds(300),

    ASSERTION_TTL_SECONDS: z.coerce.number().int().min(10).max(300).default(60),
    TRANSACTION_TTL_SECONDS: seconds(300),
    // POST /auth/transaction also returns the login page's CSRF token, so API clients need not parse the HTML.
    // Unset: on outside production, off in production. The Origin check applies either way.
    TRANSACTION_API_RETURNS_CSRF: z
      .enum(['true', 'false'])
      .optional()
      .transform((v) => (v === undefined ? undefined : v === 'true')),
    SESSION_IDLE_TTL_SECONDS: seconds(1800),
    SESSION_ABSOLUTE_TTL_SECONDS: seconds(28800),

    SESSION_COOKIE_NAME: z.string().regex(/^[A-Za-z0-9_-]+$/).default('federation_session'),
    COOKIE_SECURE: bool.default('true'),
    COOKIE_SAMESITE: z.enum(['None', 'Lax', 'Strict']).default('None'),
    COOKIE_DOMAIN: z.string().optional().transform((v) => (v ? v : undefined)),

    LOGIN_MAX_FAILURES_PER_IDENTIFIER: z.coerce.number().int().positive().default(5),
    LOGIN_IDENTIFIER_WINDOW_SECONDS: seconds(900),
    LOGIN_ACCOUNT_LOCK_SECONDS: seconds(900),
    LOGIN_MAX_ATTEMPTS_PER_IP: z.coerce.number().int().positive().default(30),
    LOGIN_IP_WINDOW_SECONDS: seconds(300),

    PORTAL_ENVIRONMENT: z.string().regex(/^[A-Z0-9_]{2,16}$/).default('DEV'),
  })
  .superRefine((env, ctx) => {
    const issuer = new URL(env.ISSUER);
    if (issuer.pathname !== '/' || issuer.search || issuer.hash) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ISSUER'], message: 'must be an origin without path' });
    }
    if (env.NODE_ENV === 'production') {
      if (issuer.protocol !== 'https:') ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ISSUER'], message: 'must use https in production' });
      if (!env.COOKIE_SECURE) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['COOKIE_SECURE'], message: 'must be true in production' });
      if (env.SIGNING_KEY_PROVIDER === 'file') {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['SIGNING_KEY_PROVIDER'], message: 'must be secretsmanager or ssm in production' });
      }
      if (env.AWS_ENDPOINT_URL) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['AWS_ENDPOINT_URL'], message: 'must not be set in production' });
      }
    }
    if (env.COOKIE_SAMESITE === 'None' && !env.COOKIE_SECURE) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['COOKIE_SAMESITE'], message: 'SameSite=None requires COOKIE_SECURE=true' });
    }
    if (env.SESSION_ABSOLUTE_TTL_SECONDS < env.SESSION_IDLE_TTL_SECONDS) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['SESSION_ABSOLUTE_TTL_SECONDS'], message: 'must be >= SESSION_IDLE_TTL_SECONDS' });
    }
  });

export type Env = z.infer<typeof envSchema>;

/** Loads `.env` (or `.env.test` under jest / ENV_FILE) without overriding real environment variables. */
export function loadEnvFiles(cwd = process.cwd()): void {
  const file = process.env.ENV_FILE ?? (process.env.NODE_ENV === 'test' ? '.env.test' : '.env');
  const path = resolve(cwd, file);
  if (!existsSync(path)) return;
  // Explicit assignment (not process.loadEnvFile) so it also works inside Jest's sandboxed process.env.
  for (const [key, value] of Object.entries(parseEnv(readFileSync(path, 'utf8')))) {
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

/** Parses and validates the environment. Error messages never include values. */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid environment configuration: ${issues}`);
  }
  return parsed.data;
}
