import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';

export function readSessionHandle(request: FastifyRequest, config: AppConfig): string | undefined {
  const value = request.cookies?.[config.env.SESSION_COOKIE_NAME];
  return typeof value === 'string' ? value : undefined;
}

/** Cookie holds only the opaque handle. HttpOnly; Secure; SameSite=None (iframe) by default. */
export function setSessionCookie(reply: FastifyReply, config: AppConfig, handle: string, maxAgeSeconds: number): void {
  void reply.setCookie(config.env.SESSION_COOKIE_NAME, handle, {
    httpOnly: true,
    secure: config.env.COOKIE_SECURE,
    sameSite: config.env.COOKIE_SAMESITE.toLowerCase() as 'none' | 'lax' | 'strict',
    path: '/',
    domain: config.env.COOKIE_DOMAIN,
    maxAge: maxAgeSeconds,
  });
}

export function clearSessionCookie(reply: FastifyReply, config: AppConfig): void {
  void reply.clearCookie(config.env.SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: config.env.COOKIE_SECURE,
    sameSite: config.env.COOKIE_SAMESITE.toLowerCase() as 'none' | 'lax' | 'strict',
    path: '/',
    domain: config.env.COOKIE_DOMAIN,
  });
}
