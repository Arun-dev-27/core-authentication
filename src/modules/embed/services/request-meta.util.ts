import type { FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { readSessionHandle } from '@modules/sessions/services/session-cookie';
import { RequestMeta } from '@shared/types/request-meta.types';

export function requestMeta(req: FastifyRequest, config: AppConfig, csrf?: string): RequestMeta {
  const ua = req.headers['user-agent'];
  return {
    ip: req.ip,
    userAgent: typeof ua === 'string' ? ua : undefined,
    origin: typeof req.headers.origin === 'string' ? req.headers.origin : undefined,
    csrf,
    sessionHandle: readSessionHandle(req, config),
  };
}
