import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { LoggerService } from '@nestjs/common';
import { Logger } from 'pino';
import pino from 'pino';
import { currentCorrelationId } from './request-context';

/**
 * Anything that could carry a credential, session handle, assertion or key material.
 * Request bodies are never logged by the HTTP logger at all.
 */
export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
  '*.password',
  '*.core_assertion',
  '*.assertion',
  '*.logout_token',
  '*.access_token',
  '*.privateKeyPem',
  '*.private_key',
  '*.csrf',
  '*.handle',
  '*.password_hash',
];

export function createLogger(level: string): Logger {
  return pino({
    level,
    base: { service: 'miqaat-identity-federation-service' },
    redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
    timestamp: pino.stdTimeFunctions.isoTime,
    serializers: {
      // Query strings on /embed/login contain state + transaction ids; keep path only.
      req: (req: { method: string; url: string; id: string; ip?: string }) => ({
        method: req.method,
        path: typeof req.url === 'string' ? req.url.split('?')[0] : undefined,
        id: req.id,
        ip: req.ip,
      }),
    },
  });
}

const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{8,128}$/;

export function genRequestId(req: IncomingMessage): string {
  const inbound = req.headers['x-request-id'];
  return typeof inbound === 'string' && REQUEST_ID_PATTERN.test(inbound) ? inbound : randomUUID();
}

export class PinoNestLogger implements LoggerService {
  constructor(private readonly logger: Logger) {}

  private write(level: 'info' | 'error' | 'warn' | 'debug' | 'trace', message: unknown, context?: string, extra?: object) {
    const payload = { context, correlation_id: currentCorrelationId(), ...extra };
    if (message instanceof Error) {
      this.logger[level]({ ...payload, err: message }, message.message);
    } else if (typeof message === 'object' && message !== null) {
      this.logger[level]({ ...payload, ...message });
    } else {
      this.logger[level](payload, String(message));
    }
  }

  log(message: unknown, context?: string) {
    this.write('info', message, context);
  }
  error(message: unknown, stackOrContext?: string, context?: string) {
    this.write('error', message, context ?? stackOrContext, context ? { stack: stackOrContext } : undefined);
  }
  warn(message: unknown, context?: string) {
    this.write('warn', message, context);
  }
  debug(message: unknown, context?: string) {
    this.write('debug', message, context);
  }
  verbose(message: unknown, context?: string) {
    this.write('trace', message, context);
  }
}
