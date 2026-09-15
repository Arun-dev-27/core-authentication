import { ArgumentsHost, Catch, ExceptionFilter, Logger } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { describeException } from '@common/filters/http-exception.filter';
import { errorEnvelope } from '../services/login-envelope';

/**
 * Errors of the Core login endpoints (/login, /select-scope and their /portal aliases) in the login envelope:
 * { success: false, session: null, request_id, timestamp, scope: null, error: { code, message, details } }.
 * Same HTTP status and headers (e.g. Retry-After) as the global filter; request_id is the correlation id.
 */
@Catch()
export class LoginEnvelopeFilter implements ExceptionFilter {
  private readonly logger = new Logger('LoginEnvelopeFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const reply = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    const { status, body, headers } = describeException(exception, this.logger);
    for (const [name, value] of Object.entries(headers)) void reply.header(name, value);
    void reply
      .status(status)
      .header('content-type', 'application/json; charset=utf-8')
      .header('cache-control', 'no-store')
      .send(errorEnvelope(String(request?.id ?? ''), body));
  }
}
