import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { DomainError } from '../errors/domain-error';

export interface DescribedException {
  status: number;
  body: { error: string; message: string; details?: unknown };
  headers: Record<string, string | number>;
}

/** Maps any thrown value to an HTTP status, error body and extra headers (shared by every exception filter). */
export function describeException(exception: unknown, logger?: Logger): DescribedException {
  if (exception instanceof DomainError) {
    return {
      status: exception.status,
      body: { error: exception.code, message: exception.message, ...(exception.details ? { details: exception.details } : {}) },
      headers: { ...(exception.headers ?? {}) },
    };
  }
  if (exception instanceof HttpException) {
    const status = exception.getStatus();
    const response = exception.getResponse() as string | { message?: string | string[] };
    if (status === HttpStatus.BAD_REQUEST && typeof response === 'object' && Array.isArray(response.message)) {
      return { status, body: { error: 'VALIDATION_ERROR', message: 'Request validation failed', details: response.message }, headers: {} };
    }
    const message = typeof response === 'string' ? response : Array.isArray(response.message) ? response.message.join(', ') : response.message;
    return { status, body: { error: HttpStatus[status] ?? 'HTTP_ERROR', message: message ?? exception.message }, headers: {} };
  }
  logger?.error(exception instanceof Error ? exception : String(exception));
  return { status: 500, body: { error: 'INTERNAL_ERROR', message: 'An unexpected error occurred' }, headers: {} };
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

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
      .send({ ...body, correlation_id: request?.id });
  }
}
