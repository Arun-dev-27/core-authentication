import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { DomainError } from '../errors/domain-error';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger('ExceptionFilter');

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const reply = ctx.getResponse<FastifyReply>();
    const request = ctx.getRequest<FastifyRequest>();

    let status = 500;
    let body: Record<string, unknown> = { error: 'INTERNAL_ERROR', message: 'An unexpected error occurred' };

    if (exception instanceof DomainError) {
      status = exception.status;
      body = { error: exception.code, message: exception.message, ...(exception.details ? { details: exception.details } : {}) };
      for (const [name, value] of Object.entries(exception.headers ?? {})) void reply.header(name, value);
    } else if (exception instanceof HttpException) {
      status = exception.getStatus();
      const response = exception.getResponse() as string | { message?: string | string[] };
      if (status === HttpStatus.BAD_REQUEST && typeof response === 'object' && Array.isArray(response.message)) {
        body = { error: 'VALIDATION_ERROR', message: 'Request validation failed', details: response.message };
      } else {
        const message = typeof response === 'string' ? response : Array.isArray(response.message) ? response.message.join(', ') : response.message;
        body = { error: HttpStatus[status] ?? 'HTTP_ERROR', message: message ?? exception.message };
      }
    } else {
      this.logger.error(exception instanceof Error ? exception : String(exception));
    }

    body.correlation_id = request?.id;
    void reply.status(status).header('content-type', 'application/json; charset=utf-8').header('cache-control', 'no-store').send(body);
  }
}
