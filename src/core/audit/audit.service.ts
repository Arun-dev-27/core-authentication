import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { currentCorrelationId } from '@common/logging/request-context';
import { AuthAuditEvent } from '@core/database/entities/auth/auth-audit-event.entity';

export interface AuditEventInput {
  eventType: string;
  outcome: 'SUCCESS' | 'FAILURE' | 'INFO';
  itsId?: string | null;
  sid?: string | null;
  clientId?: string | null;
  jti?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  /** Never put passwords, assertions, cookies, handles or keys in metadata. */
  metadata?: Record<string, unknown>;
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger('Audit');

  constructor(@InjectRepository(AuthAuditEvent) private readonly events: Repository<AuthAuditEvent>) {}

  async record(event: AuditEventInput): Promise<void> {
    const correlationId = currentCorrelationId() ?? null;
    this.logger.log({
      msg: 'audit',
      event_type: event.eventType,
      outcome: event.outcome,
      its_id: event.itsId ?? undefined,
      sid: event.sid ?? undefined,
      client_id: event.clientId ?? undefined,
      jti: event.jti ?? undefined,
      reason: event.metadata?.reason,
    });
    try {
      await this.events.save(
        this.events.create({
          eventType: event.eventType,
          outcome: event.outcome,
          itsId: event.itsId ?? null,
          sid: event.sid ?? null,
          clientId: event.clientId ?? null,
          jti: event.jti ?? null,
          ipAddress: event.ip ?? null,
          userAgent: event.userAgent?.slice(0, 512) ?? null,
          correlationId,
          metadata: event.metadata ?? null,
        }),
      );
    } catch (error) {
      this.logger.error({ msg: 'audit write failed', event_type: event.eventType, err: error });
    }
  }
}
