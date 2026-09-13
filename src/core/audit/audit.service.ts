import { Injectable, Logger } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { currentCorrelationId } from '@common/logging/request-context';

export interface AuthAuditEvent {
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

  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async record(event: AuthAuditEvent): Promise<void> {
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
      await this.db.query(
        `INSERT INTO auth_audit_events (event_type, outcome, its_id, sid, client_id, jti, ip_address, user_agent, correlation_id, metadata)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          event.eventType,
          event.outcome,
          event.itsId ?? null,
          event.sid ?? null,
          event.clientId ?? null,
          event.jti ?? null,
          event.ip ?? null,
          event.userAgent?.slice(0, 512) ?? null,
          correlationId,
          event.metadata ? JSON.stringify(event.metadata) : null,
        ],
      );
    } catch (error) {
      this.logger.error({ msg: 'audit write failed', event_type: event.eventType, err: error });
    }
  }
}
