import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { IsNull, MoreThan, Repository } from 'typeorm';
import { AuthSessionClient, type LogoutStatus } from '../entities/auth/auth-session-client.entity';
import { AuthSession } from '../entities/auth/auth-session.entity';

export interface NewAuthSession {
  sid: string;
  itsId: string;
  authMethod: string;
  createdAt: Date;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
}

/** `auth_sessions` and `auth_session_clients`: the durable record of Core federation sessions. */
@Injectable()
export class AuthSessionRepository {
  constructor(
    @InjectRepository(AuthSession) private readonly sessions: Repository<AuthSession>,
    @InjectRepository(AuthSessionClient) private readonly clients: Repository<AuthSessionClient>,
  ) {}

  async create(session: NewAuthSession): Promise<void> {
    await this.sessions.insert({ ...session, lastSeenAt: () => 'now()' });
  }

  async touch(sid: string, expiresAt: Date): Promise<void> {
    await this.sessions.update({ sid }, { expiresAt, lastSeenAt: () => 'now()', updatedAt: () => 'now()' });
  }

  findRevocationState(sid: string): Promise<Pick<AuthSession, 'itsId' | 'revokedAt'> | null> {
    return this.sessions.findOne({ where: { sid }, select: { itsId: true, revokedAt: true } });
  }

  /** Marks the session revoked once; a second call leaves the original revocation untouched. */
  async revoke(sid: string, reason: string): Promise<void> {
    await this.sessions.update({ sid, revokedAt: IsNull() }, { revokedAt: () => 'now()', revokeReason: reason.slice(0, 64), updatedAt: () => 'now()' });
  }

  async activeSidsForUser(itsId: string): Promise<string[]> {
    const rows = await this.sessions.find({
      where: { itsId, revokedAt: IsNull(), absoluteExpiresAt: MoreThan(new Date()) },
      select: { sid: true },
    });
    return rows.map((r) => r.sid);
  }

  /** First assertion for (sid, client) inserts the row; later ones bump last_assertion_at and assertion_count. */
  async recordClientAssertion(sid: string, clientId: string): Promise<void> {
    const inserted = await this.clients
      .createQueryBuilder()
      .insert()
      .into(AuthSessionClient)
      .values({ sid, clientId })
      .orIgnore()
      .returning('id')
      .execute();
    if ((inserted.raw as unknown[]).length > 0) return;
    await this.clients
      .createQueryBuilder()
      .update(AuthSessionClient)
      .set({ lastAssertionAt: () => 'now()', updatedAt: () => 'now()', assertionCount: () => 'assertion_count + 1' })
      .where('sid = :sid AND client_id = :clientId', { sid, clientId })
      .execute();
  }

  async clientIds(sid: string): Promise<string[]> {
    const rows = await this.clients.find({ where: { sid }, select: { clientId: true }, order: { clientId: 'ASC' } });
    return rows.map((r) => r.clientId);
  }

  async markClientLogout(sid: string, clientId: string, status: LogoutStatus): Promise<void> {
    await this.clients.update({ sid, clientId }, { logoutStatus: status, logoutAt: () => 'now()', updatedAt: () => 'now()' });
  }
}
