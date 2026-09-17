import { Column, Entity, OneToMany, PrimaryColumn } from 'typeorm';
import { AuthSessionClient } from './auth-session-client.entity';

/** `auth_sessions` - one Core federation session. its_id = identity users.mumin_id as text (no FK: users is a synced table). */
@Entity({ name: 'auth_sessions' })
export class AuthSession {
  @PrimaryColumn({ type: 'varchar', length: 64 })
  sid: string;

  @Column({ name: 'its_id', type: 'varchar', length: 64 })
  itsId: string;

  @Column({ name: 'auth_method', type: 'varchar', length: 32 })
  authMethod: string;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'expires_at', type: 'timestamptz' })
  expiresAt: Date;

  @Column({ name: 'absolute_expires_at', type: 'timestamptz' })
  absoluteExpiresAt: Date;

  @Column({ name: 'last_seen_at', type: 'timestamptz', nullable: true })
  lastSeenAt: Date | null;

  @Column({ name: 'revoked_at', type: 'timestamptz', nullable: true })
  revokedAt: Date | null;

  @Column({ name: 'revoke_reason', type: 'varchar', length: 64, nullable: true })
  revokeReason: string | null;

  @Column({ name: 'ip_address', type: 'varchar', length: 64, nullable: true })
  ipAddress: string | null;

  @Column({ name: 'user_agent', type: 'varchar', length: 512, nullable: true })
  userAgent: string | null;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;

  @OneToMany(() => AuthSessionClient, (client) => client.session)
  clients: AuthSessionClient[];
}
