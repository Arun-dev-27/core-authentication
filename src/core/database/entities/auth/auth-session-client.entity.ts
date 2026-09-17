import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn, Unique } from 'typeorm';
import { AuthSession } from './auth-session.entity';

export type LogoutStatus = 'PENDING' | 'SUCCEEDED' | 'FAILED' | 'NO_ENDPOINT';

/** `auth_session_clients` - which client applications received an assertion for a session (drives back-channel logout). */
@Entity({ name: 'auth_session_clients' })
@Unique('uq_auth_session_clients_sid_client', ['sid', 'clientId'])
export class AuthSessionClient {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  @Column({ type: 'varchar', length: 64 })
  sid: string;

  @ManyToOne(() => AuthSession, (session) => session.clients, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sid', referencedColumnName: 'sid' })
  session: AuthSession;

  @Column({ name: 'client_id', type: 'varchar', length: 64 })
  clientId: string;

  @Column({ name: 'first_assertion_at', type: 'timestamptz', default: () => 'now()' })
  firstAssertionAt: Date;

  @Column({ name: 'last_assertion_at', type: 'timestamptz', default: () => 'now()' })
  lastAssertionAt: Date;

  @Column({ name: 'assertion_count', type: 'integer', default: 1 })
  assertionCount: number;

  @Column({ name: 'logout_status', type: 'varchar', length: 16, nullable: true })
  logoutStatus: LogoutStatus | null;

  @Column({ name: 'logout_at', type: 'timestamptz', nullable: true })
  logoutAt: Date | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;
}
