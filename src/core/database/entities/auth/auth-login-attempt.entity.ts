import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

/** `auth_login_attempts` - one row per sign-in attempt; failure_reason also drives the durable account lockout. */
@Entity({ name: 'auth_login_attempts' })
export class AuthLoginAttempt {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: string;

  /** sha256 of the normalised identifier, so failed attempts for unknown IDs are recorded without the raw value. */
  @Column({ name: 'identifier_hash', type: 'char', length: 64 })
  identifierHash: string;

  @Column({ name: 'its_id', type: 'varchar', length: 64, nullable: true })
  itsId: string | null;

  @Column({ name: 'client_id', type: 'varchar', length: 64, nullable: true })
  clientId: string | null;

  @Column({ name: 'ip_address', type: 'varchar', length: 64, nullable: true })
  ipAddress: string | null;

  @Column({ type: 'boolean' })
  success: boolean;

  @Column({ name: 'failure_reason', type: 'varchar', length: 64, nullable: true })
  failureReason: string | null;

  @Column({ name: 'correlation_id', type: 'varchar', length: 128, nullable: true })
  correlationId: string | null;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;
}
