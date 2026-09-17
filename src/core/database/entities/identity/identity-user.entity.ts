import { Column, Entity, PrimaryColumn } from 'typeorm';

/**
 * EXISTING identity_db table `users` (legacy MHP_User_Login), owned by the Mumin sync service.
 * READ-ONLY for this service: never inserted, updated or deleted. Only the columns the login path reads are mapped.
 */
@Entity({ name: 'users' })
export class IdentityUser {
  @PrimaryColumn({ type: 'numeric' })
  id: string;

  @Column({ name: 'mumin_id', type: 'integer' })
  muminId: number;

  /** Legacy reversible password; compared with Decrypt() at sign-in, never logged or returned. */
  @Column({ type: 'varchar', length: 100, nullable: true, select: false })
  password: string | null;

  @Column({ name: 'allow_login', type: 'boolean', nullable: true })
  allowLogin: boolean | null;

  @Column({ name: 'is_source_deleted', type: 'boolean' })
  isSourceDeleted: boolean;

  @Column({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
