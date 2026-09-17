import { Column, Entity, PrimaryColumn } from 'typeorm';

export type SigningKeyStatus = 'NEXT' | 'ACTIVE' | 'RETIRING' | 'RETIRED';

/** `signing_key_metadata` - RS256 key identity and lifecycle state only. Private keys never live in the database. */
@Entity({ name: 'signing_key_metadata' })
export class SigningKeyMetadata {
  @PrimaryColumn({ type: 'varchar', length: 128 })
  kid: string;

  @Column({ type: 'varchar', length: 16 })
  alg: string;

  @Column({ type: 'varchar', length: 16 })
  status: SigningKeyStatus;

  @Column({ name: 'jwk_thumbprint', type: 'varchar', length: 64, nullable: true })
  jwkThumbprint: string | null;

  @Column({ name: 'first_seen_at', type: 'timestamptz', default: () => 'now()' })
  firstSeenAt: Date;

  @Column({ name: 'status_changed_at', type: 'timestamptz', default: () => 'now()' })
  statusChangedAt: Date;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamptz', default: () => 'now()' })
  updatedAt: Date;
}
