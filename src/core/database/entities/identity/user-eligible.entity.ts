import { Column, Entity, PrimaryColumn } from 'typeorm';

/**
 * EXISTING identity_db table `user_eligible` (legacy MHP_User_Login_Eligible), owned by the Mumin sync service.
 * READ-ONLY for this service.
 */
@Entity({ name: 'user_eligible' })
export class UserEligible {
  @PrimaryColumn({ type: 'numeric' })
  id: string;

  @Column({ name: 'mumin_id', type: 'integer' })
  muminId: number;

  @Column({ name: 'is_source_deleted', type: 'boolean' })
  isSourceDeleted: boolean;

  @Column({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
