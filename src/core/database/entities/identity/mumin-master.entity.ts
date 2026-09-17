import { Column, Entity, PrimaryColumn } from 'typeorm';

/**
 * EXISTING identity_db table `mumin_master` (legacy mumin_mast_Cal_grades), owned by the Mumin sync service.
 * READ-ONLY for this service. Only the columns the login path reads are mapped.
 */
@Entity({ name: 'mumin_master' })
export class MuminMaster {
  @PrimaryColumn({ name: 'person_id', type: 'numeric' })
  personId: string;

  @Column({ name: 'mumin_id', type: 'integer' })
  muminId: number;

  @Column({ name: 'status_id', type: 'smallint', nullable: true })
  statusId: number | null;

  @Column({ type: 'varchar', length: 50, nullable: true })
  status: string | null;

  @Column({ type: 'varchar', length: 200, nullable: true })
  fullname: string | null;

  @Column({ name: 'is_source_deleted', type: 'boolean' })
  isSourceDeleted: boolean;

  @Column({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
