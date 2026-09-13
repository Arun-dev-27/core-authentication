import { Column, Entity, PrimaryColumn } from 'typeorm';

/**
 * Read-only mappings of the legacy MMS (SQL Server) tables used by the one-off migration.
 * Only the columns the flow needs are mapped. Never written to.
 *
 * `MHP_User_Login`: the `id numeric(18,0) IDENTITY` column is unmapped (not needed by the flow).
 */
@Entity({ name: 'MHP_User_Login' })
export class MhpUserLogin {
  /** Join key to `mumin_mast_Cal_grades.Mumin_ID`. */
  @PrimaryColumn({ name: 'UserId', type: 'int' })
  userId!: number;

  @Column({ name: 'Password', type: 'nvarchar', length: 100, nullable: true })
  password!: string | null;

  @Column({ name: 'Allow_Login', type: 'bit', nullable: true })
  allowLogin!: boolean | null;
}

@Entity({ name: 'MHP_User_Login_Eligible' })
export class MhpUserLoginEligible {
  @PrimaryColumn({ name: 'ID', type: 'numeric', precision: 18, scale: 0 })
  id!: string;

  @Column({ name: 'Mumin_ID', type: 'int', nullable: true })
  muminId!: number | null;
}

/** Profile columns only (name/email/mobile) - the table holds far more personal data that is deliberately not read. */
@Entity({ name: 'mumin_mast_Cal_grades' })
export class MuminMastCalGrades {
  @PrimaryColumn({ name: 'person_id', type: 'numeric', precision: 18, scale: 0 })
  personId!: string;

  @Column({ name: 'Mumin_ID', type: 'int', nullable: true })
  muminId!: number | null;

  @Column({ name: 'Fullname', type: 'varchar', length: 200, nullable: true })
  fullName!: string | null;

  @Column({ name: 'email', type: 'varchar', length: 50, nullable: true })
  email!: string | null;

  @Column({ name: 'mobile_no', type: 'varchar', length: 20, nullable: true })
  mobileNo!: string | null;
}

export const LEGACY_ENTITIES = [MhpUserLogin, MhpUserLoginEligible, MuminMastCalGrades];
