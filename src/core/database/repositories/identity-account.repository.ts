import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IdentityUser } from '../entities/identity/identity-user.entity';
import { MuminMaster } from '../entities/identity/mumin-master.entity';
import { UserEligible } from '../entities/identity/user-eligible.entity';

/** One result of the legacy "Login Authentication Query". */
export interface LoginAccount {
  personId: string;
  muminId: number;
  statusId: number;
  status: string | null;
  fullname: string | null;
  /** Legacy reversible ciphertext from users.password. */
  password: string | null;
  /** ISNULL(Allow_Login, 1) */
  allowLogin: boolean;
}

/**
 * Read-only access to the EXISTING identity tables (users, mumin_master, user_eligible).
 * This repository has no insert / update / delete method on purpose: those tables belong to the Mumin sync service.
 */
@Injectable()
export class IdentityAccountRepository {
  constructor(
    @InjectRepository(IdentityUser) private readonly users: Repository<IdentityUser>,
    @InjectRepository(UserEligible) private readonly eligible: Repository<UserEligible>,
  ) {}

  /**
   * Legacy query, as TypeORM:
   *   SELECT mm.Person_ID, mm.Mumin_ID, mm.Status_ID, mm.[status], ul.[Password], ISNULL(ul.Allow_Login, 1) AS Allow_Login
   *     FROM MHP_USER_LOGIN ul INNER JOIN mumin_mast_cal_grades mm ON ul.userid = mm.mumin_id
   *    WHERE mm.status_id = 3 AND ul.userid = @Mumin_ID
   * Rows the sync marked deleted at source do not count.
   */
  async findLoginAccount(muminId: number, activeStatusId: number): Promise<LoginAccount | null> {
    const row = await this.users
      .createQueryBuilder('ul')
      .innerJoin(MuminMaster, 'mm', 'mm.muminId = ul.muminId')
      .select('mm.personId', 'personId')
      .addSelect('mm.muminId', 'muminId')
      .addSelect('mm.statusId', 'statusId')
      .addSelect('mm.status', 'status')
      .addSelect('mm.fullname', 'fullname')
      .addSelect('ul.password', 'password')
      .addSelect('COALESCE(ul.allowLogin, true)', 'allowLogin')
      .where('ul.muminId = :muminId', { muminId })
      .andWhere('mm.statusId = :activeStatusId', { activeStatusId })
      .andWhere('ul.isSourceDeleted = false')
      .andWhere('mm.isSourceDeleted = false')
      .orderBy('ul.id', 'DESC')
      .limit(1)
      .getRawOne<LoginAccount>();
    return row ?? null;
  }

  /** Legacy "Login Restriction Query": select count(1) from MHP_User_Login_Eligible where Mumin_ID = @Mumin_ID (> 0). */
  isEligible(muminId: number): Promise<boolean> {
    return this.eligible.exists({ where: { muminId, isSourceDeleted: false } });
  }
}
