import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthLoginAttempt } from '../entities/auth/auth-login-attempt.entity';

export interface NewLoginAttempt {
  identifierHash: string;
  itsId: string | null;
  clientId: string | null;
  ipAddress: string | null;
  success: boolean;
  failureReason: string | null;
  correlationId: string | null;
}

/** `auth_login_attempts`: the attempt log, and the durable lockout counter derived from it. */
@Injectable()
export class LoginAttemptRepository {
  constructor(@InjectRepository(AuthLoginAttempt) private readonly attempts: Repository<AuthLoginAttempt>) {}

  async record(attempt: NewLoginAttempt): Promise<void> {
    await this.attempts.insert(attempt);
  }

  /**
   * Failures with `failureReason` for this account inside the last `windowSeconds`, counted only after its most
   * recent successful sign-in, plus how long ago the latest of them happened.
   */
  async recentFailures(itsId: string, failureReason: string, windowSeconds: number): Promise<{ failures: number; secondsSinceLast: number | null }> {
    const lastSuccess = this.attempts
      .createQueryBuilder('s')
      .select('MAX(s.createdAt)')
      .where('s.itsId = :itsId')
      .andWhere('s.success = true');

    const row = await this.attempts
      .createQueryBuilder('a')
      .select('CAST(COUNT(*) AS integer)', 'failures')
      .addSelect('CAST(EXTRACT(EPOCH FROM (now() - MAX(a.createdAt))) AS double precision)', 'secondsSinceLast')
      .where('a.itsId = :itsId', { itsId })
      .andWhere('a.success = false')
      .andWhere('a.failureReason = :failureReason', { failureReason })
      .andWhere('a.createdAt > now() - make_interval(secs => :windowSeconds)', { windowSeconds })
      .andWhere(`a.createdAt > COALESCE((${lastSuccess.getQuery()}), '-infinity')`)
      .getRawOne<{ failures: number; secondsSinceLast: number | null }>();
    return { failures: Number(row?.failures ?? 0), secondsSinceLast: row?.secondsSinceLast ?? null };
  }
}
