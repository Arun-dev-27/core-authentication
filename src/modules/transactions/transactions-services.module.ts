import { Module } from '@nestjs/common';
import { TransactionService } from './services/transaction.service';

/** Login transactions — version-agnostic services, reused by every /vN edge. */
@Module({
  providers: [TransactionService],
  exports: [TransactionService],
})
export class TransactionsServicesModule {}
