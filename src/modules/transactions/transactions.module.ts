import { Module } from '@nestjs/common';
import { TransactionsServicesModule } from './transactions-services.module';
import { TransactionsV1Module } from './v1/transactions-v1.module';

/** Login transactions — feature aggregator. */
@Module({
  imports: [TransactionsServicesModule, TransactionsV1Module],
  exports: [TransactionsServicesModule],
})
export class TransactionsModule {}
