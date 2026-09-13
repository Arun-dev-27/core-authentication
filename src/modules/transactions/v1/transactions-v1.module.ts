import { Module } from '@nestjs/common';
import { ClientsServicesModule } from '@modules/clients/clients-services.module';
import { TransactionsServicesModule } from '../transactions-services.module';
import { TransactionsController } from './transactions.controller';

/** Login transactions — v1 HTTP edge. */
@Module({
  imports: [TransactionsServicesModule, ClientsServicesModule],
  controllers: [TransactionsController],
})
export class TransactionsV1Module {}
