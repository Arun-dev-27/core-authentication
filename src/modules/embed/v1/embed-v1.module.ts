import { Module } from '@nestjs/common';
import { AuthorizationClientModule } from '@modules/authorization-client/authorization-client.module';
import { ClientsServicesModule } from '@modules/clients/clients-services.module';
import { SessionsServicesModule } from '@modules/sessions/sessions-services.module';
import { TransactionsServicesModule } from '@modules/transactions/transactions-services.module';
import { EmbedServicesModule } from '../embed-services.module';
import { EmbedController } from './embed.controller';

/** Embedded login — v1 HTTP edge. */
@Module({
  imports: [EmbedServicesModule, ClientsServicesModule, TransactionsServicesModule, SessionsServicesModule, AuthorizationClientModule],
  controllers: [EmbedController],
})
export class EmbedV1Module {}
