import { Module } from '@nestjs/common';
import { ClientsServicesModule } from '../clients-services.module';
import { ClientInfoController } from './client-info.controller';

/** Dynamic client registry — v1 HTTP edge. */
@Module({
  imports: [ClientsServicesModule],
  controllers: [ClientInfoController],
})
export class ClientsV1Module {}
