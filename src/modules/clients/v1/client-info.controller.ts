import { Controller, Get, Param } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { API_V1 } from '@common/constants/api-version.constants';
import { ClientRegistry } from '../services/client-registry.service';

@ApiTags('auth')
@Controller({ path: 'auth/client', version: API_V1 })
export class ClientInfoController {
  constructor(private readonly registry: ClientRegistry) {}

  @Get(':clientId')
  @ApiOperation({ summary: 'Public display metadata for a client (no origins, callbacks or secrets)' })
  async get(@Param('clientId') clientId: string) {
    const client = await this.registry.get(clientId);
    return {
      client_id: client.client_id,
      application_name: client.application_name,
      business_unit: client.business_unit,
      utility: client.utility,
      environment: client.environment,
      authentication_mode: client.authentication_mode,
      status: client.status,
      sign_in_enabled: client.status === 'ACTIVE',
    };
  }
}
