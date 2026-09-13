import { Controller, Get, Req } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { FastifyRequest } from 'fastify';
import { AppConfig } from '@config/config.module';
import { API_V1 } from '@common/constants/api-version.constants';
import { FederationSessionService } from '../services/federation-session.service';
import { readSessionHandle } from '../services/session-cookie';

@ApiTags('auth')
@Controller({ path: 'auth/session', version: API_V1 })
export class SessionController {
  constructor(
    private readonly sessions: FederationSessionService,
    private readonly config: AppConfig,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Current central federation session for this browser (same-origin; cookie based)' })
  async current(@Req() request: FastifyRequest) {
    const session = await this.sessions.getByHandle(readSessionHandle(request, this.config));
    if (!session) return { authenticated: false };
    return {
      authenticated: true,
      its_id: session.its_id,
      identity_type: session.identity_type,
      display_name: session.display_name,
      auth_time: session.auth_time,
      expires_at: session.expires_at,
      absolute_expires_at: session.absolute_expires_at,
      clients: await this.sessions.clients(session.sid),
    };
  }
}
