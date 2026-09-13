import { Controller, Get, Header } from '@nestjs/common';
import { VERSION_NEUTRAL } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { AppConfig } from '@config/config.module';
import { KeyStore } from './services/key-store.service';

@ApiTags('discovery')
@Controller({ path: '.well-known', version: VERSION_NEUTRAL })
export class WellKnownController {
  constructor(
    private readonly keys: KeyStore,
    private readonly config: AppConfig,
  ) {}

  @Get('jwks.json')
  @Header('cache-control', 'public, max-age=300, stale-while-revalidate=60')
  @ApiOperation({ summary: 'Public RS256 verification keys (NEXT, ACTIVE, RETIRING). Select by kid.' })
  jwks() {
    return this.keys.jwks();
  }

  @Get('miqaat-federation')
  @Header('cache-control', 'public, max-age=3600')
  @ApiOperation({ summary: 'Federation metadata for Business Unit integrations' })
  metadata() {
    const base = this.config.issuer;
    return {
      issuer: base,
      jwks_uri: this.config.jwksUri,
      embed_login_endpoint: `${base}/embed/login`,
      transaction_endpoint: `${base}/auth/transaction`,
      federation_logout_endpoint: `${base}/federation/logout`,
      assertion_signing_alg_values_supported: ['RS256'],
      assertion_lifetime_seconds: this.config.env.ASSERTION_TTL_SECONDS,
      backchannel_logout_supported: true,
      backchannel_logout_session_supported: true,
      postmessage_event_types: ['MIQAAT_AUTH_SUCCESS', 'MIQAAT_AUTH_ERROR', 'MIQAAT_AUTH_TOP_LEVEL_REQUIRED', 'MIQAAT_AUTH_RESIZE'],
    };
  }
}
