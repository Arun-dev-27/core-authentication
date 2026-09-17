import { Injectable } from '@nestjs/common';
import type { AuthClientCallback, CallbackUriType } from '@core/database/entities/auth/auth-client-callback.entity';
import { AuthClientRepository } from '@core/database/repositories/auth-client.repository';
import { FederationClientConfig } from '@shared/types/federation-client.types';

/**
 * The federation client registry, read from core-authentication's own auth_clients / auth_client_origins /
 * auth_client_callbacks tables - no dependency on any authorization service.
 */
@Injectable()
export class ClientsStoreService {
  constructor(private readonly clients: AuthClientRepository) {}

  async findByClientId(clientId: string): Promise<FederationClientConfig | null> {
    const c = await this.clients.findWithUris(clientId);
    if (!c) return null;

    const byType = (type: CallbackUriType) => c.callbacks.filter((r) => r.uriType === type);
    const primaryOf = (rows: AuthClientCallback[]) => rows.find((r) => r.isPrimary) ?? rows[0];
    const callbackUris = byType('CALLBACK');
    const postLogoutUris = byType('POST_LOGOUT_REDIRECT');
    const backChannel = byType('BACK_CHANNEL_LOGOUT')[0];

    return {
      client_id: c.clientId,
      name: c.name,
      application_code: c.applicationCode,
      application_name: c.applicationName,
      business_unit: c.businessUnit,
      utility: c.utility,
      environment: c.environment,
      client_type: c.clientType,
      authentication_mode: c.authenticationMode,
      status: c.status,
      allowed_embed_origins: c.origins.map((o) => o.origin),
      callback_uri: primaryOf(callbackUris)?.uri ?? null,
      callback_uris: callbackUris.map((r) => r.uri),
      back_channel_logout_uri: backChannel?.uri ?? null,
      post_logout_redirect_uri: primaryOf(postLogoutUris)?.uri ?? null,
      post_logout_redirect_uris: postLogoutUris.map((r) => r.uri),
      initiate_login_uri: c.initiateLoginUri,
      config_version: new Date(c.updatedAt).toISOString(),
    };
  }
}
