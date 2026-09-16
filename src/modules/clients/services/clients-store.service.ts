import { Injectable } from '@nestjs/common';
import { InjectDataSource } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { FederationClientConfig } from '@shared/types/federation-client.types';

interface AuthClientRow {
  id: string;
  client_id: string;
  name: string;
  application_code: string;
  application_name: string;
  business_unit: string | null;
  utility: string | null;
  environment: string;
  client_type: string;
  authentication_mode: FederationClientConfig['authentication_mode'];
  status: FederationClientConfig['status'];
  initiate_login_uri: string | null;
  updated_at: Date;
}

interface CallbackRow {
  uri: string;
  uri_type: 'CALLBACK' | 'BACK_CHANNEL_LOGOUT' | 'POST_LOGOUT_REDIRECT';
  is_primary: boolean;
}

/**
 * The federation client registry's own storage - local to core-authentication, no dependency on any
 * authorization service. See AuthClients1789600000000 for why this moved here.
 */
@Injectable()
export class ClientsStoreService {
  constructor(@InjectDataSource() private readonly db: DataSource) {}

  async findByClientId(clientId: string): Promise<FederationClientConfig | null> {
    const rows = (await this.db.query(`SELECT * FROM auth_clients WHERE client_id = $1`, [clientId])) as AuthClientRow[];
    if (!rows.length) return null;
    const c = rows[0];

    const origins = (await this.db.query(`SELECT origin FROM auth_client_origins WHERE client_ref = $1 ORDER BY created_at`, [c.id])) as { origin: string }[];
    const callbacks = (await this.db.query(`SELECT uri, uri_type, is_primary FROM auth_client_callbacks WHERE client_ref = $1 ORDER BY created_at`, [c.id])) as CallbackRow[];

    const byType = (type: CallbackRow['uri_type']) => callbacks.filter((r) => r.uri_type === type);
    const primaryOf = (rows: CallbackRow[]) => rows.find((r) => r.is_primary) ?? rows[0];
    const callbackUris = byType('CALLBACK');
    const postLogoutUris = byType('POST_LOGOUT_REDIRECT');
    const backChannel = byType('BACK_CHANNEL_LOGOUT')[0];

    return {
      client_id: c.client_id,
      name: c.name,
      application_code: c.application_code,
      application_name: c.application_name,
      business_unit: c.business_unit,
      utility: c.utility,
      environment: c.environment,
      client_type: c.client_type,
      authentication_mode: c.authentication_mode,
      status: c.status,
      allowed_embed_origins: origins.map((o) => o.origin),
      callback_uri: primaryOf(callbackUris)?.uri ?? null,
      callback_uris: callbackUris.map((r) => r.uri),
      back_channel_logout_uri: backChannel?.uri ?? null,
      post_logout_redirect_uri: primaryOf(postLogoutUris)?.uri ?? null,
      post_logout_redirect_uris: postLogoutUris.map((r) => r.uri),
      initiate_login_uri: c.initiate_login_uri,
      config_version: new Date(c.updated_at).toISOString(),
    };
  }
}
