import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Federation client registry, owned by core-authentication itself.
 *
 * This was previously read from core-authorization over HTTP (ClientRegistry -> AuthzClient ->
 * GET /internal/federation/clients/:clientId). That made core-authentication depend on one specific
 * authorization service for data that is fundamentally an authentication-boundary concern (which
 * origins may embed the login iframe and receive an assertion for which client_id) - a decision that
 * does not scale once multiple authorization services exist (rms-authorization, mumin-portal-authorization,
 * ...): core-authentication cannot depend on any one of them, or all of them, for its own trust boundary.
 *
 * Matches the `auth_clients` / `auth_client_origins` / `auth_client_callbacks` tables already named in
 * the original architecture doc's data model (miqaat_core_embedded_federation_authentication_architecture
 * _nestjs_signing_v2.md, section 18) and the `auth_*` naming already used by InitAuthenticationSchema.
 */
export class AuthClients1789600000000 implements MigrationInterface {
  name = 'AuthClients1789600000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE auth_clients (
        id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_id           varchar(64)  NOT NULL UNIQUE CHECK (client_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
        name                varchar(255) NOT NULL,
        application_code    varchar(64)  NOT NULL,
        application_name    varchar(255) NOT NULL,
        business_unit       varchar(255),
        utility             varchar(255),
        environment         varchar(32)  NOT NULL,
        client_type         varchar(16)  NOT NULL DEFAULT 'WEB' CHECK (client_type IN ('WEB', 'SPA', 'MOBILE', 'SERVICE')),
        authentication_mode varchar(24)  NOT NULL CHECK (authentication_mode IN ('EMBEDDED', 'REDIRECT', 'EMBEDDED_OR_REDIRECT')),
        status              varchar(24)  NOT NULL DEFAULT 'PENDING'
                              CHECK (status IN ('PENDING', 'SECURITY_REVIEW', 'ACTIVE', 'SUSPENDED', 'RETIRED')),
        initiate_login_uri  varchar(2048),
        created_at          timestamptz  NOT NULL DEFAULT now(),
        updated_at          timestamptz  NOT NULL DEFAULT now()
      )`);

    await q.query(`
      CREATE TABLE auth_client_origins (
        id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_ref uuid NOT NULL REFERENCES auth_clients (id) ON DELETE CASCADE,
        origin     varchar(512) NOT NULL CHECK (origin !~ '\\*'),
        created_at timestamptz  NOT NULL DEFAULT now(),
        UNIQUE (client_ref, origin)
      )`);
    await q.query(`CREATE INDEX idx_auth_client_origins_client ON auth_client_origins (client_ref)`);

    await q.query(`
      CREATE TABLE auth_client_callbacks (
        id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        client_ref uuid NOT NULL REFERENCES auth_clients (id) ON DELETE CASCADE,
        uri        varchar(2048) NOT NULL CHECK (uri !~ '\\*'),
        uri_type   varchar(32)   NOT NULL CHECK (uri_type IN ('CALLBACK', 'BACK_CHANNEL_LOGOUT', 'POST_LOGOUT_REDIRECT')),
        is_primary boolean       NOT NULL DEFAULT false,
        created_at timestamptz   NOT NULL DEFAULT now(),
        UNIQUE (client_ref, uri, uri_type)
      )`);
    await q.query(`CREATE INDEX idx_auth_client_callbacks_client ON auth_client_callbacks (client_ref)`);
    await q.query(`CREATE UNIQUE INDEX uq_auth_client_single_backchannel ON auth_client_callbacks (client_ref) WHERE uri_type = 'BACK_CHANNEL_LOGOUT'`);
  }

  public async down(q: QueryRunner): Promise<void> {
    for (const table of ['auth_client_callbacks', 'auth_client_origins', 'auth_clients']) {
      await q.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
    }
  }
}
