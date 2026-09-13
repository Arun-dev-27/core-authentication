/** Client configuration published by the Core Identity Authorization Service. */
export interface FederationClientConfig {
  client_id: string;
  name: string;
  application_code: string;
  application_name: string;
  business_unit: string | null;
  utility: string | null;
  environment: string;
  client_type: string;
  authentication_mode: 'EMBEDDED' | 'REDIRECT' | 'EMBEDDED_OR_REDIRECT';
  status: 'PENDING' | 'SECURITY_REVIEW' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
  allowed_embed_origins: string[];
  callback_uri: string | null;
  callback_uris: string[];
  back_channel_logout_uri: string | null;
  post_logout_redirect_uri: string | null;
  post_logout_redirect_uris: string[];
  initiate_login_uri: string | null;
  config_version: string;
}

export interface LaunchableApplication {
  application_code: string;
  application_name: string;
  business_unit: string | null;
  utility: string | null;
  environment: string;
  client_id: string | null;
  initiate_login_uri: string | null;
  launchable: boolean;
  roles: { code: string; name: string }[];
}

export type ScopeType = 'CORE' | 'BUSINESS_UNIT' | 'UTILITY';

/** One role held by the user in one scope - a card on the Select Workspace screen. */
export interface WorkspaceAssignment {
  role_id: string;
  role_name: string;
  scope_type: ScopeType;
  scope_id: string | null;
  scope_name: string | null;
}

export interface WorkspaceList {
  its_id: string;
  name: string | null;
  requires_scope_selection: boolean;
  assignments: WorkspaceAssignment[];
}

/** A validated workspace with its permission map { MODULE_CODE: [actions] }. */
export interface ResolvedWorkspace {
  active_scope: WorkspaceAssignment;
  permissions: Record<string, string[]>;
}

/** Active scope carried in an access token (never permissions). */
export interface ActiveScopeClaim {
  role_id: string;
  scope_type: ScopeType;
  scope_id: string | null;
}

/** Profile pushed to the Authorization service. Never contains credentials. */
export interface UserProfileSync {
  its_id: string;
  name?: string;
  email?: string;
  status?: 'active' | 'inactive' | 'suspended';
}
