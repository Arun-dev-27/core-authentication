import type { ScopeType, WorkspaceAssignment } from '@shared/types/federation-client.types';

/**
 * Response envelope of the Core login endpoints (POST /login, /portal/login, /select-scope, /portal/select-scope).
 *
 *   { success, session: { token, user, role_type, active_role, roles[], modules[], permissions{} , ... }, request_id, timestamp, scope, error }
 *
 * role_type: SINGLE (the only role is active), MULTI (choose one with /select-scope), NONE (no role assigned).
 * Everything is derived from the Authorization service's workspace data; no business rule lives here.
 */

export type RoleType = 'SINGLE' | 'MULTI' | 'NONE';
export type RoleLevel = 'CORE_ADMIN' | 'BUSINESS_UNIT_ADMIN' | 'UTILITY_ADMIN';
export type LoginScope = 'PLATFORM' | 'BUSINESS_UNIT' | 'UTILITY';

export interface LoginRole {
  role_id: string;
  role_name: string;
  level: RoleLevel;
  /** "CORE" for a Core role, otherwise the business unit / utility id. */
  tenant_id: string;
  tenant_name: string;
  /** Send scope_type + scope_id (with role_id) to POST /select-scope. */
  scope_type: ScopeType;
  scope_id: string | null;
}

export interface ModulePermissions {
  create: boolean;
  read: boolean;
  update: boolean;
  delete: boolean;
  approve: boolean;
  export: boolean;
}

export interface LoginUser {
  id: string;
  its_id: string;
  name: string | null;
  status: 'ACTIVE';
}

/** Embedded login only: how the core_assertion (session.token) is handed to the application. */
export interface EmbedDelivery {
  type: 'MIQAAT_AUTH_SUCCESS';
  transaction_id: string;
  state: string;
  delivery: 'post_message' | 'form_post';
  target_origin?: string;
  callback_uri?: string;
}

export interface LoginSession {
  /** Core Portal: at+jwt access token (Bearer). Embedded login: the one-time core_assertion (CoreAssertion). */
  token: string;
  token_type: 'Bearer' | 'CoreAssertion';
  expires_in: number;
  /** Authorization API audience, or the client_id the core_assertion was issued for. */
  audience: string;
  user: LoginUser;
  role_type: RoleType;
  active_role: LoginRole | null;
  roles: LoginRole[];
  modules: string[];
  permissions: Record<string, ModulePermissions>;
  onboarding_required: boolean;
  delivery?: EmbedDelivery;
}

export interface LoginEnvelope {
  success: true;
  session: LoginSession;
  request_id: string;
  timestamp: string;
  scope: LoginScope | null;
  error: null;
}

export interface LoginErrorEnvelope {
  success: false;
  session: null;
  request_id: string;
  timestamp: string;
  scope: null;
  error: { code: string; message: string; details?: unknown };
}

const LEVELS: Record<ScopeType, RoleLevel> = { CORE: 'CORE_ADMIN', BUSINESS_UNIT: 'BUSINESS_UNIT_ADMIN', UTILITY: 'UTILITY_ADMIN' };
const SCOPES: Record<ScopeType, LoginScope> = { CORE: 'PLATFORM', BUSINESS_UNIT: 'BUSINESS_UNIT', UTILITY: 'UTILITY' };
/** Authorization service action names → response keys. */
const ACTION_KEYS: Record<string, keyof ModulePermissions> = { view: 'read', create: 'create', edit: 'update', delete: 'delete', approve: 'approve', export: 'export' };

export function roleType(roleCount: number): RoleType {
  if (roleCount === 0) return 'NONE';
  return roleCount === 1 ? 'SINGLE' : 'MULTI';
}

export function toLoginRole(workspace: WorkspaceAssignment): LoginRole {
  const core = workspace.scope_type === 'CORE';
  return {
    role_id: workspace.role_id,
    role_name: workspace.role_name,
    level: LEVELS[workspace.scope_type],
    tenant_id: core ? 'CORE' : (workspace.scope_id ?? ''),
    tenant_name: core ? 'Core' : (workspace.scope_name ?? workspace.scope_id ?? ''),
    scope_type: workspace.scope_type,
    scope_id: workspace.scope_id ?? null,
  };
}

/** DASHBOARD → dashboard, BUSINESS_UNIT_MGMT → business-unit-management, MUMIN_INFO → mumin-information. */
export function moduleSlug(moduleCode: string): string {
  return moduleCode.toLowerCase().replace(/_mgmt$/, '_management').replace(/_info$/, '_information').replace(/_/g, '-');
}

/** { MODULE_CODE: [actions] } → modules[] (granted at least one action) and { slug: { create, read, update, ... } }. */
export function toModulePermissions(permissionMap: Record<string, string[]>): { modules: string[]; permissions: Record<string, ModulePermissions> } {
  const modules: string[] = [];
  const permissions: Record<string, ModulePermissions> = {};
  for (const [code, actions] of Object.entries(permissionMap ?? {})) {
    if (!Array.isArray(actions) || actions.length === 0) continue;
    const entry: ModulePermissions = { create: false, read: false, update: false, delete: false, approve: false, export: false };
    for (const action of actions) {
      const key = ACTION_KEYS[action];
      if (key) entry[key] = true;
    }
    const slug = moduleSlug(code);
    modules.push(slug);
    permissions[slug] = entry;
  }
  return { modules, permissions };
}

export function loginScope(role: LoginRole | null): LoginScope | null {
  return role ? SCOPES[role.scope_type] : null;
}

export function successEnvelope(requestId: string, session: LoginSession, now = new Date()): LoginEnvelope {
  return { success: true, session, request_id: requestId, timestamp: now.toISOString(), scope: loginScope(session.active_role), error: null };
}

export function errorEnvelope(requestId: string, error: { error: string; message: string; details?: unknown }, now = new Date()): LoginErrorEnvelope {
  return {
    success: false,
    session: null,
    request_id: requestId,
    timestamp: now.toISOString(),
    scope: null,
    error: { code: error.error, message: error.message, ...(error.details !== undefined ? { details: error.details } : {}) },
  };
}
