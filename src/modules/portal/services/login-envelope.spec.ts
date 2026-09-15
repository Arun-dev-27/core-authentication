import type { WorkspaceAssignment } from '@shared/types/federation-client.types';
import { errorEnvelope, LoginSession, moduleSlug, roleType, successEnvelope, toLoginRole, toModulePermissions } from './login-envelope';

const CORE: WorkspaceAssignment = { role_id: 'r-core', role_name: 'Platform Administrator', scope_type: 'CORE', scope_id: null, scope_name: 'Miqaat' };
const BU: WorkspaceAssignment = { role_id: 'r-bu', role_name: 'Business Unit Admin', scope_type: 'BUSINESS_UNIT', scope_id: 'bu-1', scope_name: 'RMS' };
const UT: WorkspaceAssignment = { role_id: 'r-ut', role_name: 'Utility Admin', scope_type: 'UTILITY', scope_id: 'ut-1', scope_name: 'Helpdesk' };

describe('login envelope', () => {
  it('role_type is SINGLE, MULTI or NONE by number of roles', () => {
    expect(roleType(0)).toBe('NONE');
    expect(roleType(1)).toBe('SINGLE');
    expect(roleType(2)).toBe('MULTI');
    expect(roleType(5)).toBe('MULTI');
  });

  it('maps a workspace to a role with level and tenant', () => {
    expect(toLoginRole(CORE)).toEqual({ role_id: 'r-core', role_name: 'Platform Administrator', level: 'CORE_ADMIN', tenant_id: 'CORE', tenant_name: 'Core', scope_type: 'CORE', scope_id: null });
    expect(toLoginRole(BU)).toEqual({ role_id: 'r-bu', role_name: 'Business Unit Admin', level: 'BUSINESS_UNIT_ADMIN', tenant_id: 'bu-1', tenant_name: 'RMS', scope_type: 'BUSINESS_UNIT', scope_id: 'bu-1' });
    expect(toLoginRole(UT)).toMatchObject({ level: 'UTILITY_ADMIN', tenant_id: 'ut-1', tenant_name: 'Helpdesk' });
    expect(toLoginRole({ ...UT, scope_name: null }).tenant_name).toBe('ut-1');
  });

  it('turns module codes into slugs', () => {
    const codes = ['DASHBOARD', 'BUSINESS_UNIT_MGMT', 'UTILITY_MGMT', 'ROLE_MGMT', 'USER_MGMT', 'MUMIN_INFO', 'EVENT_CONTRACT', 'API_CONTRACT', 'CONTRACT_LIBRARY', 'ACCESS_REQUEST', 'TICKET_MGMT', 'MONITORING', 'AUDIT_LOG', 'CONFIGURATION'];
    expect(codes.map(moduleSlug)).toEqual([
      'dashboard', 'business-unit-management', 'utility-management', 'role-management', 'user-management', 'mumin-information',
      'event-contract', 'api-contract', 'contract-library', 'access-request', 'ticket-management', 'monitoring', 'audit-log', 'configuration',
    ]);
    expect(moduleSlug('RMS_REGISTRATION')).toBe('rms-registration');
  });

  it('converts the permission map to modules and create/read/update/delete/approve/export flags', () => {
    const { modules, permissions } = toModulePermissions({ DASHBOARD: ['view'], ROLE_MGMT: ['view', 'create', 'edit'], EVENT_CONTRACT: ['view', 'create', 'approve'], HIDDEN: [], AUDIT_LOG: ['view', 'export', 'unknown'] });
    expect(modules).toEqual(['dashboard', 'role-management', 'event-contract', 'audit-log']);
    expect(permissions.dashboard).toEqual({ create: false, read: true, update: false, delete: false, approve: false, export: false });
    expect(permissions['role-management']).toEqual({ create: true, read: true, update: true, delete: false, approve: false, export: false });
    expect(permissions['event-contract']).toMatchObject({ create: true, read: true, approve: true, update: false });
    expect(permissions['audit-log']).toMatchObject({ read: true, export: true });
    expect(permissions).not.toHaveProperty('hidden');
    expect(toModulePermissions({})).toEqual({ modules: [], permissions: {} });
  });

  it('success envelope: scope follows the active role; null before a role is chosen', () => {
    const now = new Date('2026-09-15T11:42:07.512Z');
    const base: LoginSession = {
      token: 't', token_type: 'Bearer', expires_in: 600, audience: 'miqaat-core-authorization',
      user: { id: '30416234', its_id: '30416234', name: 'Ali Hakim', status: 'ACTIVE' },
      role_type: 'SINGLE', active_role: toLoginRole(CORE), roles: [toLoginRole(CORE)], modules: [], permissions: {}, onboarding_required: false,
    };
    expect(successEnvelope('req-1', base, now)).toEqual({ success: true, session: base, request_id: 'req-1', timestamp: '2026-09-15T11:42:07.512Z', scope: 'PLATFORM', error: null });
    expect(successEnvelope('req-2', { ...base, active_role: toLoginRole(BU) }, now).scope).toBe('BUSINESS_UNIT');
    expect(successEnvelope('req-3', { ...base, active_role: toLoginRole(UT) }, now).scope).toBe('UTILITY');
    expect(successEnvelope('req-4', { ...base, role_type: 'MULTI', active_role: null }, now).scope).toBeNull();
  });

  it('error envelope carries code, message and details', () => {
    const now = new Date('2026-09-15T11:42:07.512Z');
    expect(errorEnvelope('req-9', { error: 'CSRF_VALIDATION_FAILED', message: 'nope', details: { reason: 'CSRF_TOKEN_MISMATCH' } }, now)).toEqual({
      success: false, session: null, request_id: 'req-9', timestamp: '2026-09-15T11:42:07.512Z', scope: null,
      error: { code: 'CSRF_VALIDATION_FAILED', message: 'nope', details: { reason: 'CSRF_TOKEN_MISMATCH' } },
    });
    expect(errorEnvelope('req-10', { error: 'INVALID_CREDENTIALS', message: 'Invalid ITS ID or password' }, now).error).toEqual({ code: 'INVALID_CREDENTIALS', message: 'Invalid ITS ID or password' });
  });
});
