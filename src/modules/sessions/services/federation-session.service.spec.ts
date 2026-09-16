import { sha256Hex } from '@common/utils/crypto.util';
import { FederationSessionService } from './federation-session.service';
import type { FederationSession } from '@shared/types/session.types';

const IP = '203.0.113.7';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0';
const HANDLE = 'h'.repeat(43); // SESSION_HANDLE_PATTERN: 43 base64url chars

const session = (over: Partial<FederationSession> = {}): FederationSession => ({
  sid: 'sid_abc',
  its_id: '31267890',
  identity_type: 'ITS',
  display_name: 'Demo Admin',
  auth_method: 'password',
  auth_time: Math.floor(Date.now() / 1000),
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 1_800_000).toISOString(),
  absolute_expires_at: new Date(Date.now() + 28_800_000).toISOString(),
  is_active: true,
  handle_hash: sha256Hex(HANDLE),
  ip_address: IP,
  user_agent: UA,
  ...over,
});

function build(stored: FederationSession | null, opts: { sidForHandle?: string | null } = {}) {
  const audit = { record: jest.fn().mockResolvedValue(undefined) };
  const redis = {
    get: jest.fn(async (key: string) => {
      if (key.includes('session-handle:')) return opts.sidForHandle === undefined ? (stored ? stored.sid : null) : opts.sidForHandle;
      if (key.includes('session:')) return stored ? JSON.stringify(stored) : null;
      return null;
    }),
  };
  const config = { env: { SESSION_IDLE_TTL_SECONDS: 1800, SESSION_ABSOLUTE_TTL_SECONDS: 28800 } };
  const svc = new FederationSessionService(redis as never, { query: jest.fn() } as never, config as never, audit as never);
  return { svc, audit };
}

describe('FederationSessionService.resolveByHandle binding', () => {
  it('resolves for the same IP and User-Agent', async () => {
    const { svc } = build(session());
    const result = await svc.resolveByHandle(HANDLE, { ip: IP, userAgent: UA });
    expect(result.ok).toBe(true);
  });

  it('refuses a different IP', async () => {
    const { svc } = build(session());
    expect(await svc.resolveByHandle(HANDLE, { ip: '198.51.100.9', userAgent: UA })).toMatchObject({ ok: false, reason: 'IP_MISMATCH' });
  });

  it('refuses a different User-Agent', async () => {
    const { svc } = build(session());
    expect(await svc.resolveByHandle(HANDLE, { ip: IP, userAgent: 'PostmanRuntime/7.39.0' })).toMatchObject({
      ok: false,
      reason: 'USER_AGENT_MISMATCH',
    });
  });

  it('refuses a missing cookie', async () => {
    const { svc } = build(session());
    expect(await svc.resolveByHandle(undefined, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'INVALID_HANDLE' });
  });

  it('refuses a tampered handle without consulting Redis', async () => {
    const { svc } = build(session());
    expect(await svc.resolveByHandle('not-a-valid-handle', { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'INVALID_HANDLE' });
  });

  it('refuses a handle whose index entry is gone (expired or revoked)', async () => {
    const { svc } = build(session(), { sidForHandle: null });
    expect(await svc.resolveByHandle(HANDLE, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'NOT_FOUND' });
  });

  it('refuses a session past its absolute expiry', async () => {
    const { svc } = build(session({ absolute_expires_at: new Date(Date.now() - 1000).toISOString() }));
    expect(await svc.resolveByHandle(HANDLE, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'NOT_FOUND' });
  });

  it('refuses an inactive (revoked) session', async () => {
    const { svc } = build(session({ is_active: false }));
    expect(await svc.resolveByHandle(HANDLE, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'NOT_FOUND' });
  });

  it('refuses a handle that does not hash to the session it indexes', async () => {
    const { svc } = build(session({ handle_hash: sha256Hex('x'.repeat(43)) }));
    expect(await svc.resolveByHandle(HANDLE, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'NOT_FOUND' });
  });

  it('refuses a legacy session stored without binding values', async () => {
    const { svc } = build(session({ ip_address: null, user_agent: null }));
    expect(await svc.resolveByHandle(HANDLE, { ip: IP, userAgent: UA })).toMatchObject({ ok: false, reason: 'BINDING_MISSING' });
  });

  it('audits a mismatch with the reason and masked values only', async () => {
    const { svc, audit } = build(session());
    await svc.resolveByHandle(HANDLE, { ip: '198.51.100.9', userAgent: UA });
    expect(audit.record).toHaveBeenCalledTimes(1);
    const event = audit.record.mock.calls[0][0];
    expect(event).toMatchObject({ eventType: 'FEDERATION_SESSION_BINDING_REJECTED', outcome: 'FAILURE' });
    const serialised = JSON.stringify(event);
    expect(serialised).not.toContain(IP);
    expect(serialised).not.toContain('198.51.100.9');
    expect(serialised).not.toContain(UA);
    expect(serialised).not.toContain(HANDLE);
    expect(event.metadata).toMatchObject({ reason: 'IP_MISMATCH', stored_ip: '203.0.113.x', current_ip: '198.51.100.x' });
  });

  it('getByHandle collapses every refusal to null', async () => {
    const { svc } = build(session());
    expect(await svc.getByHandle(HANDLE, { ip: '198.51.100.9', userAgent: UA })).toBeNull();
    expect(await svc.getByHandle(HANDLE, { ip: IP, userAgent: UA })).not.toBeNull();
  });
});
