import {
  USER_AGENT_MAX_LENGTH,
  bindingAuditMetadata,
  checkSessionBinding,
  maskIp,
  normalizeIp,
  normalizeUserAgent,
  userAgentFingerprint,
} from './session-binding';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0';
const IP = '203.0.113.7';
const stored = { ipAddress: IP, userAgent: UA };

describe('checkSessionBinding', () => {
  it('allows the same IP and the same User-Agent', () => {
    expect(checkSessionBinding(stored, { ip: IP, userAgent: UA })).toEqual({ ok: true });
  });

  it('refuses a different IP', () => {
    expect(checkSessionBinding(stored, { ip: '198.51.100.9', userAgent: UA })).toEqual({ ok: false, reason: 'IP_MISMATCH' });
  });

  it('refuses a different User-Agent', () => {
    expect(checkSessionBinding(stored, { ip: IP, userAgent: 'PostmanRuntime/7.39.0' })).toEqual({
      ok: false,
      reason: 'USER_AGENT_MISMATCH',
    });
  });

  it('refuses a User-Agent that merely shares a prefix', () => {
    expect(checkSessionBinding(stored, { ip: IP, userAgent: UA.slice(0, UA.length - 1) })).toEqual({
      ok: false,
      reason: 'USER_AGENT_MISMATCH',
    });
  });

  it('checks the IP before the User-Agent so the reported reason is stable', () => {
    expect(checkSessionBinding(stored, { ip: '198.51.100.9', userAgent: 'curl/8.4.0' })).toEqual({
      ok: false,
      reason: 'IP_MISMATCH',
    });
  });

  // Fail closed: an unbindable session must not become an unchecked one.
  it.each([
    ['no stored IP', { ipAddress: null, userAgent: UA }, { ip: IP, userAgent: UA }],
    ['no stored User-Agent', { ipAddress: IP, userAgent: null }, { ip: IP, userAgent: UA }],
    ['request sends no User-Agent', stored, { ip: IP, userAgent: null }],
    ['request has no IP', stored, { ip: null, userAgent: UA }],
    ['request sends an empty User-Agent', stored, { ip: IP, userAgent: '   ' }],
  ])('refuses when %s', (_label, s, ctx) => {
    expect(checkSessionBinding(s, ctx)).toEqual({ ok: false, reason: 'BINDING_MISSING' });
  });

  it('treats an IPv4-mapped IPv6 address as the IPv4 address it is', () => {
    expect(checkSessionBinding(stored, { ip: `::ffff:${IP}`, userAgent: UA })).toEqual({ ok: true });
  });

  it('ignores surrounding whitespace and an IPv6 zone index', () => {
    expect(checkSessionBinding({ ipAddress: 'fe80::1', userAgent: UA }, { ip: 'fe80::1%eth0', userAgent: ` ${UA} ` })).toEqual({ ok: true });
  });

  it('compares only the first USER_AGENT_MAX_LENGTH characters, matching what is stored', () => {
    const long = 'A'.repeat(USER_AGENT_MAX_LENGTH);
    expect(checkSessionBinding({ ipAddress: IP, userAgent: long }, { ip: IP, userAgent: long + 'TRAILING' })).toEqual({ ok: true });
  });
});

describe('normalisation', () => {
  it('canonicalises IP forms', () => {
    expect(normalizeIp('::FFFF:203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeIp('[2001:db8::1]')).toBe('2001:db8::1');
    expect(normalizeIp('::1')).toBe('127.0.0.1');
    expect(normalizeIp('')).toBeNull();
    expect(normalizeIp(undefined)).toBeNull();
  });

  it('trims and caps the User-Agent', () => {
    expect(normalizeUserAgent('  x  ')).toBe('x');
    expect(normalizeUserAgent('')).toBeNull();
    expect(normalizeUserAgent('B'.repeat(600))?.length).toBe(USER_AGENT_MAX_LENGTH);
  });
});

describe('log redaction', () => {
  it('masks the host octet of an IPv4 address and the tail of an IPv6 one', () => {
    expect(maskIp(IP)).toBe('203.0.113.x');
    expect(maskIp('2001:db8:1:2::1')).toBe('2001:db8:1:x');
  });

  it('fingerprints a User-Agent without revealing it', () => {
    const fp = userAgentFingerprint(UA)!;
    expect(fp).toHaveLength(12);
    expect(UA).not.toContain(fp);
    expect(userAgentFingerprint(UA)).toBe(fp);
    expect(userAgentFingerprint('other')).not.toBe(fp);
  });

  it('never puts a full IP or User-Agent in audit metadata', () => {
    const meta = bindingAuditMetadata('IP_MISMATCH', stored, { ip: '198.51.100.9', userAgent: 'PostmanRuntime/7.39.0' });
    const serialised = JSON.stringify(meta);
    expect(serialised).not.toContain(IP);
    expect(serialised).not.toContain('198.51.100.9');
    expect(serialised).not.toContain(UA);
    expect(serialised).not.toContain('PostmanRuntime/7.39.0');
    expect(meta).toMatchObject({ reason: 'IP_MISMATCH', stored_ip: '203.0.113.x', current_ip: '198.51.100.x' });
  });
});
