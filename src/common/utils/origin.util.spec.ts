import { canonicalOrigin, matchRegisteredOrigin, matchRegisteredUri, originOfReferer } from './origin.util';

describe('origin.util (exact matching only)', () => {
  const registered = ['https://rms.example.com'];

  it('matches the exact registered origin (case-insensitive host, optional trailing slash)', () => {
    expect(matchRegisteredOrigin('https://rms.example.com', registered)).toBe('https://rms.example.com');
    expect(matchRegisteredOrigin('https://RMS.example.com/', registered)).toBe('https://rms.example.com');
  });

  it.each([
    'https://rms.example.com.evil.com',
    'https://evil-rms.example.com',
    'https://sub.rms.example.com',
    'http://rms.example.com',
    'https://rms.example.com:8443',
    'https://rms.example.com/path',
    '*',
    'null',
    '',
    undefined,
  ])('rejects look-alike or malformed origin %p', (candidate) => {
    expect(matchRegisteredOrigin(candidate, registered)).toBeNull();
  });

  it('never treats a registered wildcard as a pattern', () => {
    expect(canonicalOrigin('https://*.example.com')).toBeNull();
    expect(matchRegisteredOrigin('https://a.example.com', ['https://*.example.com'])).toBeNull();
  });

  it('matches callback URIs exactly', () => {
    const cbs = ['https://rms.example.com/auth/core/callback'];
    expect(matchRegisteredUri('https://rms.example.com/auth/core/callback', cbs)).toBe(cbs[0]);
    expect(matchRegisteredUri('https://rms.example.com/auth/core/callback/', cbs)).toBeNull();
    expect(matchRegisteredUri('https://rms.example.com/auth/core/callback?next=//evil', cbs)).toBeNull();
    expect(matchRegisteredUri('https://rms.example.com/auth/core/callback#x', cbs)).toBeNull();
  });

  it('extracts the origin from a referer', () => {
    expect(originOfReferer('https://rms.example.com/login?x=1')).toBe('https://rms.example.com');
    expect(originOfReferer('garbage')).toBeNull();
  });
});
