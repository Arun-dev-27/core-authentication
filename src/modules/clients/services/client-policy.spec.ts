import type { FederationClientConfig } from '@shared/types/federation-client.types';
import { assertClientCanAuthenticate, resolveCallback, resolveEmbedOrigin, resolvePostLogoutRedirect } from './client-policy';

const client = (overrides: Partial<FederationClientConfig> = {}): FederationClientConfig => ({
  client_id: 'rms-web-prod',
  name: 'RMS Web',
  application_code: 'rms',
  application_name: 'RMS Web',
  business_unit: 'RMS',
  utility: null,
  environment: 'PROD',
  client_type: 'WEB',
  authentication_mode: 'EMBEDDED',
  status: 'ACTIVE',
  allowed_embed_origins: ['https://rms.example.com'],
  callback_uri: 'https://rms.example.com/auth/core/callback',
  callback_uris: ['https://rms.example.com/auth/core/callback'],
  back_channel_logout_uri: 'https://rms.example.com/auth/core/logout',
  post_logout_redirect_uri: 'https://rms.example.com/logout/callback',
  post_logout_redirect_uris: ['https://rms.example.com/logout/callback'],
  initiate_login_uri: null,
  config_version: '2026-09-13T00:00:00.000Z',
  ...overrides,
});

describe('client-policy', () => {
  it.each(['PENDING', 'SECURITY_REVIEW', 'SUSPENDED', 'RETIRED'] as const)('blocks %s clients', (status) => {
    expect(() => assertClientCanAuthenticate(client({ status }), 'embed')).toThrow(expect.objectContaining({ code: 'CLIENT_NOT_ACTIVE' }));
  });

  it('allows ACTIVE embedded clients, blocks embedding REDIRECT-only clients', () => {
    expect(() => assertClientCanAuthenticate(client(), 'embed')).not.toThrow();
    expect(() => assertClientCanAuthenticate(client(), 'page')).not.toThrow();
    expect(() => assertClientCanAuthenticate(client({ authentication_mode: 'REDIRECT' }), 'embed')).toThrow(
      expect.objectContaining({ code: 'AUTHENTICATION_MODE_NOT_ALLOWED' }),
    );
  });

  it('resolves embed origins by exact match only', () => {
    expect(resolveEmbedOrigin(client())).toBe('https://rms.example.com');
    expect(resolveEmbedOrigin(client(), 'https://rms.example.com')).toBe('https://rms.example.com');
    expect(() => resolveEmbedOrigin(client(), 'https://ams.example.com')).toThrow(expect.objectContaining({ code: 'ORIGIN_NOT_ALLOWED' }));
    expect(() => resolveEmbedOrigin(client({ allowed_embed_origins: ['https://a.example.com', 'https://b.example.com'] }))).toThrow();
  });

  it('never accepts an unregistered callback from the browser', () => {
    expect(resolveCallback(client())).toBe('https://rms.example.com/auth/core/callback');
    expect(() => resolveCallback(client(), 'https://evil.example.com/steal')).toThrow(expect.objectContaining({ code: 'CALLBACK_NOT_ALLOWED' }));
    expect(() => resolveCallback(client({ callback_uri: null, callback_uris: [] }))).toThrow();
  });

  it('only redirects after logout to registered URIs', () => {
    expect(resolvePostLogoutRedirect(client(), 'https://evil.example.com')).toBeNull();
    expect(resolvePostLogoutRedirect(client())).toBe('https://rms.example.com/logout/callback');
  });
});
