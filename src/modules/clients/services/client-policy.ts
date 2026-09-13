import { Errors } from '@common/errors/domain-error';
import { matchRegisteredOrigin, matchRegisteredUri } from '@common/utils/origin.util';
import type { FederationClientConfig } from '@shared/types/federation-client.types';

export type DisplayMode = 'embed' | 'page';

/**
 * Only ACTIVE clients may authenticate.
 * embed: requires EMBEDDED or EMBEDDED_OR_REDIRECT.
 * page : top-level flow; allowed for every mode because it is also the fallback when a browser
 *        blocks third-party iframe cookies/storage for an embedded client.
 */
export function assertClientCanAuthenticate(client: FederationClientConfig, display: DisplayMode): void {
  if (client.status !== 'ACTIVE') throw Errors.clientInactive();
  if (display === 'embed' && client.authentication_mode === 'REDIRECT') throw Errors.modeNotAllowed();
}

/** Exact match against registered embed origins. Defaults only when exactly one origin is registered. */
export function resolveEmbedOrigin(client: FederationClientConfig, requested?: string | null): string {
  if (requested) {
    const match = matchRegisteredOrigin(requested, client.allowed_embed_origins);
    if (!match) throw Errors.originNotAllowed();
    return match;
  }
  if (client.allowed_embed_origins.length === 1) return client.allowed_embed_origins[0];
  throw Errors.originNotAllowed();
}

/** Exact match against registered callback URIs. Browser input can only SELECT a registered value. */
export function resolveCallback(client: FederationClientConfig, requested?: string | null): string {
  if (requested) {
    const match = matchRegisteredUri(requested, client.callback_uris);
    if (!match) throw Errors.callbackNotAllowed();
    return match;
  }
  if (client.callback_uri) return client.callback_uri;
  throw Errors.callbackNotAllowed();
}

export function resolvePostLogoutRedirect(client: FederationClientConfig, requested?: string | null): string | null {
  if (requested) return matchRegisteredUri(requested, client.post_logout_redirect_uris);
  return client.post_logout_redirect_uri;
}
