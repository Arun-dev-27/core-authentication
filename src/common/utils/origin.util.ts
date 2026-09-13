/**
 * Exact origin / URI matching helpers. Registered values arrive already canonicalised by the
 * Authorization service; request-supplied values are canonicalised here and compared by equality only.
 * There is no wildcard, prefix, suffix or regex matching anywhere in the federation flow.
 */

export function canonicalOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || value.includes('*')) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (url.username || url.password || url.search || url.hash) return null;
    if (url.pathname !== '/' && url.pathname !== '') return null;
    return url.origin;
  } catch {
    return null;
  }
}

export function canonicalUri(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048 || value.includes('*')) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (url.username || url.password || url.hash) return null;
    return url.toString();
  } catch {
    return null;
  }
}

/** Returns the registered origin that exactly equals the candidate, or null. */
export function matchRegisteredOrigin(candidate: unknown, registered: readonly string[]): string | null {
  const origin = canonicalOrigin(candidate);
  if (!origin) return null;
  return registered.find((r) => canonicalOrigin(r) === origin) ?? null;
}

export function matchRegisteredUri(candidate: unknown, registered: readonly string[]): string | null {
  const uri = canonicalUri(candidate);
  if (!uri) return null;
  return registered.find((r) => canonicalUri(r) === uri) ?? null;
}

/** Origin portion of a Referer header, if parseable. */
export function originOfReferer(referer: unknown): string | null {
  if (typeof referer !== 'string') return null;
  try {
    return new URL(referer).origin;
  } catch {
    return null;
  }
}
