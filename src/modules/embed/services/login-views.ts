import type { FastifyReply } from 'fastify';

export interface LoginPageBoot {
  mode: 'embed' | 'page' | 'portal';
  transaction_id: string;
  csrf: string;
  client_id: string | null;
  state: string | null;
  target_origin: string | null;
  callback_uri: string | null;
  application: { name: string; business_unit: string | null; utility: string | null; environment: string } | null;
  session: { its_id: string; display_name: string | null } | null;
  auto_continue: boolean;
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]!);
}

/** JSON for a non-executable data block; `<` is escaped so the payload can never close the tag. */
function safeJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

export function buildCsp(opts: { frameAncestors: string | null; formActionOrigin?: string | null }): string {
  return [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    `form-action 'self'${opts.formActionOrigin ? ` ${opts.formActionOrigin}` : ''}`,
    `frame-ancestors ${opts.frameAncestors ?? "'none'"}`,
    "base-uri 'none'",
    "object-src 'none'",
  ].join('; ');
}

function shell(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<link rel="icon" href="/assets/miqaat-mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/login.css">
</head>
<body>
${body}
</body>
</html>`;
}

const MARK = `<img class="brand-mark" src="/assets/miqaat-mark.svg" alt="" width="44" height="44">`;

export function renderLoginPage(boot: LoginPageBoot): string {
  const appName = boot.application?.name ?? 'Miqaat Core Portal';
  const body = `
<main class="shell ${boot.mode === 'embed' ? 'is-embedded' : 'is-page'}" id="app" aria-live="polite">
  <section class="card" aria-labelledby="title">
    <header class="brand">
      ${MARK}
      <div>
        <p class="brand-name">Miqaat Core</p>
        <p class="brand-sub">Identity Federation</p>
      </div>
    </header>
    <div class="context" ${boot.application ? '' : 'hidden'}>
      <span class="context-label">Signing in to</span>
      <span class="context-app">${escapeHtml(appName)}</span>
      ${boot.application ? `<span class="chip">${escapeHtml(boot.application.environment)}</span>` : ''}
    </div>
    <div id="view" class="view">
      <noscript><p class="alert">JavaScript is required to sign in.</p></noscript>
      <div class="spinner" role="status"><span class="sr-only">Loading…</span></div>
    </div>
    <footer class="card-foot">
      <span>Secured by Miqaat Core</span>
      <span aria-hidden="true">·</span>
      <span>Your password is never shared with ${escapeHtml(appName)}</span>
    </footer>
  </section>
</main>
<script type="application/json" id="miqaat-boot">${safeJson(boot)}</script>
<script src="/assets/login.js" defer></script>`;
  return shell(`Sign in · ${appName}`, body);
}

export interface ErrorPageExtras {
  /** A safe next step, e.g. open the registered application that owns this sign-in. */
  action?: { label: string; href: string; hint?: string };
  /** Present only when the page may be framed by this exact registered origin; notifies the parent by postMessage. */
  embedError?: { target_origin: string; transaction_id: string | null; state: string | null; error: string; code: string };
}

export function renderErrorPage(title: string, message: string, correlationId: string, extras: ErrorPageExtras = {}): string {
  const action = extras.action
    ? `${extras.action.hint ? `<p class="muted">${escapeHtml(extras.action.hint)}</p>` : ''}
      <a class="btn btn-primary" id="error-action" href="${escapeHtml(extras.action.href)}">${escapeHtml(extras.action.label)}</a>`
    : '';
  const notify = extras.embedError
    ? `
<script type="application/json" id="miqaat-error">${safeJson(extras.embedError)}</script>
<script src="/assets/embed-error.js" defer></script>`
    : '';
  const body = `
<main class="shell ${extras.embedError ? 'is-embedded' : 'is-page'}">
  <section class="card" aria-labelledby="error-title">
    <header class="brand">${MARK}<div><p class="brand-name">Miqaat Core</p><p class="brand-sub">Identity Federation</p></div></header>
    <div class="state state-error">
      <h1 id="error-title">${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
      ${action}
      <p class="muted">Reference: <code>${escapeHtml(correlationId)}</code></p>
    </div>
  </section>
</main>${notify}`;
  return shell(title, body);
}

export function sendHtml(reply: FastifyReply, status: number, html: string, csp: string): FastifyReply {
  return reply
    .status(status)
    .header('content-type', 'text/html; charset=utf-8')
    .header('content-security-policy', csp)
    .header('cache-control', 'no-store')
    .header('referrer-policy', 'no-referrer')
    .send(html);
}
