/*
 * Miqaat Core embedded login - error notification.
 *
 * Loaded only on error pages the server allowed to be framed by the transaction's registered embed origin
 * (client, origin and fetch-metadata checks already passed). Tells the parent application what happened so it
 * can restart sign-in instead of showing a dead frame. The target origin is the exact registered origin, never "*".
 */
(function () {
  'use strict';
  var el = document.getElementById('miqaat-error');
  if (!el || window.parent === window) return;
  var data;
  try {
    data = JSON.parse(el.textContent || '{}');
  } catch (e) {
    return;
  }
  if (typeof data.target_origin !== 'string' || !data.target_origin) return;
  window.parent.postMessage(
    { type: 'MIQAAT_AUTH_ERROR', transaction_id: data.transaction_id, state: data.state, error: data.error, code: data.code },
    data.target_origin,
  );
})();
