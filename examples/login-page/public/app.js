/*
 * Miqaat Login Page frontend.
 * - hosts the Identity login form in an iframe (embedded login)
 * - validates every postMessage (origin, source, type, transaction_id, state, schema) and forwards the
 *   core_assertion unchanged to this page's backend, which does all verification
 * - shows authentication (Identity JWKS) and authorization (Authorization JWKS) as two separate results
 */
(function () {
  'use strict';
  var root = document.getElementById('root');
  var cfg = null;
  var pending = null; // { transaction_id, state, iframe }
  var watcher = null;
  var JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      var v = attrs[k];
      if (v === undefined || v === null || v === false) return;
      if (k === 'text') n.textContent = v;
      else if (k === 'onClick') n.addEventListener('click', v);
      else if (k === 'onSubmit') n.addEventListener('submit', v);
      else n.setAttribute(k, v === true ? '' : v);
    });
    (children || []).forEach(function (c) { if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }

  function api(method, path, body) {
    return fetch(path, {
      method: method,
      credentials: 'same-origin',
      headers: body ? { 'content-type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { status: r.status, body: d }; });
    });
  }

  function params() { return new URLSearchParams(window.location.search); }
  function clearQuery() { window.history.replaceState(null, '', '/'); }

  function notice(kind, text) {
    return el('div', { class: 'notice notice-' + kind, role: kind === 'bad' ? 'alert' : 'status', text: text });
  }

  // ------------------------------------------------------------ key sets
  function keysSection() {
    var box = el('div', { class: 'keys' }, [el('p', { class: 'muted', text: 'Loading published keys…' })]);
    api('GET', '/api/jwks').then(function (res) {
      box.replaceChildren(keyCard('authn', 'Authentication keys', res.body.authentication), keyCard('authz', 'Authorization keys', res.body.authorization));
    });
    return el('section', { class: 'block', 'aria-labelledby': 'keys-title' }, [
      el('h2', { id: 'keys-title', text: 'Published keys (JWKS)' }),
      el('p', { class: 'muted', text: 'Each service publishes its own public keys. This page checks every token only against the keys of the service that signed it.' }),
      box,
    ]);
  }

  function keyCard(kind, title, set) {
    set = set || { keys: [] };
    return el('div', { class: 'keycard keycard-' + kind }, [
      el('div', { class: 'keycard-head' }, [el('span', { class: 'tag tag-' + kind, text: kind === 'authn' ? 'Authentication' : 'Authorization' }), el('strong', { text: title })]),
      el('div', { class: 'kv' }, [
        el('span', { class: 'muted', text: 'Signed by' }), el('span', { text: set.signed_by || '' }),
        el('span', { class: 'muted', text: 'JWKS' }), el('a', { href: set.jwks_uri, target: '_blank', rel: 'noopener', text: set.jwks_uri || '' }),
        el('span', { class: 'muted', text: 'Keys' }),
        set.error
          ? el('span', { class: 'bad-text', text: 'Not reachable. Is the service running?' })
          : el('span', {}, set.keys.map(function (k) { return el('code', { class: 'chip', text: k.kid + ' · ' + k.alg }); })),
      ]),
    ]);
  }

  // ------------------------------------------------------------ verification results
  function resultCard(kind, result, extra) {
    if (!result) {
      return el('div', { class: 'result result-' + kind + ' result-empty' }, [
        el('div', { class: 'result-head' }, [el('span', { class: 'tag tag-' + kind, text: kind === 'authn' ? '1 · Authentication' : '2 · Authorization' }), el('span', { class: 'muted', text: 'Not reached' })]),
      ]);
    }
    return el('div', { class: 'result result-' + kind }, [
      el('div', { class: 'result-head' }, [
        el('span', { class: 'tag tag-' + kind, text: kind === 'authn' ? '1 · Authentication' : '2 · Authorization' }),
        el('span', { class: 'status status-ok', text: 'Signature verified' }),
      ]),
      el('div', { class: 'kv' }, [
        el('span', { class: 'muted', text: 'Signed by' }), el('span', { text: result.signed_by }),
        el('span', { class: 'muted', text: 'Verified with' }), el('code', { text: result.jwks_uri }),
        el('span', { class: 'muted', text: 'Key (kid)' }), el('code', { text: result.kid }),
        el('span', { class: 'muted', text: 'Token type' }), el('code', { text: result.typ + ' · ' + result.alg }),
      ]),
      extra || null,
      el('ul', { class: 'checks' }, result.checks.map(function (c) { return el('li', { text: c }); })),
      el('details', {}, [el('summary', { text: 'Verified claims' }), el('pre', { text: JSON.stringify(result.claims, null, 2) })]),
    ]);
  }

  function accessBlock(authz) {
    if (!authz) return null;
    var granted = authz.access === 'GRANTED';
    return el('div', { class: 'access' }, [
      el('div', { class: 'kv' }, [
        el('span', { class: 'muted', text: 'Access' }),
        el('span', { class: 'status ' + (granted ? 'status-ok' : 'status-bad'), text: granted ? 'GRANTED' : 'DENIED' + (authz.reason ? ' · ' + authz.reason : '') }),
        el('span', { class: 'muted', text: 'Roles' }),
        el('span', {}, authz.roles.length ? authz.roles.map(function (r) { return el('span', { class: 'chip', text: r.role_name + ' · ' + r.scope_type }); }) : [el('span', { class: 'muted', text: 'none for this application' })]),
        el('span', { class: 'muted', text: 'Permissions' }),
        el('span', {}, authz.permissions.length ? authz.permissions.map(function (p) { return el('code', { class: 'chip', text: p }); }) : [el('span', { class: 'muted', text: 'none' })]),
      ]),
    ]);
  }

  // ------------------------------------------------------------ signed out
  function renderSignedOut(message, lastResult) {
    stopWatcher();
    var frame = el('div', { class: 'frame' }, [el('p', { class: 'muted', text: 'Preparing the secure sign-in…' })]);
    var children = [
      el('section', { class: 'hero' }, [
        el('div', { class: 'hero-text' }, [
          el('h1', { text: 'Sign in' }),
          el('p', { class: 'lead', text: 'Use your ITS ID and password. The form is served by Miqaat Identity inside this page, so this application never sees your password.' }),
          message || null,
          el('ol', { class: 'flow' }, [
            el('li', {}, [el('strong', { text: 'Identity signs you in' }), ' and hands this page a 60-second core_assertion.']),
            el('li', {}, [el('strong', { text: 'Authentication check:' }), ' the backend verifies it with the Identity JWKS.']),
            el('li', {}, [el('strong', { text: 'Authorization check:' }), ' the backend asks Authorization for a signed authorization_token and verifies it with the Authorization JWKS.']),
            el('li', {}, [el('strong', { text: 'Session:' }), ' only when both pass and access is granted, this page creates its own session.']),
          ]),
        ]),
        el('div', { class: 'hero-frame' }, [frame]),
      ]),
    ];
    if (lastResult && (lastResult.authentication || lastResult.authorization)) {
      children.push(el('section', { class: 'block' }, [
        el('h2', { text: 'Last sign-in attempt' }),
        el('div', { class: 'results' }, [
          resultCard('authn', lastResult.authentication),
          resultCard('authz', lastResult.authorization, accessBlock(lastResult.authorization)),
        ]),
      ]));
    }
    children.push(keysSection(), adminSection(null));
    root.replaceChildren.apply(root, children);
    startEmbed(frame);
  }

  function startEmbed(container) {
    api('POST', '/auth/core/start', { display: 'embed' }).then(function (res) {
      if (res.status !== 200) {
        container.replaceChildren(notice('bad', 'Sign-in could not start: ' + (res.body.error || res.status) + (res.body.hint ? '. ' + res.body.hint : '')));
        return;
      }
      var iframe = el('iframe', {
        class: 'login-frame',
        title: 'Miqaat sign in',
        src: res.body.login_url,
        referrerpolicy: 'origin',
        allow: 'storage-access',
        sandbox: 'allow-scripts allow-forms allow-same-origin allow-storage-access-by-user-activation',
      });
      pending = { transaction_id: res.body.transaction_id, state: res.body.state, iframe: iframe };
      container.replaceChildren(iframe);
    });
  }

  function startTopLevel() {
    api('POST', '/auth/core/start', { display: 'page' }).then(function (res) {
      if (res.status === 200) window.location.assign(res.body.login_url);
    });
  }

  window.addEventListener('message', function (event) {
    if (!cfg || event.origin !== cfg.identity_origin) return;               // exact Identity origin
    if (!pending || event.source !== pending.iframe.contentWindow) return;  // our iframe only
    var data = event.data;
    if (!data || typeof data !== 'object' || typeof data.type !== 'string' || data.transaction_id !== pending.transaction_id) return;

    if (data.type === 'MIQAAT_AUTH_RESIZE' && typeof data.height === 'number') {
      pending.iframe.style.height = Math.min(Math.max(data.height, 360), 1200) + 'px';
      return;
    }
    if (data.type === 'MIQAAT_AUTH_TOP_LEVEL_REQUIRED') return startTopLevel();
    if (data.type === 'MIQAAT_AUTH_ERROR') {
      if (data.error === 'TRANSACTION_EXPIRED') renderSignedOut(notice('bad', 'The sign-in timed out. Please try again.'));
      return;
    }
    if (data.type !== 'MIQAAT_AUTH_SUCCESS') return;
    var keys = Object.keys(data).sort().join(',');
    if (keys !== 'core_assertion,state,transaction_id,type' || data.state !== pending.state || typeof data.core_assertion !== 'string' || !JWS.test(data.core_assertion)) return;

    var message = { transaction_id: data.transaction_id, state: data.state, core_assertion: data.core_assertion };
    pending = null; // single use
    api('POST', '/auth/core/callback', message).then(function (res) {
      if (res.status === 200) return load(notice('ok', 'Signed in. Both checks passed.'));
      var b = res.body;
      var text = b.error === 'ACCESS_DENIED'
        ? 'You are signed in to Miqaat, but you do not have access to this page (' + (b.reason || 'DENIED') + '). Ask an administrator for the "Login Page Viewer" role.'
        : 'Sign-in was rejected at the ' + (b.step || 'callback') + ' step: ' + (b.error || res.status) + (b.message ? ' (' + b.message + ')' : '');
      renderSignedOut(notice('bad', text), b);
    });
  });

  // ------------------------------------------------------------- signed in
  function renderSignedIn(me, message) {
    var refreshOut = el('p', { class: 'muted small', text: '' });
    root.replaceChildren(
      el('section', { class: 'block profile' }, [
        el('div', { class: 'profile-main' }, [
          el('h1', { text: 'Welcome, ' + me.its_id }),
          message || null,
          el('div', { class: 'kv' }, [
            el('span', { class: 'muted', text: 'ITS ID' }), el('code', { text: me.its_id }),
            el('span', { class: 'muted', text: 'Application' }), el('code', { text: me.client_id }),
            el('span', { class: 'muted', text: 'Federation session (sid)' }), el('code', { text: me.sid }),
            el('span', { class: 'muted', text: 'Page session ends' }), el('span', { text: new Date(me.expires_at).toLocaleString() }),
          ]),
        ]),
        el('div', { class: 'actions' }, [
          el('button', { class: 'btn', type: 'button', text: 'Check access again', onClick: function () {
            refreshOut.textContent = 'Asking Authorization…';
            api('POST', '/api/authorization/refresh').then(function (res) {
              if (res.status === 200) return load(notice('ok', 'Access checked again with a new signed authorization token.'));
              if (res.status === 403) return load();
              refreshOut.textContent = 'Could not refresh: ' + (res.body.error || res.status);
            });
          } }),
          el('button', { class: 'btn', type: 'button', text: 'Sign out of this page', onClick: function () {
            api('POST', '/auth/logout').then(function () { renderSignedOut(notice('ok', 'Signed out of this page. Your Miqaat session is still active, so signing in again needs no password.')); });
          } }),
          el('button', { class: 'btn btn-primary', type: 'button', text: 'Sign out everywhere', onClick: federatedLogout }),
          refreshOut,
        ]),
      ]),
      el('section', { class: 'block' }, [
        el('h2', { text: 'How you were verified' }),
        el('div', { class: 'results' }, [resultCard('authn', me.authentication), resultCard('authz', me.authorization, accessBlock(me.authorization))]),
      ]),
      keysSection(),
      adminSection(me),
    );
    startWatcher();
  }

  function federatedLogout() {
    api('POST', '/auth/logout/federated').then(function (res) {
      if (res.status !== 200) return load();
      var form = el('form', { method: 'POST', action: res.body.action });
      Object.keys(res.body.fields).forEach(function (k) { form.appendChild(el('input', { type: 'hidden', name: k, value: res.body.fields[k] })); });
      document.body.appendChild(form);
      form.submit();
    });
  }

  // ------------------------------------------------------- force logout
  function adminSection(me) {
    var out = el('pre', { class: 'admin-out', text: 'The result from Identity appears here.' });
    var token = el('textarea', { id: 'admin-token', rows: '3', autocomplete: 'off', spellcheck: 'false', placeholder: 'eyJhbGciOiJSUzI1NiIs…' });
    var its = el('input', { id: 'admin-its', inputmode: 'numeric', autocomplete: 'off', placeholder: 'e.g. 31267890' });
    var sid = el('input', { id: 'admin-sid', autocomplete: 'off', placeholder: 'sid_…' });
    var form = el('form', { class: 'admin-form', onSubmit: function (e) {
      e.preventDefault();
      out.textContent = 'Sending to Miqaat Identity…';
      api('POST', '/api/admin/force-logout', { admin_token: token.value, its_id: its.value, sid: sid.value }).then(function (res) {
        out.textContent = 'HTTP ' + res.status + '\n' + JSON.stringify(res.body, null, 2);
        token.value = '';
      });
    } }, [
      el('label', { for: 'admin-token', text: 'Administrator token' }),
      token,
      el('p', { class: 'hint', text: 'From POST /select-scope with "audience": "identity" in a CORE workspace that has USER_MGMT edit. It is sent once to Identity and not stored.' }),
      el('div', { class: 'row2' }, [
        el('div', {}, [el('label', { for: 'admin-its', text: 'ITS ID (every session of the user)' }), its]),
        el('div', {}, [el('label', { for: 'admin-sid', text: 'or one session (sid)' }), sid]),
      ]),
      el('div', { class: 'row' }, [
        me ? el('button', { class: 'btn', type: 'button', text: 'Use my sid', onClick: function () { sid.value = me.sid; its.value = ''; } }) : null,
        el('button', { class: 'btn btn-danger', type: 'submit', text: 'Force logout' }),
      ]),
    ]);
    return el('section', { class: 'block admin', 'aria-labelledby': 'admin-title' }, [
      el('h2', { id: 'admin-title', text: 'Administrator: force logout' }),
      el('p', { class: 'muted', text: 'Ends Miqaat sessions immediately. Identity revokes them and calls every application’s back-channel logout. If you target your own session, this page notices within a few seconds.' }),
      form,
      out,
    ]);
  }

  // ------------------------------------------------------ session watcher
  function startWatcher() {
    stopWatcher();
    watcher = setInterval(function () {
      api('GET', '/api/me').then(function (res) {
        if (res.status === 200) return;
        stopWatcher();
        renderSignedOut(notice('bad', res.body.ended ? res.body.ended.reason : 'Your session on this page has ended.'));
      });
    }, 5000);
  }
  function stopWatcher() { if (watcher) { clearInterval(watcher); watcher = null; } }

  // ------------------------------------------------------------- boot
  function load(message) {
    api('GET', '/api/me').then(function (res) {
      if (res.status === 200) return renderSignedIn(res.body, message);
      var p = params();
      if (!message && res.body.ended) message = notice('bad', res.body.ended.reason);
      if (!message && p.get('signed_out') === 'everywhere') message = notice('ok', 'You have been signed out of all Miqaat applications.');
      if (!message && p.get('error')) message = notice('bad', 'Sign-in failed: ' + p.get('error'));
      if (p.toString()) clearQuery();
      renderSignedOut(message);
    });
  }

  api('GET', '/api/config').then(function (res) {
    cfg = res.body;
    document.getElementById('meta').textContent = cfg.client_id + ' · ' + cfg.app_origin;
    load();
  });
})();
