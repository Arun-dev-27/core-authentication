/*
 * Reference BU frontend integration for Miqaat Core embedded login.
 * - validates event.origin, event.source, message type, transaction_id, state and schema
 * - forwards the assertion UNCHANGED to its own backend; never decodes or trusts claims
 * - never renders roles/permissions as a security decision (the backend enforces them)
 */
(function () {
  'use strict';
  var cfg = JSON.parse(document.getElementById('bu-boot').textContent);
  var root = document.getElementById('root');
  var pending = null; // { transaction_id, state, iframe }
  var JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') n.textContent = attrs[k];
      else if (k === 'onClick') n.addEventListener('click', attrs[k]);
      else n.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return n;
  }

  function post(path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { d.__status = r.status; return d; }); });
  }

  function params() { return new URLSearchParams(window.location.search); }

  // ------------------------------------------------------------ signed out
  function renderSignedOut(notice) {
    var loginPanel = el('section', { class: 'panel', 'aria-label': 'Sign in' });
    root.replaceChildren(el('div', { class: 'grid' }, [
      el('section', {}, [
        el('h1', { text: 'Welcome to ' + cfg.appName }),
        el('p', { class: 'muted', text: 'Sign in with your Miqaat account. The form on the right is served by Miqaat Core; this application never sees your password.' }),
        notice ? el('div', { class: 'alert ' + (notice.ok ? 'alert-ok' : 'alert-bad'), role: 'status', text: notice.text }) : null,
        el('ol', { class: 'steps' }, [
          el('li', { text: 'Core authenticates you and returns a signed, 60-second assertion.' }),
          el('li', { text: 'This app’s backend verifies it with Core’s JWKS and checks your permissions.' }),
          el('li', { text: 'A local ' + cfg.clientId.split('-')[0] + '_session is created for this app only.' }),
        ]),
        otherApps(),
      ]),
      loginPanel,
    ]));
    startEmbed(loginPanel, params().get('sso') === 'auto' ? 'auto' : undefined);
  }

  function otherApps() {
    if (!cfg.otherApps.length) return null;
    return el('p', { class: 'muted' }, ['Try SSO: ', ].concat(cfg.otherApps.map(function (a, i) {
      return el('span', {}, [i ? ' · ' : '', el('a', { href: a.url, text: a.name })]);
    })));
  }

  function startEmbed(container, prompt) {
    post('/auth/core/start', { display: 'embed', prompt: prompt }).then(function (start) {
      var iframe = el('iframe', {
        class: 'miqaat-login',
        title: 'Miqaat Core sign in',
        src: start.login_url,
        referrerpolicy: 'origin',
        allow: 'storage-access',
        sandbox: 'allow-scripts allow-forms allow-same-origin allow-storage-access-by-user-activation',
      });
      pending = { transaction_id: start.transaction_id, state: start.state, iframe: iframe };
      container.replaceChildren(iframe);
    });
  }

  function startTopLevel() {
    post('/auth/core/start', { display: 'page' }).then(function (start) { window.location.assign(start.login_url); });
  }

  window.addEventListener('message', function (event) {
    if (event.origin !== cfg.identityOrigin) return;                       // exact origin
    if (!pending || event.source !== pending.iframe.contentWindow) return; // from our iframe only
    var data = event.data;
    if (!data || typeof data !== 'object' || typeof data.type !== 'string') return;
    if (data.transaction_id !== pending.transaction_id) return;

    if (data.type === 'MIQAAT_AUTH_RESIZE' && typeof data.height === 'number') {
      pending.iframe.style.height = Math.min(Math.max(data.height, 320), 1200) + 'px';
      return;
    }
    if (data.type === 'MIQAAT_AUTH_TOP_LEVEL_REQUIRED') return startTopLevel();
    if (data.type === 'MIQAAT_AUTH_ERROR') {
      if (data.error === 'TRANSACTION_EXPIRED') renderSignedOut({ ok: false, text: 'Sign-in timed out. Please try again.' });
      return;
    }
    if (data.type !== 'MIQAAT_AUTH_SUCCESS') return;

    var keys = Object.keys(data).sort().join(',');
    if (keys !== 'core_assertion,state,transaction_id,type' || data.state !== pending.state || typeof data.core_assertion !== 'string' || !JWS.test(data.core_assertion)) {
      return; // schema/state mismatch: ignore
    }
    var message = { transaction_id: data.transaction_id, state: data.state, core_assertion: data.core_assertion };
    pending = null; // single use
    post('/auth/core/callback', message).then(function (res) {
      if (res.__status === 200) { window.history.replaceState(null, '', '/'); return load(); }
      renderSignedOut({ ok: false, text: 'Sign-in was rejected: ' + (res.error || res.__status) });
    });
  });

  // ------------------------------------------------------------- signed in
  function renderSignedIn(me) {
    var eff = me.effective || { roles: [], modules: [], permissions: [] };
    var result = el('pre', { text: 'Call a protected API to see server-side authorization.' });

    root.replaceChildren(el('div', { class: 'grid' }, [
      el('section', { class: 'panel' }, [
        el('h1', { text: cfg.appName }),
        el('div', { class: 'kv' }, [
          el('span', { class: 'muted', text: 'ITS ID' }), el('code', { text: me.its_id }),
          el('span', { class: 'muted', text: 'Client' }), el('code', { text: me.client_id }),
          el('span', { class: 'muted', text: 'Federation sid' }), el('code', { text: me.sid }),
          el('span', { class: 'muted', text: 'Roles' }), el('span', {}, eff.roles.length ? eff.roles.map(function (r) { return el('span', { class: 'pill', text: r.role_name }); }) : [el('span', { class: 'muted', text: 'none' })]),
          el('span', { class: 'muted', text: 'Permissions' }), el('span', {}, eff.permissions.map(function (p) { return el('span', { class: 'pill', text: p }); })),
        ]),
        el('h2', { class: 'section-title', text: 'Protected API: ' + cfg.module + ' module' }),
        el('div', { class: 'row' }, cfg.actions.map(function (action) {
          return el('button', { class: 'btn', text: action, onClick: function () {
            fetch('/api/demo/' + encodeURIComponent(action), { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (d) {
              result.textContent = JSON.stringify(d, null, 2);
            });
          } });
        })),
        result,
      ]),
      el('section', { class: 'panel' }, [
        el('h2', { text: 'Sessions' }),
        el('p', { class: 'muted', text: 'This app holds its own session. Miqaat Core holds the federation session shared by every app.' }),
        otherApps(),
        el('div', { class: 'row' }, [
          el('button', { class: 'btn', text: 'Sign out of ' + cfg.appName, onClick: function () { post('/auth/logout').then(function () { load({ ok: true, text: 'Signed out of ' + cfg.appName + ' only.' }); }); } }),
          el('button', { class: 'btn btn-primary', text: 'Sign out everywhere', onClick: federatedLogout }),
        ]),
      ]),
    ]));
  }

  function federatedLogout() {
    post('/auth/logout/federated').then(function (res) {
      var form = el('form', { method: 'POST', action: res.action });
      Object.keys(res.fields).forEach(function (k) { form.appendChild(el('input', { type: 'hidden', name: k, value: res.fields[k] })); });
      document.body.appendChild(form);
      form.submit();
    });
  }

  function load(notice) {
    fetch('/api/me', { credentials: 'same-origin' }).then(function (r) {
      if (r.status === 200) return r.json().then(renderSignedIn);
      var p = params();
      if (!notice && p.get('logged_out')) notice = { ok: true, text: 'You have been signed out of all Miqaat applications.' };
      if (!notice && p.get('error')) notice = { ok: false, text: 'Sign-in failed: ' + p.get('error') };
      renderSignedOut(notice);
    });
  }

  load();
})();
