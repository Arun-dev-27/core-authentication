/*
 * Miqaat Core embedded login UI.
 *
 * Runs on the Identity Federation origin only. Security properties:
 *  - credentials are posted same-origin; the parent application never sees them
 *  - the assertion is handed off with postMessage to ONE exact registered origin (never "*")
 *  - no inbound postMessage listener: the parent cannot drive or read this frame
 *  - no inline script (CSP script-src 'self'); DOM is built with textContent, never innerHTML
 */
(function () {
  'use strict';

  var bootEl = document.getElementById('miqaat-boot');
  var view = document.getElementById('view');
  if (!bootEl || !view) return;
  var boot = JSON.parse(bootEl.textContent || '{}');
  var app = boot.application;
  var appName = app ? app.name : 'Miqaat Core Portal';
  var workspaces = [];   // role x scope assignments of the signed-in user
  var workspace = null;  // active scope chosen with POST /portal/select-scope

  var MESSAGES = {
    INVALID_CREDENTIALS: 'The ITS ID or password you entered is incorrect.',
    TOO_MANY_ATTEMPTS: 'Too many sign-in attempts. Please wait a few minutes and try again.',
    ACCOUNT_UNAVAILABLE: 'This account cannot sign in right now. Please contact support.',
    CLIENT_NOT_ACTIVE: appName + ' is not currently enabled for sign-in.',
    CSRF_VALIDATION_FAILED: 'This page has expired. Please reload and try again.',
    DEPENDENCY_UNAVAILABLE: 'Sign-in is temporarily unavailable. Please try again shortly.',
    VALIDATION_ERROR: 'Please check the details you entered.',
    SCOPE_NOT_ASSIGNED: 'This workspace is no longer assigned to you.',
  };

  // ---------------------------------------------------------------- helpers
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      var value = attrs[key];
      if (value === false || value === null || value === undefined) return;
      if (key === 'text') node.textContent = value;
      else if (key === 'onClick') node.addEventListener('click', value);
      else if (key === 'onSubmit') node.addEventListener('submit', value);
      else node.setAttribute(key, value === true ? '' : String(value));
    });
    (children || []).forEach(function (child) {
      if (child) node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
  }

  function render(nodes, focusSelector) {
    view.replaceChildren.apply(view, nodes);
    var target = focusSelector ? view.querySelector(focusSelector) : null;
    if (target) target.focus();
    notifyResize();
  }

  function initials(name, fallback) {
    var source = (name || fallback || '?').trim();
    var parts = source.split(/\s+/).filter(Boolean);
    return ((parts[0] || '?')[0] + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
  }

  function api(path, body) {
    return fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json', 'x-csrf-token': boot.csrf },
      body: JSON.stringify(body),
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          // Login / select-scope errors: { success: false, error: { code, message } }; other endpoints: { error, message }.
          var detail = data.error && typeof data.error === 'object' ? data.error : { code: data.error, message: data.message };
          var error = new Error(detail.message || 'Request failed');
          error.code = detail.code || 'HTTP_' + res.status;
          error.status = res.status;
          throw error;
        }
        return data;
      });
    });
  }

  function getJson(path) {
    return fetch(path, { credentials: 'same-origin' }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) { var e = new Error(data.message || 'Request failed'); e.code = data.error || 'HTTP_' + res.status; throw e; }
        return data;
      });
    });
  }

  function messageFor(error) {
    return MESSAGES[error.code] || error.message || 'Something went wrong. Please try again.';
  }

  // ------------------------------------------------------ parent messaging
  var embedded = boot.mode === 'embed';

  function postToParent(message) {
    if (!embedded || !boot.target_origin || window.parent === window) return;
    // Exact registered origin chosen by the server for this transaction. Never "*".
    window.parent.postMessage(message, boot.target_origin);
  }

  function notifyResize() {
    postToParent({ type: 'MIQAAT_AUTH_RESIZE', transaction_id: boot.transaction_id, height: Math.ceil(document.documentElement.scrollHeight) });
  }

  if (embedded && typeof ResizeObserver === 'function') {
    new ResizeObserver(notifyResize).observe(document.body);
  }

  function deliver(result) {
    // Login envelope: session.token is the core_assertion, session.delivery says how to hand it over.
    if (result && result.session && result.session.delivery) {
      var s = result.session;
      result = {
        type: s.delivery.type, transaction_id: s.delivery.transaction_id, state: s.delivery.state, core_assertion: s.token,
        delivery: s.delivery.delivery, target_origin: s.delivery.target_origin, callback_uri: s.delivery.callback_uri,
      };
    }
    if (!result || result.type !== 'MIQAAT_AUTH_SUCCESS' || typeof result.core_assertion !== 'string') {
      return showError('Unexpected response from the sign-in service.');
    }
    if (result.delivery === 'post_message') {
      if (result.target_origin !== boot.target_origin || window.parent === window) {
        return showError('This sign-in page must be opened from ' + appName + '.');
      }
      showSuccess();
      window.parent.postMessage(
        { type: 'MIQAAT_AUTH_SUCCESS', transaction_id: result.transaction_id, state: result.state, core_assertion: result.core_assertion },
        boot.target_origin,
      );
      return;
    }
    if (result.delivery === 'form_post' && result.callback_uri === boot.callback_uri) {
      showSuccess();
      var form = el('form', { method: 'POST', action: result.callback_uri, hidden: true });
      [['transaction_id', result.transaction_id], ['state', result.state], ['core_assertion', result.core_assertion]].forEach(function (pair) {
        form.appendChild(el('input', { type: 'hidden', name: pair[0], value: pair[1] }));
      });
      document.body.appendChild(form);
      form.submit();
      return;
    }
    showError('Unexpected response from the sign-in service.');
  }

  // ----------------------------------------------------------------- views
  function heading(title, lede) {
    return [el('h1', { id: 'title', text: title }), lede ? el('p', { class: 'lede', text: lede }) : null];
  }

  function showSignIn(errorText) {
    var errorBox = el('div', { class: 'alert alert-error', role: 'alert', id: 'form-error', hidden: !errorText, text: errorText || '' });

    // ITS members only: the sign-in page offers ITS ID + password.
    var idInput = el('input', {
      class: 'input', id: 'identifier', name: 'its_id',
      type: 'text', inputmode: 'numeric',
      autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true,
      maxlength: 64, 'aria-describedby': 'form-error', 'aria-invalid': errorText ? 'true' : 'false',
    });
    var pwInput = el('input', {
      class: 'input has-toggle', id: 'password', name: 'password', type: 'password',
      autocomplete: 'current-password', required: true, maxlength: 256,
      'aria-describedby': 'form-error', 'aria-invalid': errorText ? 'true' : 'false',
    });
    var toggle = el('button', {
      type: 'button', class: 'toggle', 'aria-controls': 'password', 'aria-pressed': 'false', text: 'Show',
      onClick: function () {
        var reveal = pwInput.type === 'password';
        pwInput.type = reveal ? 'text' : 'password';
        toggle.textContent = reveal ? 'Hide' : 'Show';
        toggle.setAttribute('aria-pressed', String(reveal));
        pwInput.focus();
      },
    });
    var submit = el('button', { type: 'submit', class: 'btn btn-primary', text: 'Sign in' });

    var form = el('form', { novalidate: true, onSubmit: function (event) {
      event.preventDefault();
      var itsId = idInput.value.trim();
      if (!itsId || !pwInput.value) {
        errorBox.textContent = 'Enter your ITS ID and password.';
        errorBox.hidden = false;
        (itsId ? pwInput : idInput).focus();
        return notifyResize();
      }
      submit.disabled = true;
      submit.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), document.createTextNode('Signing in…'));
      var body = { transaction_id: boot.transaction_id, identity_type: 'ITS', its_id: itsId, password: pwInput.value };
      if (boot.mode !== 'portal') body.client_id = boot.client_id;

      api(boot.mode === 'portal' ? '/portal/login' : '/embed/login', body)
        .then(function (result) {
          pwInput.value = '';
          if (boot.mode === 'portal') {
            var s = result.session;
            if (s) {
              boot.session = { its_id: s.user.its_id, display_name: s.user.name };
              workspaces = (s.roles || []).map(toWorkspace);
              workspace = toWorkspace(s.active_role);
            } else {
              boot.session = { its_id: result.its_id, display_name: result.name };
              workspaces = result.assignments || [];
              workspace = result.active_scope || null;
            }
            return workspace || workspaces.length < 2 ? showApplications() : showWorkspaces();
          }
          deliver(result);
        })
        .catch(function (error) {
          pwInput.value = '';
          if (error.code === 'TRANSACTION_INVALID' || error.code === 'TRANSACTION_ALREADY_USED') return showExpired();
          showSignIn(messageFor(error));
        });
    } }, [
      errorBox,
      el('div', { class: 'field' }, [el('label', { for: 'identifier', text: 'ITS ID' }), idInput]),
      el('div', { class: 'field' }, [
        el('label', { for: 'password', text: 'Password' }),
        el('div', { class: 'input-wrap' }, [pwInput, toggle]),
      ]),
      submit,
    ]);

    render([].concat(
      heading('Sign in with your ITS ID', 'Use one Miqaat account for every application.'),
      [form],
      storageHint(),
    ), errorText ? '#identifier' : null);
  }

  function storageHint() {
    if (!embedded) return [];
    var hint = el('p', { class: 'muted', hidden: true }, [
      'Trouble signing in inside ' + appName + '? ',
      el('button', { type: 'button', class: 'btn btn-link', text: 'Continue in a full window', onClick: function () {
        postToParent({ type: 'MIQAAT_AUTH_TOP_LEVEL_REQUIRED', transaction_id: boot.transaction_id, state: boot.state, reason: 'STORAGE_ACCESS_UNAVAILABLE' });
      } }),
    ]);
    if (document.hasStorageAccess) {
      document.hasStorageAccess().then(function (granted) { if (!granted) { hint.hidden = false; notifyResize(); } }).catch(function () {});
    }
    return [hint];
  }

  function identityCard(session) {
    return el('div', { class: 'identity' }, [
      el('div', { class: 'avatar', 'aria-hidden': 'true', text: initials(session.display_name, session.its_id) }),
      el('div', {}, [
        el('p', { class: 'identity-name', text: session.display_name || 'Miqaat member' }),
        el('p', { class: 'identity-id', text: 'ITS ' + session.its_id }),
      ]),
    ]);
  }

  function showContinue(errorText) {
    var session = boot.session;
    var btn = el('button', { type: 'button', class: 'btn btn-primary', id: 'continue', text: 'Continue to ' + appName });
    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), document.createTextNode('Continuing…'));
      api('/embed/continue', { transaction_id: boot.transaction_id, client_id: boot.client_id })
        .then(deliver)
        .catch(function (error) {
          if (error.code === 'SESSION_REQUIRED') { boot.session = null; return showSignIn('Your session has ended. Please sign in again.'); }
          if (error.code === 'TRANSACTION_INVALID' || error.code === 'TRANSACTION_ALREADY_USED') return showExpired();
          showContinue(messageFor(error));
        });
    });
    render([].concat(
      heading('Welcome back', 'You are already signed in to Miqaat Core.'),
      [
        errorText ? el('div', { class: 'alert alert-error', role: 'alert', text: errorText }) : null,
        identityCard(session),
        btn,
        el('button', { type: 'button', class: 'btn btn-secondary', text: 'Use a different account', onClick: switchAccount }),
      ],
    ), '#continue');
    if (boot.auto_continue && !errorText) { boot.auto_continue = false; btn.click(); }
  }

  function switchAccount() {
    workspaces = [];
    workspace = null;
    var path = boot.mode === 'portal' ? '/portal/logout' : '/embed/logout';
    api(path, { transaction_id: boot.transaction_id }).catch(function () {}).then(function () {
      boot.session = null;
      showSignIn();
    });
  }

  function showSuccess() {
    render([el('div', { class: 'state state-success', role: 'status' }, [
      el('div', { class: 'state-icon', 'aria-hidden': 'true', text: '✓' }),
      el('h1', { text: 'Signed in' }),
      el('p', { class: 'lede', text: 'Returning you to ' + appName + '…' }),
      el('div', { class: 'spinner', 'aria-hidden': 'true' }),
    ])]);
  }

  function showExpired() {
    postToParent({ type: 'MIQAAT_AUTH_ERROR', transaction_id: boot.transaction_id, state: boot.state, error: 'TRANSACTION_EXPIRED' });
    render([el('div', { class: 'state state-expired', role: 'alert' }, [
      el('div', { class: 'state-icon', 'aria-hidden': 'true', text: '!' }),
      el('h1', { text: 'Session expired' }),
      el('p', { class: 'lede', text: 'This sign-in request is no longer valid. Please start again from ' + appName + '.' }),
      boot.mode === 'portal' ? el('button', { type: 'button', class: 'btn btn-primary', text: 'Start again', onClick: function () { window.location.reload(); } }) : null,
    ])]);
  }

  function showError(text) {
    postToParent({ type: 'MIQAAT_AUTH_ERROR', transaction_id: boot.transaction_id, state: boot.state, error: 'LOGIN_FAILED' });
    render([el('div', { class: 'state state-error', role: 'alert' }, [
      el('div', { class: 'state-icon', 'aria-hidden': 'true', text: '!' }),
      el('h1', { text: 'Unable to sign in' }),
      el('p', { class: 'lede', text: text }),
    ])]);
  }

  // ------------------------------------------- portal: workspace selection
  function scopeLabel(ws) {
    if (ws.scope_type === 'CORE') return 'Core' + (ws.scope_name ? ' · ' + ws.scope_name : '');
    return (ws.scope_type === 'BUSINESS_UNIT' ? 'Business unit' : 'Utility') + ' · ' + (ws.scope_name || ws.scope_id);
  }

  // A login-envelope role { role_id, role_name, scope_type, scope_id, tenant_name } in the workspace shape used by this page.
  function toWorkspace(role) {
    if (!role) return null;
    return { role_id: role.role_id, role_name: role.role_name, scope_type: role.scope_type, scope_id: role.scope_id, scope_name: role.scope_type === 'CORE' ? null : role.tenant_name };
  }

  function sameWorkspace(a, b) {
    return Boolean(a && b) && a.role_id === b.role_id && a.scope_type === b.scope_type && (a.scope_id || null) === (b.scope_id || null);
  }

  function startPortal() {
    render([el('div', { class: 'spinner', role: 'status' }, [el('span', { class: 'sr-only', text: 'Loading your workspaces…' })])]);
    getJson('/portal/assignments')
      .then(function (data) {
        boot.session = { its_id: data.its_id, display_name: data.name };
        workspaces = data.assignments || [];
        if (workspaces.length === 1) return selectWorkspace(workspaces[0]);
        return workspaces.length ? showWorkspaces() : showApplications();
      })
      .catch(function (error) {
        if (error.code === 'SESSION_REQUIRED') { boot.session = null; return showSignIn(); }
        showError(messageFor(error));
      });
  }

  function selectWorkspace(ws, button) {
    if (button) {
      button.disabled = true;
      button.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), document.createTextNode('Opening workspace…'));
    }
    return api('/portal/select-scope', { transaction_id: boot.transaction_id, role_id: ws.role_id, scope_type: ws.scope_type, scope_id: ws.scope_id })
      .then(function (result) { workspace = result.session ? toWorkspace(result.session.active_role) : result.active_scope; showApplications(); })
      .catch(function (error) {
        if (error.code === 'SESSION_REQUIRED') { boot.session = null; document.getElementById('app').classList.remove('is-portal-apps'); return showSignIn('Your session has ended. Please sign in again.'); }
        if (error.code === 'CSRF_VALIDATION_FAILED') return showExpired();
        showWorkspaces(messageFor(error));
      });
  }

  function showWorkspaces(errorText) {
    document.getElementById('app').classList.add('is-portal-apps');
    var selected = null;
    var continueBtn = el('button', { type: 'button', class: 'btn btn-primary', id: 'select-workspace', disabled: true, text: 'Continue' });
    var list = el('div', { class: 'apps', role: 'radiogroup', 'aria-label': 'Workspaces' }, workspaces.map(function (ws, index) {
      var id = 'workspace-' + index;
      var current = sameWorkspace(ws, workspace);
      var input = el('input', { type: 'radio', name: 'workspace', id: id, value: String(index), checked: current });
      if (current) { selected = ws; continueBtn.disabled = false; }
      input.addEventListener('change', function () { selected = ws; continueBtn.disabled = false; });
      var badge = ws.scope_type === 'CORE' ? 'CORE' : ws.scope_type === 'BUSINESS_UNIT' ? 'BU' : 'UTIL';
      return el('label', { class: 'app-option', for: id }, [
        input,
        el('span', { class: 'app-card' }, [
          el('span', { class: 'app-badge', 'aria-hidden': 'true', text: badge }),
          el('span', {}, [el('p', { class: 'app-name', text: ws.role_name }), el('p', { class: 'app-roles', text: scopeLabel(ws) })]),
          el('span', { class: 'app-check', 'aria-hidden': 'true' }),
        ]),
      ]);
    }));
    continueBtn.addEventListener('click', function () { if (selected) selectWorkspace(selected, continueBtn); });
    render([].concat(
      heading('Select workspace', 'You have ' + workspaces.length + ' roles. Choose where you want to work; you can switch at any time.'),
      [
        errorText ? el('div', { class: 'alert alert-error', role: 'alert', text: errorText }) : null,
        identityCard(boot.session),
        list,
        continueBtn,
        el('div', { class: 'row-between' }, [el('button', { type: 'button', class: 'btn btn-link', text: '← Back to sign in', onClick: switchAccount })]),
      ],
    ), 'input[name="workspace"]');
  }

  // ------------------------------------------------- portal: app selection
  function showApplications() {
    document.getElementById('app').classList.add('is-portal-apps');
    render([el('div', { class: 'spinner', role: 'status' }, [el('span', { class: 'sr-only', text: 'Loading your applications…' })])]);
    fetch('/portal/applications', { credentials: 'same-origin' })
      .then(function (res) {
        return res.json().then(function (data) { if (!res.ok) { var e = new Error(data.message); e.code = data.error; throw e; } return data; });
      })
      .then(function (data) {
        var apps = data.applications || [];
        var selected = null;
        var continueBtn = el('button', { type: 'button', class: 'btn btn-primary', id: 'launch', disabled: true, text: 'Continue' });

        var list = el('div', { class: 'apps', role: 'radiogroup', 'aria-label': 'Applications' }, apps.map(function (item, index) {
          var id = 'app-' + index;
          var roles = (item.roles || []).map(function (r) { return r.name || r.role_name; }).join(', ') || 'No roles assigned';
          var owner = item.business_unit || item.utility || '';
          var input = el('input', { type: 'radio', name: 'application', id: id, value: item.application_code, disabled: !item.launchable });
          input.addEventListener('change', function () { selected = item; continueBtn.disabled = false; });
          return el('label', { class: 'app-option', for: id }, [
            input,
            el('span', { class: 'app-card' }, [
              el('span', { class: 'app-badge', 'aria-hidden': 'true', text: (owner || item.application_code).slice(0, 4).toUpperCase() }),
              el('span', {}, [
                el('p', { class: 'app-name', text: item.application_name }),
                el('p', { class: 'app-roles', text: (owner ? owner + ' · ' : '') + roles + (item.launchable ? '' : ' · not available in ' + data.environment) }),
              ]),
              el('span', { class: 'app-check', 'aria-hidden': 'true' }),
            ]),
          ]);
        }));

        continueBtn.addEventListener('click', function () {
          if (!selected || !selected.initiate_login_uri) return;
          var target;
          try { target = new URL(selected.initiate_login_uri); } catch (e) { return; }
          if (target.protocol !== 'https:' && target.protocol !== 'http:') return;
          continueBtn.disabled = true;
          continueBtn.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), document.createTextNode('Opening ' + selected.application_name + '…'));
          window.location.assign(target.toString());
        });

        render([].concat(
          heading('Choose an application', apps.length ? 'You have access to ' + apps.length + ' application' + (apps.length === 1 ? '' : 's') + '.' : 'No applications are assigned to your account yet.'),
          [
            identityCard({ its_id: data.its_id, display_name: data.display_name }),
            workspace ? el('div', { class: 'row-between', id: 'active-workspace' }, [
              el('p', { class: 'app-roles', text: 'Workspace: ' + workspace.role_name + ' · ' + scopeLabel(workspace) }),
              workspaces.length > 1 ? el('button', { type: 'button', class: 'btn btn-link', text: 'Switch workspace', onClick: function () { showWorkspaces(); } }) : null,
            ]) : null,
            list,
            apps.length ? continueBtn : null,
            el('div', { class: 'row-between' }, [
              el('button', { type: 'button', class: 'btn btn-link', text: '← Back to sign in', onClick: switchAccount }),
              el('button', { type: 'button', class: 'btn btn-link', text: 'Sign out everywhere', onClick: function () {
                api('/portal/logout', { transaction_id: boot.transaction_id, scope: 'federation' }).catch(function () {}).then(function () { window.location.reload(); });
              } }),
            ]),
          ],
        ), apps.length ? 'input[name="application"]:not([disabled])' : null);
      })
      .catch(function (error) {
        if (error.code === 'SESSION_REQUIRED') { boot.session = null; document.getElementById('app').classList.remove('is-portal-apps'); return showSignIn('Your session has ended. Please sign in again.'); }
        showError(messageFor(error));
      });
  }

  // ------------------------------------------------------------------ start
  if (embedded && window.parent === window) {
    return showError('This sign-in page must be opened from inside ' + appName + '.');
  }
  if (boot.mode === 'portal') return boot.session ? startPortal() : showSignIn();
  return boot.session ? showContinue() : showSignIn();
})();
