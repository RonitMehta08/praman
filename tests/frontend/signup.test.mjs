/** Exercise the real login/signup modal and API transport in a browser DOM.
 * Run with: NODE_PATH=<jsdom node_modules> node --test tests/frontend/signup.test.mjs
 */
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';

const { JSDOM } = createRequire(import.meta.url)('jsdom');
const dom = new JSDOM('<main id="app"><div id="view-outlet" tabindex="-1"></div></main>', {
  url: 'https://praman.example/',
});
for (const name of ['window', 'document', 'Node', 'CustomEvent']) {
  globalThis[name] = dom.window[name];
}

const { identity, requireIdentity, signOut } = await import('../../frontend/js/auth.js');
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const response = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { 'Content-Type': 'application/json' },
});
const permissions = (username, role) => ({
  username, role, may_ingest: role !== 'viewer', may_commit: role === 'approver',
});

test('signup selects a role, validates inputs, handles duplicates, and adopts a real session', async () => {
  let signupEnabled = true;
  let duplicate = false;
  let current = null;
  const calls = [];
  globalThis.fetch = async (path, options) => {
    calls.push({ path, options });
    if (path === '/auth/options') return response({
      signup_enabled: signupEnabled,
      roles: signupEnabled ? ['viewer', 'auditor', 'approver'] : [],
      min_password_length: 12,
    });
    if (path === '/auth/signup' || path === '/auth/login') {
      const payload = JSON.parse(options.body);
      if (duplicate && path === '/auth/signup') {
        return response({ detail: "operator 'judge.test' already exists" }, 409);
      }
      current = permissions(payload.username, payload.role || 'viewer');
      return response({ ...current, token: 'test-session', expires_at: '2099-01-01' },
        path === '/auth/signup' ? 201 : 200);
    }
    if (path === '/auth/whoami') {
      assert.equal(options.headers.get('Authorization'), 'Bearer test-session');
      return response(current);
    }
    if (path === '/auth/logout') return response({ status: 'ok', revoked: true });
    throw new Error(`Unexpected request: ${path}`);
  };

  const gate = requireIdentity();
  await tick();
  const toggle = document.querySelector('.auth-toggle');
  assert.equal(toggle.hidden, false);
  assert.equal(document.querySelector('#auth-role').closest('label').hidden, true);
  toggle.click();
  const role = document.querySelector('#auth-role');
  assert.equal(role.closest('label').hidden, false);
  assert.equal(role.value, 'approver');
  assert.equal(document.querySelector('#auth-password').autocomplete, 'new-password');
  const user = document.querySelector('#auth-username');
  const pass = document.querySelector('#auth-password');
  const submit = () => document.querySelector('.auth-form').dispatchEvent(
    new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  user.value = 'judge.test';
  pass.value = 'short';
  submit();
  await tick();
  assert.match(document.querySelector('.auth-status').textContent, /at least 12/);
  assert.equal(calls.filter((call) => call.path === '/auth/signup').length, 0);

  duplicate = true;
  pass.value = 'judge-demo-passphrase';
  submit();
  await tick();
  assert.match(document.querySelector('.auth-status').textContent, /already exists/);
  assert.equal(document.querySelector('.auth-submit').disabled, false);
  assert.equal(document.querySelector('.auth-submit').textContent, 'Create account');
  assert.equal(document.querySelector('.auth-toggle').disabled, false);
  assert.equal(role.disabled, false);
  assert.equal(identity(), null);
  assert.equal(window.sessionStorage.getItem('praman.session.token'), null);

  duplicate = false;
  role.value = 'auditor';
  pass.value = 'judge-demo-passphrase';
  submit();
  assert.equal(await gate, true);
  assert.equal(identity().role, 'auditor');
  assert.equal(identity().may_commit, false);
  assert.equal(window.sessionStorage.getItem('praman.session.token'), 'test-session');
  assert.equal(document.querySelector('.auth-overlay'), null);
  assert.equal(document.getElementById('app').inert, false);
  const registered = calls.filter((call) => call.path === '/auth/signup').at(-1);
  assert.deepEqual(JSON.parse(registered.options.body), {
    username: 'judge.test', role: 'auditor', password: 'judge-demo-passphrase',
  });

  // Deployment policy also controls the frontend, while ordinary login works.
  signupEnabled = false;
  await signOut();
  await tick();
  assert.equal(document.querySelector('.auth-toggle').hidden, true);
  assert.match(document.querySelector('.auth-foot').textContent, /disabled/);
  const loginGate = requireIdentity();
  document.querySelector('#auth-username').value = 'existing.viewer';
  document.querySelector('#auth-password').value = 'viewer-passphrase';
  submit();
  assert.equal(await loginGate, true);
  assert.equal(identity().role, 'viewer');
});
