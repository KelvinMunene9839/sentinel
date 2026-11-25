const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../../src/app');
const { initDb } = require('../../src/database/db');
const { runMigrations } = require('../../src/database/migrate');

let server = null;
let baseUrl = '';

test('Integration & Security Tests — SENTINEL REST API', async (t) => {
  await initDb();
  await runMigrations();

  server = app.listen(0);
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;

  t.after(() => {
    if (server) server.close();
  });

  let sessionCookie = '';
  let csrfToken = '';

  await t.test('System health, readiness, version, and provider status endpoints return 200', async () => {
    const healthRes = await fetch(`${baseUrl}/api/v1/health`);
    assert.equal(healthRes.status, 200);
    assert.equal(healthRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(healthRes.headers.get('x-frame-options'), 'DENY');
    assert.ok(healthRes.headers.get('x-sentinel-server'));

    const readyRes = await fetch(`${baseUrl}/api/v1/ready`);
    assert.equal(readyRes.status, 200);
    const readyData = await readyRes.json();
    assert.equal(readyData.status, 'ready');
    assert.equal(readyData.checks.database.healthy, true);

    const verRes = await fetch(`${baseUrl}/api/v1/version`);
    assert.equal(verRes.status, 200);

    const provRes = await fetch(`${baseUrl}/api/v1/providers/status`);
    assert.equal(provRes.status, 200);
    const provData = await provRes.json();
    assert.equal(provData.providers.length, 4);
  });

  await t.test('Authentication rejects invalid credentials and issues HttpOnly cookie + CSRF token on valid login', async () => {
    const badRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'WrongPassword' }),
    });
    assert.equal(badRes.status, 401);

    const goodRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'AdminPassword123!' }),
    });
    assert.equal(goodRes.status, 200);

    const setCookieHeader = goodRes.headers.get('set-cookie') || '';
    assert.ok(setCookieHeader.includes('HttpOnly'));
    assert.ok(setCookieHeader.includes('SameSite=Strict'));
    sessionCookie = setCookieHeader.split(';')[0];

    const body = await goodRes.json();
    assert.equal(body.status, 'authenticated');
    assert.equal(body.user.role, 'Administrator');
    assert.ok(body.csrfToken);
    csrfToken = body.csrfToken;
  });

  await t.test('CSRF protection blocks state-changing requests missing X-CSRF-Token', async () => {
    const noCsrfRes = await fetch(`${baseUrl}/api/v1/scans/authorized-domains`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: sessionCookie,
      },
      body: JSON.stringify({ domain: 'mozilla.org' }),
    });
    assert.equal(noCsrfRes.status, 403);
    const errBody = await noCsrfRes.json();
    assert.equal(errBody.error, 'CSRFValidationFailed');
  });

  await t.test('Role-Based Access Control blocks Read-only Auditor from launching scans', async () => {
    const audLogin = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'auditor', password: 'AuditorPassword123!' }),
    });
    const audCookie = (audLogin.headers.get('set-cookie') || '').split(';')[0];
    const audBody = await audLogin.json();

    const scanRes = await fetch(`${baseUrl}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: audCookie,
        'X-CSRF-Token': audBody.csrfToken,
      },
      body: JSON.stringify({ domain: 'example.com', authorizationConfirmed: true }),
    });
    assert.equal(scanRes.status, 403);
  });

  await t.test('Authorized domain scope enforcement blocks out-of-scope domains', async () => {
    const outOfScopeRes = await fetch(`${baseUrl}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: sessionCookie,
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        domain: 'unapproved-domain.org',
        authorizationConfirmed: true,
      }),
    });
    assert.equal(outOfScopeRes.status, 403);
    const body = await outOfScopeRes.json();
    assert.equal(body.error, 'OutOfScopeDomain');
  });

  await t.test('SQL injection payloads in search parameters are safely handled via parameterized queries', async () => {
    const sqliSearch = encodeURIComponent("' OR 1=1; DROP TABLE assets; --");
    const res = await fetch(`${baseUrl}/api/v1/assets?search=${sqliSearch}`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.assets));
  });
});
