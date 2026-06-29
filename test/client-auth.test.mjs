// test/client-auth.test.mjs — hermetic unit tests for the zero-dep publisher credential
// store + device-code login/refresh/logout client (src/client/auth.mjs). No real OS keychain,
// no network: fetch + clock are injected, the token file lives under a mkdtemp dir.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, statSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  saveToken, loadToken, clearToken, decodeJwtExp,
  getValidAccessToken, login, logout, authStatus,
} from '../src/client/auth.mjs';

const tmp = () => path.join(mkdtempSync(path.join(os.tmpdir(), 'lumaline-auth-')), 'device-token.json');

// Build a syntactically valid (unsigned-content) JWT carrying a given exp (seconds).
function fakeJwt(expSec, extra = {}) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ exp: expSec, ...extra })}.sig`;
}
const tokenObj = (expSec) => ({
  access_token: fakeJwt(expSec, { publisher_id: 'p1', device_id: 'd1' }),
  refresh_token: 'refresh-abc',
  publisher_id: 'p1', device_id: 'd1', handle: 'dev-a', exp: expSec,
});

test('saveToken writes a 0600 file that loadToken round-trips', () => {
  const f = tmp();
  const obj = tokenObj(2_000_000_000);
  saveToken(f, obj);
  assert.ok(existsSync(f));
  assert.equal(statSync(f).mode & 0o777, 0o600, 'token file is owner-only (0600)');
  assert.deepEqual(loadToken(f), obj);
});

test('loadToken returns null for a missing or garbage file', () => {
  assert.equal(loadToken(tmp()), null);
});

test('clearToken removes the file (and is a no-op when already absent)', () => {
  const f = tmp();
  saveToken(f, tokenObj(2_000_000_000));
  clearToken(f);
  assert.equal(existsSync(f), false);
  clearToken(f); // no throw on absent
});

test('decodeJwtExp reads exp; returns null on garbage', () => {
  assert.equal(decodeJwtExp(fakeJwt(1234567890)), 1234567890);
  assert.equal(decodeJwtExp('not.a.jwt'), null);
  assert.equal(decodeJwtExp(''), null);
});

test('getValidAccessToken: null when no token stored (fast anonymous path, no fetch)', async () => {
  let fetched = false;
  const tok = await getValidAccessToken({ file: tmp(), now: 1000, fetchImpl: async () => { fetched = true; } });
  assert.equal(tok, null);
  assert.equal(fetched, false);
});

test('getValidAccessToken: returns the access token unchanged when far from expiry (no refresh)', async () => {
  const f = tmp();
  const nowS = 1_700_000_000;
  const obj = tokenObj(nowS + 3600);
  saveToken(f, obj);
  let fetched = false;
  const tok = await getValidAccessToken({
    file: f, now: nowS * 1000, skewMs: 300_000, fetchImpl: async () => { fetched = true; },
  });
  assert.equal(tok, obj.access_token);
  assert.equal(fetched, false, 'no network call when the token is fresh');
});

test('getValidAccessToken: refreshes (and rotates) when within the skew window', async () => {
  const f = tmp();
  const nowS = 1_700_000_000;
  saveToken(f, tokenObj(nowS + 60)); // expires in 60s, inside the 300s skew
  const newAccess = fakeJwt(nowS + 3600, { publisher_id: 'p1', device_id: 'd1' });
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return { ok: true, status: 200, json: async () => ({
      access_token: newAccess, refresh_token: 'refresh-NEW', expires_in: 3600,
      publisher_id: 'p1', device_id: 'd1', handle: 'dev-a',
    }) };
  };
  const tok = await getValidAccessToken({ file: f, now: nowS * 1000, skewMs: 300_000, authBase: 'https://x/auth-device', fetchImpl });
  assert.equal(tok, newAccess, 'returns the freshly minted access token');
  assert.match(calls[0].url, /\/device\/refresh$/);
  assert.equal(calls[0].body.refresh_token, 'refresh-abc', 'sends the OLD refresh token');
  const saved = loadToken(f);
  assert.equal(saved.access_token, newAccess);
  assert.equal(saved.refresh_token, 'refresh-NEW', 'rotated refresh token persisted');
});

test('getValidAccessToken: returns null (never throws) when refresh fails', async () => {
  const f = tmp();
  const nowS = 1_700_000_000;
  saveToken(f, tokenObj(nowS + 60));
  const tok = await getValidAccessToken({
    file: f, now: nowS * 1000, skewMs: 300_000, authBase: 'https://x/auth-device',
    fetchImpl: async () => { throw new Error('network down'); },
  });
  assert.equal(tok, null, 'degrades to anonymous instead of throwing on the hot path');
});

test('login: device-code flow polls until approved, then persists the token', async () => {
  const f = tmp();
  const printed = [];
  let tokenCalls = 0;
  const fetchImpl = async (url, opts) => {
    if (url.endsWith('/device/code')) {
      return { ok: true, status: 200, json: async () => ({
        device_code: 'DC', user_code: 'ABCD-EFGH',
        verification_uri: 'https://x/activate', verification_uri_complete: 'https://x/activate?user_code=ABCD-EFGH',
        expires_in: 600, interval: 0,
      }) };
    }
    if (url.endsWith('/device/token')) {
      tokenCalls++;
      if (tokenCalls < 2) return { ok: false, status: 400, json: async () => ({ error: 'authorization_pending' }) };
      return { ok: true, status: 200, json: async () => ({
        access_token: fakeJwt(2_000_000_000, { publisher_id: 'pX' }), refresh_token: 'R',
        expires_in: 3600, publisher_id: 'pX', device_id: 'dX', handle: 'dev-x',
      }) };
    }
    throw new Error('unexpected url ' + url);
  };
  const res = await login({
    file: f, authBase: 'https://x/auth-device', fetchImpl, sleep: async () => {},
    out: (s) => printed.push(s), now: 1000, label: 'my-box',
  });
  assert.equal(res.handle, 'dev-x');
  assert.ok(printed.join('\n').includes('ABCD-EFGH'), 'shows the user_code');
  assert.ok(printed.join('\n').includes('https://x/activate'), 'shows the verification URL');
  assert.ok(printed.join('\n').includes('my-box'), 'discloses the device label that will be uploaded');
  const saved = loadToken(f);
  assert.equal(saved.publisher_id, 'pX');
  assert.equal(saved.refresh_token, 'R');
  assert.ok(tokenCalls >= 2, 'polled at least twice (pending then approved)');
});

test('login: surfaces access_denied / expired without persisting a token', async () => {
  const f = tmp();
  const fetchImpl = async (url) => {
    if (url.endsWith('/device/code')) return { ok: true, status: 200, json: async () => ({ device_code: 'DC', user_code: 'U', verification_uri: 'https://x/a', interval: 0, expires_in: 600 }) };
    return { ok: false, status: 400, json: async () => ({ error: 'access_denied' }) };
  };
  await assert.rejects(
    () => login({ file: f, authBase: 'https://x/auth-device', fetchImpl, sleep: async () => {}, out: () => {}, now: 1000 }),
    /access_denied|denied/,
  );
  assert.equal(loadToken(f), null, 'no token persisted on denial');
});

test('logout: clears the stored token (and attempts a best-effort server revoke)', async () => {
  const f = tmp();
  saveToken(f, tokenObj(2_000_000_000));
  let revoked = false;
  await logout({ file: f, authBase: 'https://x/auth-device', out: () => {}, fetchImpl: async (url) => {
    if (url.endsWith('/device/logout')) { revoked = true; return { ok: true, status: 200, json: async () => ({ ok: true }) }; }
    return { ok: true, status: 200, json: async () => ({}) };
  } });
  assert.equal(loadToken(f), null, 'local token cleared');
  assert.equal(revoked, true, 'server revoke attempted');
});

test('logout: still clears locally even if the server revoke call fails', async () => {
  const f = tmp();
  saveToken(f, tokenObj(2_000_000_000));
  await logout({ file: f, authBase: 'https://x/auth-device', out: () => {}, fetchImpl: async () => { throw new Error('offline'); } });
  assert.equal(loadToken(f), null);
});

test('authStatus reflects logged-in identity and logged-out state', () => {
  const f = tmp();
  assert.equal(authStatus({ file: f, now: 1000 }).loggedIn, false);
  const nowS = 1_700_000_000;
  saveToken(f, tokenObj(nowS + 3600));
  const s = authStatus({ file: f, now: nowS * 1000 });
  assert.equal(s.loggedIn, true);
  assert.equal(s.handle, 'dev-a');
  assert.equal(s.publisherId, 'p1');
  assert.ok(s.expiresInS > 0 && s.expiresInS <= 3600);
});
