// test/client-auth.test.mjs — hermetic unit tests for the zero-dep publisher credential
// store + device-code login/refresh/logout client (src/client/auth.mjs). No real OS keychain,
// no network: fetch + clock are injected, the token file lives under a mkdtemp dir.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, statSync, readFileSync, writeFileSync, utimesSync } from 'node:fs';
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

test('getValidAccessToken: a failed refresh keeps using the STILL-VALID access token (no spurious anonymous)', async () => {
  const f = tmp();
  const nowS = 1_700_000_000;
  const obj = tokenObj(nowS + 60);          // 60s left — inside skew, but NOT yet expired
  saveToken(f, obj);
  const tok = await getValidAccessToken({
    file: f, now: nowS * 1000, skewMs: 300_000, authBase: 'https://x/auth-device',
    fetchImpl: async () => { throw new Error('network down'); },
  });
  assert.equal(tok, obj.access_token, 'a transient refresh failure must NOT drop a valid session to anonymous');
});

test('getValidAccessToken: null (anonymous) only once the token is EXPIRED and refresh fails', async () => {
  const f = tmp();
  const nowS = 1_700_000_000;
  saveToken(f, tokenObj(nowS - 10));        // already expired
  const tok = await getValidAccessToken({
    file: f, now: nowS * 1000, skewMs: 300_000, authBase: 'https://x/auth-device',
    fetchImpl: async () => ({ ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) }),
  });
  assert.equal(tok, null, 'expired token + dead refresh → anonymous (never throws)');
});

test('getValidAccessToken: concurrent ticks redeem the single-use refresh token exactly ONCE (lock)', async () => {
  const f = tmp();
  const nowS = 1_700_000_000;
  const old = tokenObj(nowS + 60);          // inside skew → both calls attempt refresh
  saveToken(f, old);
  const newAccess = fakeJwt(nowS + 3600, { publisher_id: 'p1' });
  let calls = 0;
  let release;
  const gate = new Promise((r) => { release = r; });
  const fetchImpl = async () => {
    calls += 1;
    await gate;                             // hold the winner open so the loser must decide meanwhile
    return { ok: true, status: 200, json: async () => ({ access_token: newAccess, refresh_token: 'refresh-NEW', expires_in: 3600 }) };
  };
  const opts = { file: f, now: nowS * 1000, skewMs: 300_000, authBase: 'https://x/auth-device', fetchImpl };
  const p1 = getValidAccessToken(opts);     // acquires the lock, then blocks on the gate
  const p2 = getValidAccessToken(opts);     // lock busy → must NOT call fetch
  const r2 = await p2;
  assert.equal(calls, 1, 'the loser did not fire a second refresh (single-use token not burned)');
  assert.equal(r2, old.access_token, 'the loser keeps using the still-valid access token');
  release();
  const r1 = await p1;
  assert.equal(r1, newAccess, 'the winner returns the freshly minted token');
  assert.equal(loadToken(f).refresh_token, 'refresh-NEW', 'rotation persisted exactly once');
  assert.equal(existsSync(`${f}.lock`), false, 'lock released after refresh');
});

test('getValidAccessToken: a stale lock (crashed holder) is reclaimed so refresh is not wedged shut', async () => {
  const f = tmp();
  const nowS = 1_700_000_000;
  saveToken(f, tokenObj(nowS + 60));
  const lock = `${f}.lock`;
  writeFileSync(lock, '');                  // simulate a lock left by a dead process
  const past = Date.now() / 1000 - 60;      // 60s old (> LOCK_STALE_MS 15s)
  utimesSync(lock, past, past);
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return { ok: true, status: 200, json: async () => ({ access_token: fakeJwt(nowS + 3600), refresh_token: 'refresh-NEW', expires_in: 3600 }) }; };
  const tok = await getValidAccessToken({ file: f, now: nowS * 1000, skewMs: 300_000, authBase: 'https://x/auth-device', fetchImpl });
  assert.equal(calls, 1, 'stale lock reclaimed and refresh proceeded');
  assert.equal(loadToken(f).refresh_token, 'refresh-NEW');
});

test('getValidAccessToken: an aborted refresh leaves the OLD token on disk, and the next tick RE-PRESENTS it (server-grace self-heal)', async () => {
  // Client half of migration 20260704120000 (refresh-token grace window). The SQL grace only recovers
  // a crash-mid-rotation if the client — having failed to persist the successor — re-presents the SAME
  // (old) refresh token on its next tick. Pin that contract: the integration tests drive SQL directly
  // and can NOT catch a client refactor (persist-before-call, clear-on-fail) that would break self-heal.
  const f = tmp();
  const nowS = 1_700_000_000;
  saveToken(f, tokenObj(nowS + 60));            // 60s left → inside the 300s skew → attempts refresh
  const base = 'https://x/auth-device';

  // Tick 1 — the server rotates, but the client ABORTS before persisting (killed at FETCH_TIMEOUT).
  const calls1 = [];
  const tok1 = await getValidAccessToken({
    file: f, now: nowS * 1000, skewMs: 300_000, authBase: base,
    fetchImpl: async (url, opts) => {
      calls1.push({ url, body: JSON.parse(opts.body) });
      throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    },
  });
  assert.equal(calls1[0].body.refresh_token, 'refresh-abc', 'tick 1 presented the original token');
  assert.equal(tok1, tokenObj(nowS + 60).access_token, 'tick 1 falls back to the still-valid access token (never throws)');
  assert.equal(loadToken(f).refresh_token, 'refresh-abc', 'the OLD refresh token is STILL on disk — successor was never persisted');

  // Tick 2 — the server GRACE arm accepts the re-presented original and rotates. Client MUST re-present the original.
  const calls2 = [];
  const newAccess = fakeJwt(nowS + 3600, { publisher_id: 'p1' });
  const tok2 = await getValidAccessToken({
    file: f, now: nowS * 1000, skewMs: 300_000, authBase: base,
    fetchImpl: async (url, opts) => {
      calls2.push({ url, body: JSON.parse(opts.body) });
      return { ok: true, status: 200, json: async () => ({ access_token: newAccess, refresh_token: 'refresh-RECOVERED', expires_in: 3600 }) };
    },
  });
  assert.equal(calls2[0].body.refresh_token, 'refresh-abc', 'tick 2 RE-PRESENTS the original (grace-recoverable) token');
  assert.equal(tok2, newAccess, 'tick 2 recovers a fresh access token via the grace arm');
  assert.equal(loadToken(f).refresh_token, 'refresh-RECOVERED', 'the recovery successor is now persisted');
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

test('login: a transient poll error (timeout/network) does NOT crash login — keeps polling', async () => {
  // Regression: a single thrown fetch (e.g. AbortError on a slow cold-start poll) used to escape
  // login() uncaught and kill the whole flow. It must be tolerated and polling must continue.
  const f = tmp();
  let tokenCalls = 0;
  const fetchImpl = async (url) => {
    if (url.endsWith('/device/code')) {
      return { ok: true, status: 200, json: async () => ({
        device_code: 'DC', user_code: 'U', verification_uri: 'https://x/a', interval: 0, expires_in: 600,
      }) };
    }
    if (url.endsWith('/device/token')) {
      tokenCalls++;
      if (tokenCalls === 1) throw Object.assign(new Error('aborted'), { name: 'AbortError' }); // transient
      if (tokenCalls === 2) return { ok: false, status: 400, json: async () => ({ error: 'authorization_pending' }) };
      return { ok: true, status: 200, json: async () => ({
        access_token: fakeJwt(2_000_000_000, { publisher_id: 'pZ' }), refresh_token: 'R2',
        expires_in: 3600, publisher_id: 'pZ', device_id: 'dZ', handle: 'dev-z',
      }) };
    }
    throw new Error('unexpected url ' + url);
  };
  const res = await login({
    file: f, authBase: 'https://x/auth-device', fetchImpl, sleep: async () => {}, out: () => {}, now: 1000,
  });
  assert.equal(res.handle, 'dev-z', 'login completed despite a transient poll throw');
  assert.ok(tokenCalls >= 3, 'kept polling through the thrown error');
  assert.equal(loadToken(f).publisher_id, 'pZ', 'token persisted');
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
