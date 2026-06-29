// M1 integration test — proves the device-code login binds credit to a REAL publisher and that
// revocation, refresh rotation, and earnings RLS all behave, end-to-end through PostgREST using
// the SAME SECURITY DEFINER RPCs the auth-device edge fn drives.
//
//   device_code_start (service) -> approve (publisher A's auth JWT) -> redeem (service) =>
//   a real device JWT whose window_open/beat/close credit publisher A (NOT the sentinel);
//   then: redeem is one-shot, a revoked device is rejected by window_open, refresh rotates the
//   token (old hash invalid after), and the earnings views are RLS-scoped per publisher.
//
// SKIPs cleanly when the local Supabase stack is down, so the offline unit suite stays green.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createHash, randomBytes } from 'node:crypto';

const BASE = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// Seeded identities (supabase/seed.sql).
const A = { auth: '11111111-1111-1111-1111-111111111111', pub: 'a1a1a1a1-0000-0000-0000-000000000001' };
const B = { auth: '22222222-2222-2222-2222-222222222222', pub: 'b1b1b1b1-0000-0000-0000-000000000002' };
const EXPECTED_GROSS = 5 * 2000; // 5 attention-seconds * seeded cpva_bid_micros (matches phase1)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha = (s) => createHash('sha256').update(s).digest('hex');

function mintJwt(claims) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', iat: 1700000000, exp: 2000000000, ...claims });
  const sig = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}
const beatHmac = (challenge, seq, prevHash, delta) =>
  createHmac('sha256', challenge).update(`${seq}|${prevHash}|${delta}`).digest('hex');

async function rpc(name, body, { jwt } = {}) {
  const headers = { apikey: ANON, 'content-type': 'application/json' };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  const res = await fetch(`${BASE}/rpc/${name}`, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
  const text = await res.text();
  if (!res.ok) throw new Error(`rpc ${name} -> HTTP ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}
async function getView(view, query, jwt) {
  const res = await fetch(`${BASE}/${view}?${query}`, { headers: { apikey: ANON, Authorization: `Bearer ${jwt}` } });
  const text = await res.text();
  if (!res.ok) throw new Error(`GET ${view} -> HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}
async function svcSelect(path) {
  const res = await fetch(`${BASE}/${path}`, { headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` } });
  const text = await res.text();
  if (!res.ok) throw new Error(`GET ${path} -> HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}

// Run one device-code cycle as publisher A; returns the minted device identity + refresh hash.
async function loginAs(authIdent, { revokeReady = false } = {}) {
  const deviceCode = randomBytes(24).toString('base64url');
  const userCode = randomBytes(5).toString('hex').toUpperCase().slice(0, 8);
  const refresh = randomBytes(24).toString('base64url');
  await rpc('device_code_start', { p_device_code_hash: sha(deviceCode), p_user_code: userCode, p_ttl_seconds: 600, p_interval: 5 }, { jwt: SERVICE });
  const approve = await rpc('device_code_approve', { p_user_code: userCode }, { jwt: mintJwt({ sub: authIdent.auth }) });
  assert.equal(approve.ok, true, `approve ok (reason=${approve.reason})`);
  const redeem = await rpc('device_code_redeem', { p_device_code_hash: sha(deviceCode), p_label: 'itest', p_client_version: 't', p_refresh_token_hash: sha(refresh) }, { jwt: SERVICE });
  assert.equal(redeem.status, 'approved');
  return { redeem, deviceCode, refresh, refreshHash: sha(refresh) };
}

async function fullWindow(deviceJwt) {
  const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt: deviceJwt });
  const openedAt = Date.now();
  let prev = win.window_id;
  for (let seq = 1; seq <= 5; seq++) {
    await sleep(560);
    const hmac = beatHmac(win.challenge, seq, prev, 'high');
    await rpc('window_beat', { p_window_id: win.window_id, p_seq: seq, p_hmac: hmac, p_activity_delta: 'high' }, { jwt: deviceJwt });
    prev = hmac;
  }
  const remaining = 5400 - (Date.now() - openedAt);
  if (remaining > 0) await sleep(remaining);
  const close = await rpc('close_window', { p_window_id: win.window_id }, { jwt: deviceJwt });
  return { windowId: win.window_id, close };
}

async function isReachable() {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 1500);
  try {
    const res = await fetch(`${BASE}/`, { headers: { apikey: ANON }, signal: ctrl.signal });
    return res.status >= 200 && res.status < 500;
  } catch { return false; } finally { clearTimeout(t); }
}

const UP = await isReachable();
if (!UP) console.log(`[auth-device.integration] PostgREST unreachable at ${BASE} — SKIPPING.`);

test('M1 device-code login: attribution, one-shot, revocation, refresh, earnings RLS', {
  skip: UP ? false : `PostgREST unreachable at ${BASE}`,
}, async (t) => {
  let session;

  await t.test('ensure_publisher is idempotent + never overwrites an existing handle', async () => {
    const r = await rpc('ensure_publisher', { p_handle: 'should-be-ignored' }, { jwt: mintJwt({ sub: A.auth }) });
    assert.equal(r.publisher_id, A.pub);
    assert.equal(r.created, false, 'existing publisher is returned, not recreated');
    assert.equal(r.handle, 'dev-a', "an explicit handle never renames an existing publisher");
  });

  await t.test('device-code grant approves + redeems to a REAL device for publisher A', async () => {
    session = await loginAs(A);
    assert.equal(session.redeem.publisher_id, A.pub, 'minted device belongs to publisher A');
    assert.equal(session.redeem.auth_user_id, A.auth, 'sub maps to A.auth_user_id (earnings RLS works)');
    assert.ok(session.redeem.device_id, 'a device row was created');
  });

  await t.test('a logged-in window credits the REAL publisher (not the sentinel), gross > 0', async () => {
    const deviceJwt = mintJwt({ sub: A.auth, publisher_id: A.pub, device_id: session.redeem.device_id });
    const { windowId, close } = await fullWindow(deviceJwt);
    assert.equal(close.credited, true, `credited (reason=${close.reason})`);
    assert.equal(close.gross_micros, EXPECTED_GROSS, 'real publisher bills (gross>0), unlike the gross=0 sentinel');
    const rows = await svcSelect(`impressions?window_id=eq.${windowId}&select=publisher_id,gross_micros,state`);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].publisher_id, A.pub, 'impression attributed to the REAL publisher A');
    assert.equal(rows[0].state, 'provisional');
  });

  await t.test('redeem is one-shot: a replayed redeem returns consumed (no second device)', async () => {
    const again = await rpc('device_code_redeem', { p_device_code_hash: sha(session.deviceCode) }, { jwt: SERVICE });
    assert.equal(again.status, 'consumed');
  });

  await t.test('revoked device is rejected by window_open (cannot accrue)', async () => {
    const rev = await rpc('device_revoke', { p_device_id: session.redeem.device_id }, { jwt: mintJwt({ sub: A.auth }) });
    assert.equal(rev.ok, true);
    const deviceJwt = mintJwt({ sub: A.auth, publisher_id: A.pub, device_id: session.redeem.device_id });
    await assert.rejects(() => rpc('window_open', { p_activity_snapshot: 'session' }, { jwt: deviceJwt }), /28000|revoked|unknown/i);
  });

  await t.test("another publisher cannot revoke A's device (ownership scoped)", async () => {
    const s2 = await loginAs(A);
    const bTry = await rpc('device_revoke', { p_device_id: s2.redeem.device_id }, { jwt: mintJwt({ sub: B.auth }) });
    assert.equal(bTry.ok, false, "publisher B's revoke does not touch A's device");
  });

  await t.test('refresh rotates: the old refresh hash is invalid after one use', async () => {
    const s = await loginAs(A);
    const newRefresh = randomBytes(24).toString('base64url');
    const r1 = await rpc('device_refresh', { p_refresh_token_hash: s.refreshHash, p_new_refresh_token_hash: sha(newRefresh) }, { jwt: SERVICE });
    assert.equal(r1.status, 'ok');
    assert.equal(r1.publisher_id, A.pub);
    const r2 = await rpc('device_refresh', { p_refresh_token_hash: s.refreshHash, p_new_refresh_token_hash: sha(randomBytes(8).toString('hex')) }, { jwt: SERVICE });
    assert.equal(r2.status, 'invalid', 'the rotated-away hash no longer refreshes');
  });

  await t.test('earnings views are RLS-scoped: A sees A only; B never sees A', async () => {
    const aJwt = mintJwt({ sub: A.auth, publisher_id: A.pub, device_id: '00000000-0000-0000-0000-000000000000' });
    const bJwt = mintJwt({ sub: B.auth });
    const balA = await getView('v_publisher_balance', 'select=*', aJwt);
    assert.ok(balA.every((r) => r.publisher_id === A.pub), 'A sees only its own balance row(s)');
    const balB = await getView('v_publisher_balance', 'select=*', bJwt);
    assert.ok(balB.every((r) => r.publisher_id !== A.pub), "B never sees A's balance");
    const winA = await getView('v_publisher_window_clearing', `publisher_id=eq.${A.pub}&select=publisher_id`, aJwt);
    assert.ok(winA.length >= 1 && winA.every((r) => r.publisher_id === A.pub), 'A sees its own cleared windows');
    const winB = await getView('v_publisher_window_clearing', `publisher_id=eq.${A.pub}&select=publisher_id`, bJwt);
    assert.equal(winB.length, 0, "B sees none of A's windows even when querying A's id");
  });
});
