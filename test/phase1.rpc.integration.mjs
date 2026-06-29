// Phase 1 integration test — proves the verified-impression hot path end-to-end
// through PostgREST using the REAL device-JWT path (the same calls the browser/CLI make).
//
// open -> 5 honest heartbeats (HMAC hash-chain, anti-batch spacing) -> full-dwell close
//   => exactly one provisional CPVA impression (5 attention-seconds * 2000 micros = 10000),
//   credited idempotently (a replayed close never double-bills),
//   plus a tokenized click that redirects to the booked dest and dedupes durably.
//
// This file talks to a live local Supabase/PostgREST. It SKIPs cleanly when that stack is
// unreachable so the offline `node --test` unit suite stays green.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

const BASE = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// Seeded publisher A (deterministic UUIDs from the harness).
const PUB_A = {
  sub: '11111111-1111-1111-1111-111111111111',
  publisher_id: 'a1a1a1a1-0000-0000-0000-000000000001',
  device_id: 'd1d1d1d1-0000-0000-0000-000000000001',
};

// CPVA economics of the seeded line_item 11000000-...-1 (cpva_bid_micros = 2000 micro-USD/sec).
const ATTENTION_SECONDS = 5;
const CPVA_BID_MICROS = 2000;
const EXPECTED_GROSS = ATTENTION_SECONDS * CPVA_BID_MICROS; // 10000
const EXPECTED_DEST = 'https://example.com/matei';

const BEAT_SPACING_MS = 560; // > server anti-batch floor (500ms), with jitter margin
const BEATS = 5; // >= minBeats (3)
const DWELL_TARGET_MS = 5400; // > dwell_ms (5000) so the window stays open the FULL dwell
const ACTIVITY_DELTA = 'high'; // non-'none' => flips activity_progress true (required to credit)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Zero-dep device JWT (HS256), matching the harness minting recipe.
function mintDeviceJwt({ sub, publisher_id, device_id }) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({
    role: 'authenticated',
    aud: 'authenticated',
    sub,
    publisher_id,
    device_id,
    iat: 1700000000,
    exp: 2000000000,
  });
  const sig = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

// HMAC link: hmac_hex = HMAC-SHA256(key=challenge, msg=`${seq}|${prevHash}|${activityDelta}`)
function beatHmac(challenge, seq, prevHash, activityDelta) {
  return createHmac('sha256', challenge).update(`${seq}|${prevHash}|${activityDelta}`).digest('hex');
}

// Call a SECURITY DEFINER RPC through PostgREST. With { jwt } the device claims drive
// request.jwt.claims (authenticated); without it the call runs as anon (the click redirect).
async function rpc(name, body, { jwt } = {}) {
  const headers = { apikey: ANON, 'content-type': 'application/json' };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  const res = await fetch(`${BASE}/rpc/${name}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`rpc ${name} -> HTTP ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// Read rows with the service_role key (bypasses RLS) to assert durable state.
async function svcSelect(path) {
  const res = await fetch(`${BASE}/${path}`, {
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`GET ${path} -> HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}

async function isReachable() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 1500);
  try {
    const res = await fetch(`${BASE}/`, { headers: { apikey: ANON }, signal: ctrl.signal });
    return res.status >= 200 && res.status < 500; // any HTTP answer means the stack is up
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

const UP = await isReachable();
if (!UP) {
  console.log(
    `[phase1.rpc.integration] PostgREST unreachable at ${BASE} — SKIPPING ` +
      `(offline node --test unit suite stays green).`,
  );
}

test('Phase 1 verified-impression hot path (PostgREST, real device-JWT)', {
  skip: UP ? false : `PostgREST unreachable at ${BASE}`,
}, async (t) => {
  const jwt = mintDeviceJwt(PUB_A);

  // Shared across the ordered sub-steps below.
  let windowId, challenge, clickToken, openedAt;

  await t.test('window_open: opens a window with a challenge, click token, and booked ad', async () => {
    const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
    openedAt = Date.now();
    assert.ok(win.window_id, 'window_id present');
    assert.ok(win.challenge, 'challenge present');
    assert.ok(win.click_token, 'click_token present');
    assert.equal(win.dwell_ms, 5000, 'dwell is 5s');
    assert.ok(win.ad && win.ad.line, 'a booked creative was served (not house/no-fill)');
    assert.equal(win.ad.house, undefined, 'not a house window');
    windowId = win.window_id;
    challenge = win.challenge;
    clickToken = win.click_token;
  });

  await t.test('window_beat x5: honest HMAC-chained heartbeats spaced >=520ms are accepted', async () => {
    let prevHash = windowId; // chain seed = window_id
    for (let seq = 1; seq <= BEATS; seq++) {
      await sleep(BEAT_SPACING_MS);
      const hmac = beatHmac(challenge, seq, prevHash, ACTIVITY_DELTA);
      const r = await rpc(
        'window_beat',
        { p_window_id: windowId, p_seq: seq, p_hmac: hmac, p_activity_delta: ACTIVITY_DELTA },
        { jwt },
      );
      assert.deepEqual(r, { ok: true }, `beat ${seq} accepted`);
      prevHash = hmac; // next link chains on the accepted hmac
    }
  });

  await t.test('close_window: credits true after FULL dwell — 5s @ CPVA = 10000 micros', async () => {
    const remaining = DWELL_TARGET_MS - (Date.now() - openedAt);
    if (remaining > 0) await sleep(remaining); // keep the window open the full dwell
    const res = await rpc('close_window', { p_window_id: windowId }, { jwt });
    assert.equal(res.credited, true, `credited (reason=${res.reason})`);
    assert.equal(res.attention_seconds, ATTENTION_SECONDS, '5 attention-seconds');
    assert.equal(res.gross_micros, EXPECTED_GROSS, '5 * 2000 = 10000 micros');
  });

  await t.test('impressions: exactly one provisional row @ 10000 micros (service_role read)', async () => {
    const rows = await svcSelect(`impressions?window_id=eq.${windowId}&select=*`);
    assert.equal(rows.length, 1, 'exactly one impression row');
    assert.equal(rows[0].state, 'provisional', 'state is provisional');
    assert.equal(Number(rows[0].gross_micros), EXPECTED_GROSS, 'gross_micros 10000');
    assert.equal(Number(rows[0].attention_seconds), ATTENTION_SECONDS, 'attention_seconds 5');
  });

  await t.test('idempotency: replayed close_window does not re-credit (still ONE row)', async () => {
    const res2 = await rpc('close_window', { p_window_id: windowId }, { jwt });
    assert.equal(res2.credited, false, 'second close credits nothing');
    const rows = await svcSelect(`impressions?window_id=eq.${windowId}&select=window_id`);
    assert.equal(rows.length, 1, 'still exactly one impression row');
  });

  await t.test('click_resolve: redirects to booked dest and dedupes durably (ONE click row)', async () => {
    // The real redirect is anon -> the `click` edge fn -> click_resolve via the SERVICE ROLE
    // key (serviceRpc). M0's harden_function_grants migration REVOKEd anon EXECUTE on
    // click_resolve, so we call it as service_role here to mirror that hardened path.
    const c1 = await rpc('click_resolve', { p_token: clickToken }, { jwt: SERVICE });
    assert.equal(c1.ok, true, 'first click ok');
    assert.equal(c1.dest, EXPECTED_DEST, 'dest is the booked creative dest (server-side)');

    const c2 = await rpc('click_resolve', { p_token: clickToken }, { jwt: SERVICE }); // replay
    assert.equal(c2.ok, true, 'replayed click still redirects');

    const clicks = await svcSelect(`clicks?window_id=eq.${windowId}&select=window_id`);
    assert.equal(clicks.length, 1, 'exactly one click row (deduped via unique click_token_hash)');
  });
});
