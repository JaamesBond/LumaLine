// test/serving.integration.mjs — Integration tests for M2-T1 serving algorithm.
//
// Tests the weighted rotation, sentinel gate, frequency cap, budget pacing, and
// reserve-floor (clearing_price_micros) against the REAL local Supabase/PostgREST stack.
//
// Pattern mirrors phase1.rpc.integration.mjs: self-skips cleanly when the local stack is
// unreachable, so the offline `node --test` hermetic suite stays green.
//
// WHAT IS TESTED (requires local stack with `supabase db reset` seeded data):
//   T1  Sentinel publisher receives ONLY house/zero-cost creatives (gross=0 gate).
//   T2  Real publisher gets the seeded paid creative via weighted rotation.
//   T3  clearing_price_micros is locked at window_open (stored value matches seed bid).
//   T4  serve_counters increment at window_open (frequency cap tracker).
//   T5  Frequency cap: N+1th serve is suppressed when cap=N is reached.
//   T6  line_item_daily_stats spend is updated at close_window for paid impressions.
//   T7  Sentinel window credits with gross=0 (honest billing: never pays sentinel).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

const BASE = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// Publisher A — dev seed "real publisher" (paid creative, cpva_bid_micros=2000).
const PUB_A = {
  sub: '11111111-1111-1111-1111-111111111111',
  publisher_id: 'a1a1a1a1-0000-0000-0000-000000000001',
  device_id: 'd1d1d1d1-0000-0000-0000-000000000001',
};

// Sentinel identity — seed.prod.sql / lumaline-feed edge function defaults.
// publisher_id MUST equal the SENTINEL_PUB constant in the migration.
const SENTINEL = {
  sub: '5e470000-0000-4000-8000-000000000001',
  publisher_id: '5e470000-0000-4000-8000-0000000000b1',
  device_id: '5e470000-0000-4000-8000-0000000000d1',
};

// Seeded line_item / creative for PUB_A's demand path (from seed.sql).
const SEEDED_LINE_ITEM_ID = '11000000-0000-0000-0000-000000000001';
const SEEDED_CPVA_BID = 2000; // cpva_bid_micros in seed.sql

const BEAT_SPACING_MS = 560;   // > 500ms anti-batch floor
const BEATS = 5;               // >= minBeats (3)
const DWELL_TARGET_MS = 5400;  // > dwell_ms (5000)
const ACTIVITY_DELTA = 'high'; // non-'none' => activity_progress = true

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mintDeviceJwt({ sub, publisher_id, device_id }) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({
    role: 'authenticated', aud: 'authenticated',
    sub, publisher_id, device_id,
    iat: 1700000000, exp: 2000000000,
  });
  const sig = createHmac('sha256', JWT_SECRET)
    .update(`${head}.${payload}`)
    .digest('base64url');
  return `${head}.${payload}.${sig}`;
}

function beatHmac(challenge, seq, prevHash, activityDelta) {
  return createHmac('sha256', challenge)
    .update(`${seq}|${prevHash}|${activityDelta}`)
    .digest('hex');
}

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

async function svcSelect(path) {
  const res = await fetch(`${BASE}/${path}`, {
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`GET ${path} -> HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}

// Execute arbitrary SQL via service_role (used to read counters / set up edge cases).
async function svcSql(query) {
  const res = await fetch(`${BASE}/../rest/v1/rpc/exec_sql`, {
    method: 'POST',
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  // If exec_sql doesn't exist, we fall back to manual data inspection via svcSelect.
  return res.ok ? res.json() : null;
}

// Do an honest full-dwell close (beats + wait + close) for a given window.
// Returns the close_window result.
async function honestClose(windowId, challenge, jwt, openedAt) {
  let prevHash = windowId;
  for (let seq = 1; seq <= BEATS; seq++) {
    await sleep(BEAT_SPACING_MS);
    const hmac = beatHmac(challenge, seq, prevHash, ACTIVITY_DELTA);
    await rpc('window_beat', { p_window_id: windowId, p_seq: seq, p_hmac: hmac, p_activity_delta: ACTIVITY_DELTA }, { jwt });
    prevHash = hmac;
  }
  const remaining = DWELL_TARGET_MS - (Date.now() - openedAt);
  if (remaining > 0) await sleep(remaining);
  return rpc('close_window', { p_window_id: windowId }, { jwt });
}

async function isReachable() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 1500);
  try {
    const res = await fetch(`${BASE}/`, { headers: { apikey: ANON }, signal: ctrl.signal });
    return res.status >= 200 && res.status < 500;
  } catch { return false; }
  finally { clearTimeout(timer); }
}

const UP = await isReachable();
if (!UP) {
  console.log(
    `[serving.integration] PostgREST unreachable at ${BASE} — SKIPPING ` +
      `(offline node --test unit suite stays green).`,
  );
}

// Check if the sentinel publisher is seeded (seed.prod.sql, not the dev seed.sql).
// T1 and T7 require the sentinel to be in the DB; skip cleanly in plain dev stacks.
async function sentinelSeeded() {
  try {
    const rows = await svcSelect(`publishers?id=eq.${SENTINEL.publisher_id}&select=id`);
    return rows.length > 0;
  } catch { return false; }
}
const SENTINEL_SEEDED = UP ? await sentinelSeeded() : false;
if (UP && !SENTINEL_SEEDED) {
  console.log(
    `[serving.integration] Sentinel publisher not in dev seed — T1/T7 will SKIP. ` +
      `Apply supabase/seed.prod.sql to test sentinel gate against a live stack.`,
  );
}

// ---------------------------------------------------------------------------
// T1: Sentinel gate — sentinel publisher receives only house/zero-cost creatives
// Requires seed.prod.sql to be applied (sentinel publisher/device must exist in DB).
// ---------------------------------------------------------------------------
test('T1 — sentinel publisher receives only zero-cost (gross=0) creative', {
  skip: !UP ? `PostgREST unreachable at ${BASE}`
    : !SENTINEL_SEEDED ? 'sentinel not in dev seed (apply seed.prod.sql to test this gate)'
    : false,
}, async () => {
  const jwt = mintDeviceJwt(SENTINEL);
  const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
  assert.ok(win.window_id, 'window opened for sentinel');
  // The ad must be served — sentinel has a seeded self-promo creative.
  // TRUST INVARIANT: clearing_price_micros MUST be 0 for the sentinel.
  const rows = await svcSelect(`ad_windows?window_id=eq.${win.window_id}&select=clearing_price_micros,line_item_id,creative_id`);
  assert.equal(rows.length, 1, 'one ad_windows row');
  assert.equal(Number(rows[0].clearing_price_micros), 0,
    'sentinel window clearing_price_micros MUST be 0 (paid-demand auth gate)');
});

// ---------------------------------------------------------------------------
// T2: Real publisher gets the seeded paid creative via weighted rotation
// ---------------------------------------------------------------------------
test('T2 — real publisher receives the seeded paid creative (weighted rotation)', {
  skip: UP ? false : `PostgREST unreachable at ${BASE}`,
}, async () => {
  const jwt = mintDeviceJwt(PUB_A);
  const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
  assert.ok(win.window_id, 'window opened for real publisher');
  assert.ok(win.ad && win.ad.line, 'a booked creative was served (not house)');
  assert.equal(win.ad.house, undefined, 'not a house window');
});

// ---------------------------------------------------------------------------
// T3: clearing_price_micros is locked at serve time (matches the seeded cpva bid)
// ---------------------------------------------------------------------------
test('T3 — clearing_price_micros is locked at window_open to the seeded CPVA bid', {
  skip: UP ? false : `PostgREST unreachable at ${BASE}`,
}, async () => {
  const jwt = mintDeviceJwt(PUB_A);
  const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
  const rows = await svcSelect(`ad_windows?window_id=eq.${win.window_id}&select=clearing_price_micros,line_item_id`);
  assert.equal(rows.length, 1);
  // The seeded line_item has cpva_bid_micros=2000 — this MUST be locked at open.
  assert.equal(Number(rows[0].clearing_price_micros), SEEDED_CPVA_BID,
    `clearing_price_micros should be ${SEEDED_CPVA_BID} (seeded cpva_bid_micros)`);
  assert.equal(rows[0].line_item_id, SEEDED_LINE_ITEM_ID, 'correct line_item served');
});

// ---------------------------------------------------------------------------
// T4: serve_counters increment at window_open
// ---------------------------------------------------------------------------
test('T4 — serve_counters increments at window_open', {
  skip: UP ? false : `PostgREST unreachable at ${BASE}`,
}, async () => {
  const jwt = mintDeviceJwt(PUB_A);

  // Read counter before.
  const before = await svcSelect(
    `serve_counters?publisher_id=eq.${PUB_A.publisher_id}&line_item_id=eq.${SEEDED_LINE_ITEM_ID}&day=eq.${new Date().toISOString().slice(0, 10)}&select=served`
  );
  const beforeCount = before.length > 0 ? Number(before[0].served) : 0;

  await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });

  const after = await svcSelect(
    `serve_counters?publisher_id=eq.${PUB_A.publisher_id}&line_item_id=eq.${SEEDED_LINE_ITEM_ID}&day=eq.${new Date().toISOString().slice(0, 10)}&select=served`
  );
  const afterCount = Number(after[0].served);

  assert.equal(afterCount, beforeCount + 1,
    `serve_counters.served should be ${beforeCount + 1} after window_open (was ${beforeCount})`);
});

// ---------------------------------------------------------------------------
// T5: Frequency cap — N+1th serve is suppressed when cap=N is reached
// ---------------------------------------------------------------------------
test('T5 — frequency cap: N+1th serve suppressed when cap=N reached', {
  skip: UP ? false : `PostgREST unreachable at ${BASE}`,
}, async () => {
  const today = new Date().toISOString().slice(0, 10);
  const jwt = mintDeviceJwt(PUB_A);

  // Read current served count (earlier tests in this session already incremented it).
  const counter = await svcSelect(
    `serve_counters?publisher_id=eq.${PUB_A.publisher_id}&line_item_id=eq.${SEEDED_LINE_ITEM_ID}&day=eq.${today}&select=served`,
  );
  const currentServed = counter.length > 0 ? Number(counter[0].served) : 0;

  // Set cap = currentServed + 1 → exactly one more serve allowed, then blocked.
  const patch = await fetch(`${BASE}/line_items?id=eq.${SEEDED_LINE_ITEM_ID}`, {
    method: 'PATCH',
    headers: {
      apikey: SERVICE, Authorization: `Bearer ${SERVICE}`,
      'content-type': 'application/json', Prefer: 'return=minimal',
    },
    body: JSON.stringify({ frequency_cap_per_day: currentServed + 1 }),
  });
  if (!patch.ok) throw new Error(`PATCH line_items -> ${patch.status}: ${await patch.text()}`);

  try {
    // First window_open — cap not yet hit (served=currentServed < cap=currentServed+1).
    const win1 = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
    assert.ok(win1.window_id, 'first window opened');
    assert.ok(!win1.ad?.house, 'first serve is paid creative (cap not yet hit)');

    // Second window_open — cap now hit (served=currentServed+1 = cap).
    const win2 = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
    assert.ok(win2.window_id, 'second window opened');
    assert.equal(win2.ad?.house, true, 'second serve must be house creative (frequency cap hit)');
  } finally {
    // Cleanup: reset frequency_cap_per_day to null so later tests are unaffected.
    await fetch(`${BASE}/line_items?id=eq.${SEEDED_LINE_ITEM_ID}`, {
      method: 'PATCH',
      headers: {
        apikey: SERVICE, Authorization: `Bearer ${SERVICE}`,
        'content-type': 'application/json', Prefer: 'return=minimal',
      },
      body: JSON.stringify({ frequency_cap_per_day: null }),
    });
  }
});

// ---------------------------------------------------------------------------
// T6: line_item_daily_stats.spent_micros increments at close_window
// ---------------------------------------------------------------------------
test('T6 — line_item_daily_stats.spent_micros increments after a credited close', {
  skip: UP ? false : `PostgREST unreachable at ${BASE}`,
}, async (t) => {
  if (!process.env.SERVING_SLOW_TESTS) { t.skip('set SERVING_SLOW_TESTS=1 to run'); return; }

  const jwt = mintDeviceJwt(PUB_A);
  const today = new Date().toISOString().slice(0, 10);

  const before = await svcSelect(
    `line_item_daily_stats?line_item_id=eq.${SEEDED_LINE_ITEM_ID}&day=eq.${today}&select=spent_micros`
  );
  const beforeSpent = before.length > 0 ? Number(before[0].spent_micros) : 0;

  const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
  const openedAt = Date.now();
  const res = await honestClose(win.window_id, win.challenge, jwt, openedAt);

  assert.equal(res.credited, true, `close credited (reason=${res.reason})`);
  assert.ok(res.gross_micros > 0, 'gross_micros > 0 (paid impression)');

  const after = await svcSelect(
    `line_item_daily_stats?line_item_id=eq.${SEEDED_LINE_ITEM_ID}&day=eq.${today}&select=spent_micros`
  );
  const afterSpent = Number(after[0].spent_micros);
  assert.equal(afterSpent, beforeSpent + res.gross_micros,
    `daily_stats.spent_micros should have grown by ${res.gross_micros}`);
});

// ---------------------------------------------------------------------------
// T7: Sentinel window credits with gross=0 (honest billing invariant)
// Requires seed.prod.sql to be applied (sentinel publisher/device must exist in DB).
// ---------------------------------------------------------------------------
test('T7 — sentinel window credits with gross=0 (honest billing invariant)', {
  skip: !UP ? `PostgREST unreachable at ${BASE}`
    : !SENTINEL_SEEDED ? 'sentinel not in dev seed (apply seed.prod.sql to test this gate)'
    : false,
}, async (t) => {
  if (!process.env.SERVING_SLOW_TESTS) { t.skip('set SERVING_SLOW_TESTS=1 to run'); return; }

  const jwt = mintDeviceJwt(SENTINEL);
  const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
  const openedAt = Date.now();
  const res = await honestClose(win.window_id, win.challenge, jwt, openedAt);

  // The sentinel creative has cpva=0, so gross is always 0.
  assert.equal(res.credited, true, `sentinel window should credit (gross=0 is still credited)`);
  assert.equal(res.gross_micros, 0, 'sentinel window MUST credit with gross=0 (honest billing)');
});
