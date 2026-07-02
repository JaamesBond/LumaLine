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
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
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

async function svcWrite(method, path, body) {
  const res = await fetch(`${BASE}/${path}`, {
    method,
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'content-type': 'application/json', Prefer: 'return=minimal' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${path} -> HTTP ${res.status}: ${await res.text()}`);
}

// Direct psql access — needed ONLY for auth.users (config.toml exposes just
// public/graphql_public via PostgREST, so REST cannot see the auth schema). B1 needs it
// to create a dedicated publisher's backing auth.users row. Mirrors the pattern used in
// payout-rails.integration.mjs / gdpr-deletion.integration.mjs.
function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

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

// B1 needs psql to seed a dedicated publisher's backing auth.users row (see psql() above).
const PSQL_OK = UP ? psqlWorks() : false;
if (UP && !PSQL_OK) {
  console.log(`[serving.integration] psql unavailable — B1 will SKIP.`);
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

// ---------------------------------------------------------------------------
// TOL: dwell tolerance — a window whose SERVER-measured dwell lands within v_tolerance
// (1000ms) BELOW dwell_ms still credits. Guards the edge-latency fix
// (20260703010000_close_window_dwell_tolerance.sql): the client stamps its dwell start
// BEFORE the /window/open round-trip, the server stamps ad_windows.started_at AFTER it, so
// an honest full dwell measures a few hundred ms short server-side at real edge latency.
// Without the tolerance this legitimate PAID impression was thrown away as 'dwell too short'
// (window 'abandoned', no credit → lost advertiser revenue + uncredited publisher).
// Deterministic: backdate started_at to now()-4600ms (between dwell_ms-tolerance=4000 and
// dwell_ms=5000) instead of racing the wall clock. The OLD close_window rejected this.
// ---------------------------------------------------------------------------
test('TOL — a paid dwell within tolerance of dwell_ms still credits (edge-latency fix)', {
  skip: !UP ? `PostgREST unreachable at ${BASE}`
    : !PSQL_OK ? 'psql unavailable (needed to backdate started_at)'
    : false,
}, async () => {
  const jwt = mintDeviceJwt(PUB_A);
  const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
  assert.ok(win.window_id, 'window opened');

  // 3 anti-batch-respecting beats (>= minBeats, spaced > 500ms) so beats_count and
  // activity_progress gates are satisfied, then backdate started_at so the server measures
  // elapsed ~4600ms — under dwell_ms (5000) but inside the 1000ms tolerance.
  let prevHash = win.window_id;
  for (let seq = 1; seq <= 3; seq++) {
    await sleep(BEAT_SPACING_MS);
    const hmac = beatHmac(win.challenge, seq, prevHash, ACTIVITY_DELTA);
    await rpc('window_beat', { p_window_id: win.window_id, p_seq: seq, p_hmac: hmac, p_activity_delta: ACTIVITY_DELTA }, { jwt });
    prevHash = hmac;
  }
  psql(`update public.ad_windows set started_at = now() - interval '4600 milliseconds' where window_id = '${win.window_id}'`);

  const res = await rpc('close_window', { p_window_id: win.window_id }, { jwt });
  assert.equal(res.credited, true, `sub-dwell-but-in-tolerance window MUST credit (reason=${res.reason})`);
  assert.ok(res.gross_micros > 0, 'paid impression credits gross_micros > 0 within tolerance');
  assert.ok(res.attention_seconds >= 4, `attention reflects the real ~4.6s elapsed capped at dwell (got ${res.attention_seconds})`);
});

// ---------------------------------------------------------------------------
// B1: cumulative total-budget cap counts only VALID impressions — a line item is
// suppressed once lifetime spend (sum of provisional+cleared impressions.gross_micros)
// reaches budget_total_micros, but a clawed_back impression of the same amount does NOT
// count (20260702120000_true_total_budget_cap.sql sums public.impressions in billable
// states; clawbacks are excluded on purpose so a reversed flight regains its budget).
//
// Uses a DEDICATED advertiser->campaign->line_item->creative AND a DEDICATED
// publisher+device (fresh rows), so this test can never mutate the SHARED seed line item
// (SEEDED_LINE_ITEM_ID) or any other publisher's counters — the total-budget guard has NO
// publisher filter, so the old B1 (which PATCHed the shared line item + shared
// line_item_daily_stats) could starve concurrent test files of paid/house fills. This
// version seeds public.impressions directly (the guard's actual source), never
// line_item_daily_stats (which the new guard no longer reads).
// ---------------------------------------------------------------------------
test('B1 — cumulative total budget cap counts only valid impressions (clawbacks excluded)', {
  skip: !UP ? `PostgREST unreachable at ${BASE}`
    : !PSQL_OK ? 'psql unavailable (needed to seed a dedicated publisher\'s auth.users row)'
    : false,
}, async () => {
  const BUDGET_TOTAL = 3_000_000;
  const UNIQUE_LINE = `B1-dedicated-budget-cap-${randomUUID()}`;
  // High weight (1000) vs the seeded competitor's weight (1, per seed.sql) makes both the
  // "excluded" and "eligible" outcomes below effectively deterministic over N calls.
  const N = 25;

  const authId       = randomUUID();
  const pubId        = randomUUID();
  const deviceId     = randomUUID();
  const advertiserId = randomUUID();
  const campaignId   = randomUUID();
  const lineItemId   = randomUUID();
  const creativeId   = randomUUID();
  const impressionId = randomUUID();

  const jwt = mintDeviceJwt({ sub: authId, publisher_id: pubId, device_id: deviceId });

  async function servedLines() {
    const lines = [];
    for (let i = 0; i < N; i++) {
      const win = await rpc('window_open', { p_activity_snapshot: 'session' }, { jwt });
      lines.push(win.ad && win.ad.line ? win.ad.line : null);
    }
    return lines;
  }

  try {
    // ---- Arrange: dedicated auth user + publisher + device (shapes mirror seed.sql) ----
    psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
        email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
        confirmation_token, recovery_token, email_change_token_new, email_change)
      values ('00000000-0000-0000-0000-000000000000','${authId}','authenticated','authenticated',
        'b1-${authId}@example.com','',now(),'{"provider":"email","providers":["email"]}','{}',
        now(),now(),'','','','');`);

    await svcWrite('POST', 'publishers',
      [{ id: pubId, auth_user_id: authId, handle: `b1-${pubId.slice(0, 8)}`, country: 'US', status: 'active' }]);
    await svcWrite('POST', 'devices',
      [{ id: deviceId, publisher_id: pubId, label: 'B1 dedicated device', client_version: '0.1.0', attested: true, revoked_at: null }]);

    // ---- Arrange: dedicated demand chain — small total budget, high weight, global targeting ----
    await svcWrite('POST', 'advertisers', [{ id: advertiserId, name: 'B1 dedicated advertiser', status: 'active' }]);
    await svcWrite('POST', 'campaigns', [{ id: campaignId, advertiser_id: advertiserId, name: 'B1 dedicated campaign', status: 'active' }]);
    await svcWrite('POST', 'line_items', [{
      id: lineItemId, campaign_id: campaignId,
      cpva_bid_micros: 1000, cpc_bid_micros: 0, weight: 1000,
      budget_total_micros: BUDGET_TOTAL, budget_daily_micros: null,
      targeting: {}, status: 'active',
      start_at: new Date(Date.now() - 3600_000).toISOString(),
      end_at: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    }]);
    await svcWrite('POST', 'creatives', [{
      id: creativeId, line_item_id: lineItemId, line: UNIQUE_LINE,
      dest_url: null, label: 'sponsored', status: 'active',
    }]);

    // ---- Capped case: one CLEARED impression at exactly budget_total -> excluded ----
    await svcWrite('POST', 'impressions', [{
      id: impressionId, window_id: randomUUID(), publisher_id: pubId,
      line_item_id: lineItemId, creative_id: creativeId,
      gross_micros: BUDGET_TOTAL, state: 'cleared',
    }]);

    const cappedLines = await servedLines();
    assert.ok(!cappedLines.includes(UNIQUE_LINE),
      'dedicated line item must NOT be served once valid (cleared) spend >= budget_total_micros');
    // Positive control: the publisher CAN still get a paid ad (the seeded item) over the
    // same N calls — proves the absence above is the budget cap, not a dead/no-fill stack.
    assert.ok(cappedLines.some((l) => l !== null && l !== UNIQUE_LINE),
      'some OTHER paid creative must still serve — proves absence above is the cap, not a dead stack');

    // ---- Clawback case: same amount, but clawed_back -> must NOT count against budget ----
    await svcWrite('PATCH', `impressions?id=eq.${impressionId}`, { state: 'clawed_back' });

    const clawbackLines = await servedLines();
    assert.ok(clawbackLines.includes(UNIQUE_LINE),
      'dedicated line item MUST be eligible again once its only spend is clawed_back (excluded from the guard)');
  } finally {
    // ---- Cleanup: best-effort, FK-safe order (children before parents); never touches
    // the shared seed (SEEDED_LINE_ITEM_ID / PUB_A are never referenced above). ----
    try { await svcWrite('DELETE', `impressions?line_item_id=eq.${lineItemId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `ad_windows?publisher_id=eq.${pubId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `serve_counters?publisher_id=eq.${pubId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `line_item_daily_stats?line_item_id=eq.${lineItemId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `creatives?id=eq.${creativeId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `line_items?id=eq.${lineItemId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `campaigns?id=eq.${campaignId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `advertisers?id=eq.${advertiserId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `devices?id=eq.${deviceId}`, {}); } catch { /* best-effort */ }
    try { await svcWrite('DELETE', `publishers?id=eq.${pubId}`, {}); } catch { /* best-effort */ }
    try { psql(`delete from auth.users where id='${authId}';`); } catch { /* best-effort */ }
  }
});
