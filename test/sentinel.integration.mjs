// test/sentinel.integration.mjs — Integration tests for M2-T2 sentinel-never-bills guard.
//
// Tests the structural DB constraint that prevents house/sentinel advertisers from ever
// having non-zero bids, and verifies the is_house flag is correctly set.
//
// Self-skips cleanly when the local Supabase stack is unreachable, matching the pattern
// used by serving.integration.mjs so `node --test test/` stays green offline.
//
// WHAT IS TESTED:
//   T8  Sentinel advertiser has is_house=true after the M2-T2 migration.
//   T9  Inserting a line_item with cpva_bid_micros>0 under the house campaign raises
//       a CHECK constraint violation (line_items_house_bids_zero).
//   T10 check_house_bids() allows cpva=0,cpc=0 under the house campaign (the sentinel
//       self-promo case — should NOT be rejected).
//   T11 check_house_bids() allows any bid under a non-house advertiser's campaign.
//   T12 Billing guard in close_window forces gross=0 for house line_items even when
//       clearing_price_micros > 0 (bypasses CHECK constraint via direct service_role INSERT).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';

const BASE = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// Sentinel advertiser + campaign — from seed.sql / seed.prod.sql.
const SENTINEL_ADVERTISER_ID = '5e470000-0000-4000-8000-00000000a001';
const SENTINEL_CAMPAIGN_ID   = '5e470000-0000-4000-8000-00000000c001';
// Sentinel line_item and creative — same seed files (is_house=true via advertiser chain).
const SENTINEL_LINE_ITEM_ID  = '5e470000-0000-4000-8000-00000000f001';
const SENTINEL_CREATIVE_ID   = '5e470000-0000-4000-8000-00000000e001';

// Dev advertiser campaign — non-house, allows any bid.
const DEV_CAMPAIGN_ID = 'ca000000-0000-0000-0000-000000000001';

// Publisher A — dev seed "real publisher" (T12 calls close_window as PUB_A).
const PUB_A = {
  sub:          '11111111-1111-1111-1111-111111111111',
  publisher_id: 'a1a1a1a1-0000-0000-0000-000000000001',
  device_id:    'd1d1d1d1-0000-0000-0000-000000000001',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function isReachable() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 1500);
  try {
    const res = await fetch(`${BASE}/`, {
      headers: { apikey: ANON },
      signal: ctrl.signal,
    });
    return res.status >= 200 && res.status < 500;
  } catch { return false; }
  finally { clearTimeout(timer); }
}

async function svcSelect(path) {
  const res = await fetch(`${BASE}/${path}`, {
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`GET ${path} -> HTTP ${res.status}: ${text}`);
  return JSON.parse(text);
}

// Attempt a service-role INSERT on line_items.  Returns { ok, status, body }.
async function tryInsertLineItem(row) {
  const res = await fetch(`${BASE}/line_items`, {
    method: 'POST',
    headers: {
      apikey: SERVICE,
      Authorization: `Bearer ${SERVICE}`,
      'content-type': 'application/json',
      Prefer: 'return=minimal',
    },
    body: JSON.stringify(row),
  });
  const body = await res.text();
  return { ok: res.ok, status: res.status, body };
}

// Mint a HS256 device JWT (matches the dev Supabase JWT secret).
// Same implementation as serving.integration.mjs — duplicated here to keep this
// file self-contained.
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

// Call a SECURITY DEFINER RPC via the PostgREST API.
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

// ---------------------------------------------------------------------------
// Stack reachability guard (same pattern as serving.integration.mjs)
// ---------------------------------------------------------------------------
const UP = await isReachable();
if (!UP) {
  console.log(
    `[sentinel.integration] PostgREST unreachable at ${BASE} — SKIPPING ` +
      `(offline node --test unit suite stays green).`,
  );
}

// ---------------------------------------------------------------------------
// T8: Sentinel advertiser has is_house=true after M2-T2 migration.
// ---------------------------------------------------------------------------
test('T8 — sentinel advertiser has is_house=true after M2-T2 migration', {
  skip: !UP ? `PostgREST unreachable at ${BASE}` : false,
}, async () => {
  const rows = await svcSelect(
    `advertisers?id=eq.${SENTINEL_ADVERTISER_ID}&select=id,name,is_house`,
  );
  assert.equal(rows.length, 1, 'sentinel advertiser row must exist in DB');
  assert.equal(rows[0].is_house, true,
    'sentinel advertiser MUST have is_house=true (M2-T2 migration or seed update)');
});

// ---------------------------------------------------------------------------
// T9: INSERT a line_item with cpva_bid_micros>0 under the house campaign must fail.
//
// The check_house_bids() CHECK constraint should reject this with a 23514
// check_violation, which PostgREST maps to HTTP 400.
// ---------------------------------------------------------------------------
test('T9 — inserting non-zero bid on house line_item raises CHECK constraint violation', {
  skip: !UP ? `PostgREST unreachable at ${BASE}` : false,
}, async () => {
  const { ok, status, body } = await tryInsertLineItem({
    campaign_id:      SENTINEL_CAMPAIGN_ID,
    cpva_bid_micros:  1000,    // non-zero CPVA bid under a house advertiser — must be rejected
    cpc_bid_micros:   0,
    status:           'draft',
  });
  assert.equal(ok, false,
    `INSERT with cpva_bid_micros=1000 on house campaign must fail (got HTTP ${status})`);
  // PostgreSQL check_violation (23514) → PostgREST returns 400.
  // Also accept 409 in case future PostgREST versions remap this.
  assert.ok(
    status === 400 || status === 409,
    `Expected 400 (check_violation) but got ${status}. Body: ${body}`,
  );
  // Confirm the right constraint name appears in the error.
  assert.ok(
    body.includes('line_items_house_bids_zero'),
    `Error body should name the constraint 'line_items_house_bids_zero'. Got: ${body}`,
  );
});

// ---------------------------------------------------------------------------
// T10: INSERT a line_item with cpva=0,cpc=0 under the house campaign must succeed.
//
// Zero-bid self-promo is the intended sentinel use-case; the CHECK must allow it.
// We clean up the inserted row in the finally block.
// ---------------------------------------------------------------------------
test('T10 — zero-bid line_item under house campaign is allowed by CHECK constraint', {
  skip: !UP ? `PostgREST unreachable at ${BASE}` : false,
}, async () => {
  const { ok, status, body } = await tryInsertLineItem({
    campaign_id:      SENTINEL_CAMPAIGN_ID,
    cpva_bid_micros:  0,
    cpc_bid_micros:   0,
    status:           'draft',
  });
  // We expect success (HTTP 201 Created or 200).
  // If it fails, read back why.
  assert.ok(ok,
    `INSERT with cpva=0,cpc=0 on house campaign should succeed. HTTP ${status}: ${body}`);

  // Cleanup: delete the test row we just inserted (avoid polluting the sentinel campaign).
  if (ok) {
    // The row was inserted with no explicit id, so find and delete by campaign+status+bid.
    await fetch(
      `${BASE}/line_items?campaign_id=eq.${SENTINEL_CAMPAIGN_ID}&status=eq.draft&cpva_bid_micros=eq.0`,
      {
        method: 'DELETE',
        headers: {
          apikey: SERVICE,
          Authorization: `Bearer ${SERVICE}`,
          Prefer: 'return=minimal',
        },
      },
    );
  }
});

// ---------------------------------------------------------------------------
// T11: Non-house advertiser allows any bid (no false positives from the CHECK).
// ---------------------------------------------------------------------------
test('T11 — non-zero bid on non-house campaign is allowed (no false positive)', {
  skip: !UP ? `PostgREST unreachable at ${BASE}` : false,
}, async () => {
  const { ok, status, body } = await tryInsertLineItem({
    campaign_id:      DEV_CAMPAIGN_ID,
    cpva_bid_micros:  99999,   // high bid — must be accepted for non-house advertisers
    cpc_bid_micros:   50000,
    status:           'draft',
  });
  assert.ok(ok,
    `INSERT with high bid on non-house campaign should succeed. HTTP ${status}: ${body}`);

  // Cleanup: delete the test row.
  if (ok) {
    await fetch(
      `${BASE}/line_items?campaign_id=eq.${DEV_CAMPAIGN_ID}&status=eq.draft&cpva_bid_micros=eq.99999`,
      {
        method: 'DELETE',
        headers: {
          apikey: SERVICE,
          Authorization: `Bearer ${SERVICE}`,
          Prefer: 'return=minimal',
        },
      },
    );
  }
});

// ---------------------------------------------------------------------------
// T12: Billing guard in close_window forces gross=0 for house line_items
//      even when clearing_price_micros is non-zero.
//
// WHY: The CHECK constraint (layer 2) prevents non-zero bids from being stored
// on house line_items. This means in normal operation the billing guard (layer 3)
// in close_window is structurally unreachable — clearing_price_micros is always 0
// for house windows. This test bypasses the CHECK by inserting an ad_windows row
// directly via service_role with clearing_price_micros=1, then verifies that
// close_window still zeroes the gross. The guard is the last line of defence for
// Trust Invariant #4: "Honest billing — the sentinel-never-bills guarantee."
//
// HOW the bypass works:
//   The CHECK constraint fires on INSERT/UPDATE to line_items. The ad_windows
//   table stores clearing_price_micros directly (locked at window_open from the
//   line_item bid). By skipping window_open and inserting into ad_windows directly,
//   we can set clearing_price_micros=1 for a house line_item's window without ever
//   touching line_items — no CHECK fires, no constraint to bypass.
//
// SETUP details:
//   publisher_id + device_id = PUB_A (active device, JWT auth in close_window passes)
//   line_item_id = SENTINEL_LINE_ITEM_ID (advertiser is_house=true → billing guard fires)
//   creative_id  = SENTINEL_CREATIVE_ID  (non-null: must reach billing code, not no-fill path)
//   beats_count  = 5, activity_progress = true, started_at = 10s ago: pass all quality gates
// ---------------------------------------------------------------------------
test('T12 — billing guard forces gross=0 for house line_item even with non-zero clearing_price_micros', {
  skip: !UP ? `PostgREST unreachable at ${BASE}` : false,
}, async () => {
  const windowId = randomUUID();

  // Step 1: Direct service-role INSERT into ad_windows with non-zero clearing_price_micros.
  // This bypasses window_open entirely. The ad_windows table has no CHECK constraint on
  // clearing_price_micros — only line_items has the house_bids_zero CHECK.
  const insertRes = await fetch(`${BASE}/ad_windows`, {
    method: 'POST',
    headers: {
      apikey: SERVICE,
      Authorization: `Bearer ${SERVICE}`,
      'content-type': 'application/json',
      Prefer: 'return=minimal',
    },
    body: JSON.stringify({
      window_id:             windowId,
      publisher_id:          PUB_A.publisher_id,    // JWT auth in close_window must match
      device_id:             PUB_A.device_id,        // active, unrevoked device in seed.sql
      line_item_id:          SENTINEL_LINE_ITEM_ID,  // house advertiser (is_house=true)
      creative_id:           SENTINEL_CREATIVE_ID,   // non-null: reaches billing code, not no-fill
      challenge:             'deadbeefdeadbeefdeadbeef',
      nonce:                 'cafebabecafebabe',
      beats_count:           5,                      // >= 3: passes dwell quality gate
      activity_progress:     true,                   // passes activity gate
      started_at:            new Date(Date.now() - 10_000).toISOString(), // 10s ago > dwell_ms=5000
      dwell_ms:              5000,
      state:                 'open',
      clearing_price_micros: 1,                      // NON-ZERO — the whole point of this test
    }),
  });

  if (!insertRes.ok) {
    const body = await insertRes.text();
    throw new Error(`T12 setup: direct ad_windows INSERT failed: HTTP ${insertRes.status}: ${body}`);
  }

  // Step 2: Call close_window as PUB_A (publisher_id matches the inserted row).
  const jwt = mintDeviceJwt(PUB_A);
  const result = await rpc('close_window', { p_window_id: windowId }, { jwt });

  // Step 3: The billing guard must have fired. close_window:
  //   v_gross = v_att * 1 (non-zero from clearing_price_micros=1)
  //   → PERFORM FROM line_items JOIN campaigns JOIN advertisers WHERE is_house=true → FOUND
  //   → v_gross := 0   (guard zeroes it)
  //   → INSERT impressions with gross_micros=0
  //   → RETURN {credited:true, gross_micros:0, reason:'ok'}
  assert.equal(result.gross_micros, 0,
    `billing guard must force gross_micros=0 for house line_item (got ${result.gross_micros}); ` +
    `clearing_price_micros was 1 — guard must have zeroed it`);

  // The window should credit successfully (quality gates all passed).
  // If reason != 'ok' the setup failed (device revoked, dwell short, beat count, etc).
  assert.equal(result.reason, 'ok',
    `close_window should credit (reason=ok) — all quality gates were satisfied in setup; ` +
    `got reason=${result.reason}. Check beats_count, activity_progress, started_at, device.`);

  assert.equal(result.credited, true,
    `credited should be true (window passed quality gates); got credited=${result.credited}`);

  // Cleanup: delete the test impression row inserted by close_window.
  await fetch(`${BASE}/impressions?window_id=eq.${windowId}`, {
    method: 'DELETE',
    headers: {
      apikey: SERVICE,
      Authorization: `Bearer ${SERVICE}`,
      Prefer: 'return=minimal',
    },
  });
});
