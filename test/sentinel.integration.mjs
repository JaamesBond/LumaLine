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

import test from 'node:test';
import assert from 'node:assert/strict';

const BASE = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';

// Sentinel advertiser + campaign — from seed.sql / seed.prod.sql.
const SENTINEL_ADVERTISER_ID = '5e470000-0000-4000-8000-00000000a001';
const SENTINEL_CAMPAIGN_ID   = '5e470000-0000-4000-8000-00000000c001';

// Dev advertiser campaign — non-house, allows any bid.
const DEV_CAMPAIGN_ID = 'ca000000-0000-0000-0000-000000000001';

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
