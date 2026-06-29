// test/admin-booking.integration.mjs — Integration tests for M2-T3 admin-booking edge function.
//
// Tests the admin-only ad booking HTTP API:
//   POST /advertisers  — create advertiser
//   GET  /advertisers  — list advertisers
//   POST /campaigns    — create campaign
//   POST /line-items   — create line_item
//   POST /creatives    — create creative (pending_review)
//   PATCH /creatives/:id/activate — cascade status → active
//
// Self-skips cleanly when the local Supabase edge runtime is unreachable (same pattern
// as sentinel.integration.mjs so `node --test test/*.mjs` stays green offline).
//
// WHAT IS TESTED:
//   T13 Non-admin JWT is rejected with 403 on all mutation endpoints.
//   T14 Admin creates advertiser → 201, is_house=false, has id. (The critical positive
//       path: proves JWT forward + admin_check + service-role CRUD all work end-to-end.)
//   T15 Full booking chain: advertiser → campaign → line_item (draft) → creative (pending_review).
//   T16 PATCH /creatives/:id/activate cascades: creative→active, line_item→active, campaign→active.
//   T17 GET /advertisers returns a JSON array for an admin caller.
//   T18 POST /line-items with cpva>0 under a house campaign fails (is_house CHECK, M2-T2).

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

const EDGE_BASE = 'http://127.0.0.1:54321/functions/v1/admin-booking';
const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// dev-a (11111111...) is the admin user — row in app.admins via seed.sql.
const ADMIN_USER_ID    = '11111111-1111-1111-1111-111111111111';
// dev-b (22222222...) is a normal publisher, NOT an admin.
const NON_ADMIN_USER_ID = '22222222-2222-2222-2222-222222222222';
// Sentinel house campaign — M2-T2 is_house CHECK must reject non-zero bids.
const SENTINEL_CAMPAIGN_ID = '5e470000-0000-4000-8000-00000000c001';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Mint a Supabase Auth–style HS256 JWT (same secret PostgREST trusts locally). */
function mintJwt(sub) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({
    role: 'authenticated', aud: 'authenticated',
    sub, iat: 1700000000, exp: 2000000000,
  });
  const sig = createHmac('sha256', JWT_SECRET)
    .update(`${head}.${payload}`)
    .digest('base64url');
  return `${head}.${payload}.${sig}`;
}

const ADMIN_JWT     = mintJwt(ADMIN_USER_ID);
const NON_ADMIN_JWT = mintJwt(NON_ADMIN_USER_ID);

/** Check if the admin-booking edge function is deployed and answering OPTIONS with 200. */
async function isReachable() {
  try {
    const res = await fetch(`${EDGE_BASE}/advertisers`, {
      method: 'OPTIONS',
      signal: AbortSignal.timeout(2000),
    });
    // The function's OPTIONS handler returns exactly 200 with "ok" body.
    // A 404 here means the edge runtime doesn't have the function deployed yet.
    return res.status === 200;
  } catch { return false; }
}

/** Service-role DELETE helper for test cleanup. */
async function svcDelete(resource, query) {
  try {
    await fetch(`${REST_BASE}/${resource}?${query}`, {
      method: 'DELETE',
      headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, Prefer: 'return=minimal' },
    });
  } catch { /* best-effort cleanup */ }
}

// ---------------------------------------------------------------------------
// Stack reachability guard (same pattern as sentinel.integration.mjs)
// ---------------------------------------------------------------------------
const UP = await isReachable();
if (!UP) {
  console.log(
    `[admin-booking.integration] Edge function unreachable at ${EDGE_BASE} — SKIPPING ` +
    `(offline node --test suite stays green).`,
  );
}

// ---------------------------------------------------------------------------
// T13: Non-admin JWT returns 403.
// ---------------------------------------------------------------------------
test('T13 — non-admin request returns 403', {
  skip: !UP ? `Edge function unreachable at ${EDGE_BASE}` : false,
}, async () => {
  const res = await fetch(`${EDGE_BASE}/advertisers`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${NON_ADMIN_JWT}` },
    body: JSON.stringify({ name: 'Should be rejected' }),
  });
  assert.equal(res.status, 403, `Expected 403 for non-admin caller, got ${res.status}`);
});

// ---------------------------------------------------------------------------
// T14: Admin creates advertiser (the critical positive path).
//
// Validates: JWT forward → PostgREST verifies → admin_check() → app.is_admin() →
//   app.admins → authorized → service-role INSERT succeeds → 201.
// If JWT verification or app.admins setup is wrong this returns 403, not 201.
// ---------------------------------------------------------------------------
test('T14 — admin creates advertiser returns 201 (critical positive-path probe)', {
  skip: !UP ? `Edge function unreachable at ${EDGE_BASE}` : false,
}, async () => {
  let advertiserId;
  try {
    const res = await fetch(`${EDGE_BASE}/advertisers`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({ name: 'Integration Test Advertiser (T14)' }),
    });
    const body = await res.json();
    assert.equal(res.status, 201,
      `Expected 201, got ${res.status}. Body: ${JSON.stringify(body)}. ` +
      `If 403: check that seed.sql added dev-a to app.admins (run supabase db reset).`);
    assert.ok(body.id, 'Created advertiser must have an id');
    assert.equal(body.name, 'Integration Test Advertiser (T14)');
    assert.equal(body.is_house, false, 'New advertiser must not be a house advertiser');
    advertiserId = body.id;
  } finally {
    if (advertiserId) await svcDelete('advertisers', `id=eq.${advertiserId}`);
  }
});

// ---------------------------------------------------------------------------
// T15: Full booking chain — advertiser → campaign → line_item (draft) → creative (pending_review).
// ---------------------------------------------------------------------------
test('T15 — admin creates full booking chain: advertiser → campaign → line_item → creative', {
  skip: !UP ? `Edge function unreachable at ${EDGE_BASE}` : false,
}, async () => {
  let advId, campId, liId, creativeId;
  try {
    // Create advertiser.
    const advRes = await fetch(`${EDGE_BASE}/advertisers`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({ name: 'T15 Advertiser' }),
    });
    assert.equal(advRes.status, 201, `advertiser create: got ${advRes.status}`);
    advId = (await advRes.json()).id;

    // Create campaign.
    const campRes = await fetch(`${EDGE_BASE}/campaigns`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({ advertiser_id: advId, name: 'T15 Campaign' }),
    });
    assert.equal(campRes.status, 201, `campaign create: got ${campRes.status}`);
    campId = (await campRes.json()).id;

    // Create line_item — must start as draft.
    const liRes = await fetch(`${EDGE_BASE}/line-items`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({ campaign_id: campId, cpva_bid_micros: 2000, cpc_bid_micros: 0 }),
    });
    assert.equal(liRes.status, 201, `line_item create: got ${liRes.status}`);
    const li = await liRes.json();
    liId = li.id;
    assert.equal(li.status, 'draft', 'New line_item must start as draft');

    // Create creative — must start as pending_review.
    const creativeRes = await fetch(`${EDGE_BASE}/creatives`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({
        line_item_id: liId,
        line: 'T15 Test Ad — integration test creative',
        dest_url: 'https://example.com/t15',
        label: 'sponsored',
      }),
    });
    assert.equal(creativeRes.status, 201, `creative create: got ${creativeRes.status}`);
    const creative = await creativeRes.json();
    creativeId = creative.id;
    assert.equal(creative.status, 'pending_review', 'New creative must start as pending_review');
  } finally {
    if (creativeId) await svcDelete('creatives', `id=eq.${creativeId}`);
    if (liId)       await svcDelete('line_items', `id=eq.${liId}`);
    if (campId)     await svcDelete('campaigns', `id=eq.${campId}`);
    if (advId)      await svcDelete('advertisers', `id=eq.${advId}`);
  }
});

// ---------------------------------------------------------------------------
// T16: Activate creative cascades status to line_item and campaign.
// ---------------------------------------------------------------------------
test('T16 — PATCH /creatives/:id/activate cascades status to line_item and campaign', {
  skip: !UP ? `Edge function unreachable at ${EDGE_BASE}` : false,
}, async () => {
  let advId, campId, liId, creativeId;
  try {
    const advRes = await fetch(`${EDGE_BASE}/advertisers`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({ name: 'T16 Advertiser' }),
    });
    assert.equal(advRes.status, 201);
    advId = (await advRes.json()).id;

    const campRes = await fetch(`${EDGE_BASE}/campaigns`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({ advertiser_id: advId, name: 'T16 Campaign' }),
    });
    assert.equal(campRes.status, 201);
    campId = (await campRes.json()).id;

    const liRes = await fetch(`${EDGE_BASE}/line-items`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({ campaign_id: campId, cpva_bid_micros: 1500, cpc_bid_micros: 0 }),
    });
    assert.equal(liRes.status, 201);
    liId = (await liRes.json()).id;

    const creativeRes = await fetch(`${EDGE_BASE}/creatives`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
      body: JSON.stringify({
        line_item_id: liId,
        line: 'T16 Test Ad',
        dest_url: 'https://example.com/t16',
      }),
    });
    assert.equal(creativeRes.status, 201);
    creativeId = (await creativeRes.json()).id;

    // Activate — should cascade to line_item and campaign.
    const activateRes = await fetch(`${EDGE_BASE}/creatives/${creativeId}/activate`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${ADMIN_JWT}` },
    });
    const activateBody = await activateRes.json();
    assert.equal(activateRes.status, 200,
      `Activate failed: ${JSON.stringify(activateBody)}`);
    assert.equal(activateBody.status, 'active', 'Creative must be active after activate');

    // Verify line_item is active (direct service-role check).
    const liCheck = await fetch(
      `${REST_BASE}/line_items?id=eq.${liId}&select=status`,
      { headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` } },
    );
    const [liRow] = await liCheck.json();
    assert.equal(liRow.status, 'active', 'line_item must be active after creative activate');

    // Verify campaign is active.
    const campCheck = await fetch(
      `${REST_BASE}/campaigns?id=eq.${campId}&select=status`,
      { headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` } },
    );
    const [campRow] = await campCheck.json();
    assert.equal(campRow.status, 'active', 'campaign must be active after creative activate');
  } finally {
    if (creativeId) await svcDelete('creatives', `id=eq.${creativeId}`);
    if (liId)       await svcDelete('line_items', `id=eq.${liId}`);
    if (campId)     await svcDelete('campaigns', `id=eq.${campId}`);
    if (advId)      await svcDelete('advertisers', `id=eq.${advId}`);
  }
});

// ---------------------------------------------------------------------------
// T17: GET /advertisers returns a JSON array for an admin caller.
// ---------------------------------------------------------------------------
test('T17 — GET /advertisers returns JSON array for admin', {
  skip: !UP ? `Edge function unreachable at ${EDGE_BASE}` : false,
}, async () => {
  const res = await fetch(`${EDGE_BASE}/advertisers`, {
    headers: { Authorization: `Bearer ${ADMIN_JWT}` },
  });
  assert.equal(res.status, 200, `Expected 200, got ${res.status}`);
  const body = await res.json();
  assert.ok(Array.isArray(body), 'GET /advertisers must return a JSON array');
});

// ---------------------------------------------------------------------------
// T18: House advertiser CHECK constraint (M2-T2) rejects non-zero bid via edge function.
//
// The edge function POSTs to PostgREST with service-role but the DB-level CHECK
// (line_items_house_bids_zero) still fires and PostgREST forwards the 400 error.
// ---------------------------------------------------------------------------
test('T18 — POST /line-items with non-zero bid on house campaign rejected (M2-T2 CHECK)', {
  skip: !UP ? `Edge function unreachable at ${EDGE_BASE}` : false,
}, async () => {
  const res = await fetch(`${EDGE_BASE}/line-items`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
    body: JSON.stringify({
      campaign_id:     SENTINEL_CAMPAIGN_ID,
      cpva_bid_micros: 1000,   // non-zero bid on house advertiser — must be rejected
      cpc_bid_micros:  0,
    }),
  });
  assert.ok(
    res.status >= 400,
    `Expected error status (≥400) for house campaign line_item, got ${res.status}`,
  );
  // PostgREST maps CHECK violation (23514) to HTTP 400.
  assert.ok(
    res.status === 400 || res.status === 409 || res.status === 422,
    `Expected 400/409/422 for CHECK violation, got ${res.status}`,
  );
});
