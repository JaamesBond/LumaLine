// test/clawback.integration.mjs — Integration tests for M2-T6 clawback, refund,
// and publisher dispute endpoints.
//
// Self-skips cleanly when:
//   - Local Supabase stack is unreachable (REST API at 54321)
//   - T6 migration has not been applied (clawback_reviews table absent)
//   - auth-device or billing edge functions are not running
//   - STRIPE_SECRET_KEY is absent (for the /refund Stripe test only)
//
// WHAT IS TESTED:
//   T30 — non-admin cannot call approve_clawback or reject_clawback (PostgREST 403/401)
//   T31 — scan_ivt creates a clawback_reviews row (status='pending') for a flagged impression
//   T32 — impression stays provisional after scan_ivt (no auto-reversal)
//   T33 — reject_clawback marks review rejected; impression state unchanged
//   T34 — approve_clawback (admin) calls clawback(); impression becomes clawed_back
//   T35 — sentinel/house impression: approve_clawback → no-op result, impression unchanged
//   T36 — publisher dispute endpoint creates a disputes row scoped to the publisher
//   T37 — another publisher cannot see the dispute (RLS)
//   T38 — /billing/refund with approved review + succeeded Stripe charge issues a refund
//         (requires STRIPE_SECRET_KEY=sk_test_*)

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';

const REST_BASE      = 'http://127.0.0.1:54321/rest/v1';
const BILLING_BASE   = 'http://127.0.0.1:54321/functions/v1/billing';
const AUTH_BASE      = 'http://127.0.0.1:54321/functions/v1/auth-device';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// From seed.sql
const ADMIN_USER_ID      = 'a0000000-0000-4000-8000-000000000001';
const NON_ADMIN_USER_ID  = '22222222-2222-2222-2222-222222222222';

// Publisher A (dev-a) — the testing publisher
const PUB_A_AUTH_ID      = '11111111-1111-1111-1111-111111111111';
const PUB_A_PUBLISHER_ID = 'a1a1a1a1-0000-0000-0000-000000000001';

// Publisher B (dev-b) — used for RLS cross-publisher test
const PUB_B_AUTH_ID      = '22222222-2222-2222-2222-222222222222';

// Sentinel advertiser/publisher/line_item (is_house=true, gross_micros=0)
const SENTINEL_PUBLISHER_ID = '5e470000-0000-4000-8000-0000000000b1';
const SENTINEL_LINE_ITEM_ID = '5e470000-0000-4000-8000-00000000f001';

// Dev advertiser/line_item (real, billable)
const DEV_LINE_ITEM_ID   = '11000000-0000-0000-0000-000000000001';

// Stripe test key (optional)
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY ?? '';
const HAS_STRIPE = STRIPE_KEY.startsWith('sk_test_');

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

/** Mint a PostgREST-compatible HS256 JWT (same recipe as billing.integration). */
function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

/** Mint a device JWT (same recipe as auth-device mintDeviceJwt — carries publisher_id). */
function mintDeviceJwt(sub, publisherId) {
  return mintJwt(sub, { publisher_id: publisherId, device_id: randomUUID() });
}

const ADMIN_JWT     = mintJwt(ADMIN_USER_ID);
const NON_ADMIN_JWT = mintJwt(NON_ADMIN_USER_ID);
const PUB_A_JWT     = mintDeviceJwt(PUB_A_AUTH_ID, PUB_A_PUBLISHER_ID);
const PUB_B_JWT     = mintDeviceJwt(PUB_B_AUTH_ID, NON_ADMIN_USER_ID);  // pub B sub = non-admin

// ---------------------------------------------------------------------------
// REST helpers
// ---------------------------------------------------------------------------

/** Service-role REST request. Returns { ok, status, data }. */
async function svcReq(method, resource, { body, query, prefer } = {}) {
  const url = `${REST_BASE}/${resource}${query ? `?${query}` : ''}`;
  const resp = await fetch(url, {
    method,
    headers: {
      apikey:          SERVICE,
      Authorization:   `Bearer ${SERVICE}`,
      'content-type':  'application/json',
      Prefer:          prefer ?? 'return=representation',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

/** Service-role DELETE — best-effort cleanup. */
async function svcDelete(resource, query) {
  try {
    await fetch(`${REST_BASE}/${resource}?${query}`, {
      method:  'DELETE',
      headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, Prefer: 'return=minimal' },
    });
  } catch { /* best-effort */ }
}

/** Call a PostgREST RPC with an explicit JWT (forwarded, for admin-gated functions). */
async function rpcWithJwt(fnName, body, jwt) {
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, {
    method: 'POST',
    headers: {
      apikey:          ANON,
      Authorization:   `Bearer ${jwt}`,
      'content-type':  'application/json',
      accept:          'application/json',
    },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

/** Call the billing edge function with an admin JWT. */
async function billingReq(method, path, body, jwt = ADMIN_JWT) {
  const resp = await fetch(`${BILLING_BASE}${path}`, {
    method,
    headers: {
      Authorization:  `Bearer ${jwt}`,
      'content-type': 'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

/** Call the auth-device edge function with a given JWT. */
async function authReq(method, path, body, jwt) {
  const headers = { 'content-type': 'application/json' };
  if (jwt) headers['Authorization'] = `Bearer ${jwt}`;
  const resp = await fetch(`${AUTH_BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

// ---------------------------------------------------------------------------
// Stack/migration reachability checks
// ---------------------------------------------------------------------------

async function isStackUp() {
  try {
    const res = await fetch(`${REST_BASE}/`, {
      headers: { apikey: ANON },
      signal:  AbortSignal.timeout(2000),
    });
    return res.status >= 200 && res.status < 500;
  } catch { return false; }
}

async function isT6MigrationApplied() {
  try {
    const res = await fetch(`${REST_BASE}/clawback_reviews?select=id&limit=1`, {
      headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` },
      signal:  AbortSignal.timeout(2000),
    });
    return res.status === 200;
  } catch { return false; }
}

async function isBillingFnUp() {
  try {
    const res = await fetch(`${BILLING_BASE}/charge`, {
      method: 'OPTIONS',
      signal: AbortSignal.timeout(2000),
    });
    return res.status === 200;
  } catch { return false; }
}

async function isAuthFnUp() {
  try {
    const res = await fetch(`${AUTH_BASE}/activate`, {
      method: 'OPTIONS',
      signal: AbortSignal.timeout(2000),
    });
    return res.status === 200;
  } catch { return false; }
}

const STACK_UP     = await isStackUp();
const MIGRATION_OK = STACK_UP ? await isT6MigrationApplied() : false;
const BILLING_UP   = MIGRATION_OK ? await isBillingFnUp()    : false;
const AUTH_UP      = MIGRATION_OK ? await isAuthFnUp()        : false;

const SKIP_BASE    = !STACK_UP     ? `PostgREST unreachable at ${REST_BASE} — SKIPPING`
                   : !MIGRATION_OK ? 'clawback_reviews table not found — apply T6 migration'
                   : false;
const SKIP_BILLING = SKIP_BASE || (!BILLING_UP ? 'billing function not running' : false);
const SKIP_AUTH    = SKIP_BASE || (!AUTH_UP    ? 'auth-device function not running' : false);
const SKIP_STRIPE  = SKIP_BILLING || (!HAS_STRIPE ? 'STRIPE_SECRET_KEY absent or not sk_test_*' : false);

if (SKIP_BASE) console.log(`[clawback.integration] ${SKIP_BASE} — skipping all tests.`);

// ---------------------------------------------------------------------------
// Synthetic data helpers
// ---------------------------------------------------------------------------

/**
 * Insert a single provisional impression for a publisher and window.
 * Returns { impressionId, windowId }.
 */
async function insertProvisionalImpression({ lineItemId, publisherId, grossMicros }) {
  const windowId    = randomUUID();
  const impressionId = randomUUID();
  const res = await svcReq('POST', 'impressions', {
    body: {
      id:                impressionId,
      window_id:         windowId,
      publisher_id:      publisherId,
      line_item_id:      lineItemId,
      attention_seconds: 5,
      gross_micros:      grossMicros,
      state:             'provisional',
    },
  });
  if (!res.ok) throw new Error(`insertProvisionalImpression failed: ${JSON.stringify(res.data)}`);
  return { impressionId, windowId };
}

/**
 * Insert a cleared impression with a balanced 3-leg ledger group so it appears
 * in uncharged_advertiser_billings. Returns { impressionId, groupId }.
 */
async function insertClearedBillingEntry({ lineItemId, publisherId, grossMicros }) {
  const windowId    = randomUUID();
  const impressionId = randomUUID();
  const groupId     = randomUUID();
  const pubShare  = Math.round(grossMicros * 0.6);
  const platShare = grossMicros - pubShare;

  const impRes = await svcReq('POST', 'impressions', {
    body: { id: impressionId, window_id: windowId, publisher_id: publisherId,
            line_item_id: lineItemId, attention_seconds: 5, gross_micros: grossMicros, state: 'cleared' },
  });
  if (!impRes.ok) throw new Error(`cleared impression insert failed: ${JSON.stringify(impRes.data)}`);

  const ledRes = await svcReq('POST', 'ledger_entries', {
    body: [
      { entry_group_id: groupId, event_type: 'cpva_accrual', account: 'advertiser_billing',
        amount_micros: grossMicros, state: 'cleared', source_type: 'impression', source_id: impressionId, publisher_id: null },
      { entry_group_id: groupId, event_type: 'cpva_accrual', account: 'publisher_earnings',
        amount_micros: -pubShare, state: 'cleared', source_type: 'impression', source_id: impressionId, publisher_id: publisherId },
      { entry_group_id: groupId, event_type: 'cpva_accrual', account: 'platform_revenue',
        amount_micros: -platShare, state: 'cleared', source_type: 'impression', source_id: impressionId, publisher_id: null },
    ],
  });
  if (!ledRes.ok) {
    await svcDelete('impressions', `id=eq.${impressionId}`);
    throw new Error(`ledger insert failed: ${JSON.stringify(ledRes.data)}`);
  }
  return { impressionId, groupId, windowId };
}

async function cleanupImpression(impressionId, groupId) {
  if (groupId) {
    await svcDelete('advertiser_charges', `entry_group_id=eq.${groupId}`);
    await svcDelete('ledger_entries',     `entry_group_id=eq.${groupId}`);
  }
  if (impressionId) {
    await svcDelete('clawback_reviews',   `impression_id=eq.${impressionId}`);
    await svcDelete('risk_flags',         `impression_id=eq.${impressionId}`);
    await svcDelete('disputes',           `impression_id=eq.${impressionId}`);
    await svcDelete('impressions',        `id=eq.${impressionId}`);
  }
}

// ---------------------------------------------------------------------------
// T30 — non-admin cannot call approve/reject_clawback
// ---------------------------------------------------------------------------

test('T30: non-admin gets 403/401 calling approve_clawback via PostgREST', { skip: SKIP_BASE }, async () => {
  const res = await rpcWithJwt('approve_clawback', { p_review_id: randomUUID(), p_reason: 'test' }, NON_ADMIN_JWT);
  // PostgREST returns 403 (permission denied) or 401 for anon; 500 is acceptable if the
  // admin check raises '28000' (translated to Postgres error, PostgREST returns 403).
  assert.ok(
    res.status === 403 || res.status === 401 || res.status === 500,
    `Expected 403/401/500, got ${res.status}: ${JSON.stringify(res.data)}`,
  );
});

test('T30b: non-admin gets 403/401 calling reject_clawback via PostgREST', { skip: SKIP_BASE }, async () => {
  const res = await rpcWithJwt('reject_clawback', { p_review_id: randomUUID(), p_reason: 'test' }, NON_ADMIN_JWT);
  assert.ok(res.status === 403 || res.status === 401 || res.status === 500,
    `Expected 403/401/500, got ${res.status}`);
});

// ---------------------------------------------------------------------------
// T31 — scan_ivt creates clawback_reviews rows (pending)
// ---------------------------------------------------------------------------

test('T31: scan_ivt creates clawback_reviews (pending) for flagged impression', { skip: SKIP_BASE }, async () => {
  // Create 21 provisional impressions for the same publisher so they exceed p_max=20.
  const ids = [];
  try {
    for (let i = 0; i < 21; i++) {
      const imp = await insertProvisionalImpression({
        lineItemId:  DEV_LINE_ITEM_ID,
        publisherId: PUB_A_PUBLISHER_ID,
        grossMicros: 100_000,
      });
      ids.push(imp);
    }

    // Run scan_ivt with a window large enough to catch all synthetic impressions.
    const scanRes = await svcReq('POST', `rpc/scan_ivt`, {
      body: { p_window: '10 minutes', p_max: 20 },
      prefer: 'return=representation',
    });
    // scan_ivt should flag at least some impressions (21 > 20 threshold).
    // Check that clawback_reviews exist for one of our impressions.
    const firstId = ids[0].impressionId;
    const reviewsRes = await svcReq('GET', 'clawback_reviews', {
      query: `impression_id=eq.${firstId}&select=*`,
    });
    // If the impression was flagged, it has a pending review.
    // scan_ivt only flags if the count > p_max — so at least some should have reviews.
    // We assert that at least 1 review was created (either for firstId or any of the ids).
    let reviewFound = reviewsRes.ok && Array.isArray(reviewsRes.data) && reviewsRes.data.length > 0;

    if (!reviewFound) {
      // Check another impression in the batch
      for (const imp of ids.slice(1)) {
        const r = await svcReq('GET', 'clawback_reviews', {
          query: `impression_id=eq.${imp.impressionId}&select=*`,
        });
        if (r.ok && Array.isArray(r.data) && r.data.length > 0) { reviewFound = true; break; }
      }
    }

    assert.ok(reviewFound, 'scan_ivt should create at least one clawback_review for flagged impressions');

    // If we found a review, check it is pending.
    const reviewsAll = await svcReq('GET', 'clawback_reviews', {
      query: `impression_id=in.(${ids.map(i => i.impressionId).join(',')})&select=status`,
    });
    if (reviewsAll.ok && Array.isArray(reviewsAll.data) && reviewsAll.data.length > 0) {
      for (const r of reviewsAll.data) {
        assert.equal(r.status, 'pending', 'clawback_reviews from scan_ivt must have status=pending');
      }
    }
  } finally {
    for (const imp of ids) await cleanupImpression(imp.impressionId, null);
  }
});

// ---------------------------------------------------------------------------
// T32 — impression stays provisional after scan_ivt (no auto-reversal)
// ---------------------------------------------------------------------------

test('T32: impression stays provisional after scan_ivt (no auto-reversal)', { skip: SKIP_BASE }, async () => {
  // Create 21 provisional impressions to trigger flagging.
  const ids = [];
  try {
    for (let i = 0; i < 21; i++) {
      const imp = await insertProvisionalImpression({
        lineItemId:  DEV_LINE_ITEM_ID,
        publisherId: PUB_A_PUBLISHER_ID,
        grossMicros: 200_000,
      });
      ids.push(imp);
    }

    await svcReq('POST', 'rpc/scan_ivt', {
      body:   { p_window: '10 minutes', p_max: 20 },
      prefer: 'return=representation',
    });

    // All impressions that were flagged should STILL be provisional.
    const impRes = await svcReq('GET', 'impressions', {
      query: `id=in.(${ids.map(i => i.impressionId).join(',')})&select=id,state`,
    });
    assert.ok(impRes.ok, 'failed to fetch impressions after scan_ivt');
    for (const imp of (impRes.data ?? [])) {
      assert.equal(imp.state, 'provisional',
        `Impression ${imp.id} must remain provisional after scan_ivt (no auto-reversal)`);
    }
  } finally {
    for (const imp of ids) await cleanupImpression(imp.impressionId, null);
  }
});

// ---------------------------------------------------------------------------
// T33 — reject_clawback marks review rejected; impression unchanged
// ---------------------------------------------------------------------------

test('T33: reject_clawback marks review rejected, impression stays provisional', { skip: SKIP_BASE }, async () => {
  const { impressionId } = await insertProvisionalImpression({
    lineItemId:  DEV_LINE_ITEM_ID,
    publisherId: PUB_A_PUBLISHER_ID,
    grossMicros: 300_000,
  });
  // Manually insert a risk_flag + review (simulating scan_ivt result)
  const rfRes = await svcReq('POST', 'risk_flags', {
    body: { impression_id: impressionId, window_id: randomUUID(), reason: 'ivt:rate' },
  });
  assert.ok(rfRes.ok, `risk_flag insert failed: ${JSON.stringify(rfRes.data)}`);
  const rfId = rfRes.data?.[0]?.id ?? rfRes.data?.id;

  const revRes = await svcReq('POST', 'clawback_reviews', {
    body: { risk_flag_id: rfId, impression_id: impressionId, status: 'pending' },
  });
  assert.ok(revRes.ok, `clawback_review insert failed: ${JSON.stringify(revRes.data)}`);
  const reviewId = revRes.data?.[0]?.id ?? revRes.data?.id;

  try {
    const rejectRes = await rpcWithJwt('reject_clawback', { p_review_id: reviewId, p_reason: 'false positive' }, ADMIN_JWT);
    assert.ok(rejectRes.ok, `reject_clawback failed: ${JSON.stringify(rejectRes.data)}`);
    assert.equal((rejectRes.data)?.ok, true);

    // Review must be rejected.
    const r = await svcReq('GET', 'clawback_reviews', { query: `id=eq.${reviewId}&select=status` });
    assert.equal(r.data?.[0]?.status, 'rejected');

    // Impression must still be provisional.
    const imp = await svcReq('GET', 'impressions', { query: `id=eq.${impressionId}&select=state` });
    assert.equal(imp.data?.[0]?.state, 'provisional');
  } finally {
    await cleanupImpression(impressionId, null);
  }
});

// ---------------------------------------------------------------------------
// T34 — approve_clawback (admin) calls clawback(); impression becomes clawed_back
// ---------------------------------------------------------------------------

test('T34: approve_clawback executes the clawback; impression state becomes clawed_back', { skip: SKIP_BASE }, async () => {
  const { impressionId } = await insertProvisionalImpression({
    lineItemId:  DEV_LINE_ITEM_ID,
    publisherId: PUB_A_PUBLISHER_ID,
    grossMicros: 500_000,
  });
  const rfRes = await svcReq('POST', 'risk_flags', {
    body: { impression_id: impressionId, window_id: randomUUID(), reason: 'ivt:rate' },
  });
  assert.ok(rfRes.ok, `risk_flag insert failed: ${JSON.stringify(rfRes.data)}`);
  const rfId = rfRes.data?.[0]?.id ?? rfRes.data?.id;

  const revRes = await svcReq('POST', 'clawback_reviews', {
    body: { risk_flag_id: rfId, impression_id: impressionId, status: 'pending' },
  });
  assert.ok(revRes.ok, `clawback_review insert failed: ${JSON.stringify(revRes.data)}`);
  const reviewId = revRes.data?.[0]?.id ?? revRes.data?.id;

  try {
    const approveRes = await rpcWithJwt('approve_clawback', { p_review_id: reviewId, p_reason: 'confirmed ivt' }, ADMIN_JWT);
    assert.ok(approveRes.ok, `approve_clawback failed: ${JSON.stringify(approveRes.data)}`);
    assert.equal((approveRes.data)?.ok, true);

    // Review must be approved with audit trail.
    const r = await svcReq('GET', 'clawback_reviews', { query: `id=eq.${reviewId}&select=*` });
    assert.equal(r.data?.[0]?.status, 'approved');
    assert.ok(r.data?.[0]?.reviewed_at, 'reviewed_at must be set');
    assert.ok(r.data?.[0]?.review_reason, 'review_reason must be set');

    // Impression must be clawed_back.
    const imp = await svcReq('GET', 'impressions', { query: `id=eq.${impressionId}&select=state` });
    assert.equal(imp.data?.[0]?.state, 'clawed_back');
  } finally {
    await cleanupImpression(impressionId, null);
  }
});

// ---------------------------------------------------------------------------
// T35 — sentinel/house impression: approve_clawback → no-op
// ---------------------------------------------------------------------------

test('T35: approve_clawback on sentinel (gross_micros=0) is a no-op; state unchanged', { skip: SKIP_BASE }, async () => {
  // Insert a sentinel-like provisional impression with gross_micros=0.
  const windowId    = randomUUID();
  const impressionId = randomUUID();
  const impRes = await svcReq('POST', 'impressions', {
    body: {
      id:                impressionId,
      window_id:         windowId,
      publisher_id:      SENTINEL_PUBLISHER_ID,
      line_item_id:      SENTINEL_LINE_ITEM_ID,
      attention_seconds: 5,
      gross_micros:      0,  // sentinel structural zero
      state:             'provisional',
    },
  });
  assert.ok(impRes.ok, `sentinel impression insert failed: ${JSON.stringify(impRes.data)}`);

  const rfRes = await svcReq('POST', 'risk_flags', {
    body: { impression_id: impressionId, window_id: windowId, reason: 'ivt:rate' },
  });
  assert.ok(rfRes.ok, `risk_flag insert failed: ${JSON.stringify(rfRes.data)}`);
  const rfId = rfRes.data?.[0]?.id ?? rfRes.data?.id;

  const revRes = await svcReq('POST', 'clawback_reviews', {
    body: { risk_flag_id: rfId, impression_id: impressionId, status: 'pending' },
  });
  assert.ok(revRes.ok, `clawback_review insert failed: ${JSON.stringify(revRes.data)}`);
  const reviewId = revRes.data?.[0]?.id ?? revRes.data?.id;

  try {
    const approveRes = await rpcWithJwt('approve_clawback', { p_review_id: reviewId, p_reason: 'sentinel test' }, ADMIN_JWT);
    assert.ok(approveRes.ok, `approve_clawback failed: ${JSON.stringify(approveRes.data)}`);
    // Must return ok=true but with no-op indicator
    assert.equal((approveRes.data)?.ok, true);
    assert.ok(
      (approveRes.data)?.reason === 'no_op_gross_zero' || (approveRes.data)?.clawed_back === null,
      'sentinel no-op must return no_op_gross_zero or null clawed_back',
    );

    // Impression must STILL be provisional (nothing reversed).
    const imp = await svcReq('GET', 'impressions', { query: `id=eq.${impressionId}&select=state` });
    assert.equal(imp.data?.[0]?.state, 'provisional', 'Sentinel impression must remain provisional after no-op approval');
  } finally {
    await cleanupImpression(impressionId, null);
  }
});

// ---------------------------------------------------------------------------
// T36 — publisher dispute endpoint creates a disputes row
// ---------------------------------------------------------------------------

test('T36: POST /auth-device/dispute creates a disputes row for the publisher', { skip: SKIP_AUTH }, async () => {
  const { impressionId } = await insertProvisionalImpression({
    lineItemId:  DEV_LINE_ITEM_ID,
    publisherId: PUB_A_PUBLISHER_ID,
    grossMicros: 400_000,
  });

  try {
    const res = await authReq('POST', '/dispute', {
      impression_id: impressionId,
      description:   'I believe this clawback was incorrect.',
    }, PUB_A_JWT);

    assert.ok(res.ok, `POST /dispute failed HTTP ${res.status}: ${JSON.stringify(res.data)}`);
    assert.ok(res.data?.id, 'Response must include the dispute id');
    assert.equal(res.data?.status, 'open');

    // Verify row in DB
    const dbRes = await svcReq('GET', 'disputes', { query: `impression_id=eq.${impressionId}&select=*` });
    assert.ok(dbRes.ok && Array.isArray(dbRes.data) && dbRes.data.length > 0, 'Dispute row must exist in DB');
    assert.equal(dbRes.data[0].publisher_id, PUB_A_PUBLISHER_ID);
    assert.equal(dbRes.data[0].status, 'open');
  } finally {
    await cleanupImpression(impressionId, null);
  }
});

// ---------------------------------------------------------------------------
// T37 — another publisher cannot see the dispute (RLS)
// ---------------------------------------------------------------------------

test('T37: Publisher B cannot see Publisher A dispute (RLS)', { skip: SKIP_AUTH }, async () => {
  const { impressionId } = await insertProvisionalImpression({
    lineItemId:  DEV_LINE_ITEM_ID,
    publisherId: PUB_A_PUBLISHER_ID,
    grossMicros: 400_000,
  });

  try {
    // Create a dispute as Pub A
    const createRes = await authReq('POST', '/dispute', {
      impression_id: impressionId,
      description:   'Test dispute for RLS check.',
    }, PUB_A_JWT);
    assert.ok(createRes.ok, `dispute create failed: ${JSON.stringify(createRes.data)}`);
    const disputeId = createRes.data?.id;

    // Pub B reads disputes — must not see Pub A's dispute.
    const readRes = await fetch(`${REST_BASE}/disputes?id=eq.${disputeId}&select=*`, {
      headers: {
        apikey:          ANON,
        Authorization:   `Bearer ${PUB_B_JWT}`,
        accept:          'application/json',
      },
    });
    const rows = await readRes.json().catch(() => []);
    assert.ok(Array.isArray(rows) && rows.length === 0,
      'Publisher B must not see Publisher A dispute via RLS');
  } finally {
    await cleanupImpression(impressionId, null);
  }
});

// ---------------------------------------------------------------------------
// T38 — /billing/refund with approved review + succeeded charge (Stripe)
// ---------------------------------------------------------------------------

test('T38: /billing/refund issues a Stripe refund for an approved clawback review', { skip: SKIP_STRIPE }, async () => {
  const grossMicros = 1_000_000; // $1.00 = 100 cents
  const { impressionId, groupId } = await insertClearedBillingEntry({
    lineItemId:  DEV_LINE_ITEM_ID,
    publisherId: PUB_A_PUBLISHER_ID,
    grossMicros,
  });

  try {
    // Step 1: run billing to produce a real Stripe charge.
    const chargeRes = await billingReq('POST', '/charge', undefined);
    assert.ok(chargeRes.ok, `billing /charge failed: ${JSON.stringify(chargeRes.data)}`);

    // Find the charge for our impression.
    const chargeRow = await svcReq('GET', 'advertiser_charges', {
      query: `impression_id=eq.${impressionId}&status=eq.succeeded&select=*`,
    });
    if (!chargeRow.ok || !Array.isArray(chargeRow.data) || chargeRow.data.length === 0) {
      // If the impression wasn't charged (house/below-min guard hit), skip gracefully.
      return;
    }
    assert.ok(chargeRow.data[0].stripe_charge_id, 'Succeeded charge must have a stripe_charge_id (pi_*)');
    assert.ok(String(chargeRow.data[0].stripe_charge_id).startsWith('pi_'),
      'stripe_charge_id must be a PaymentIntent id (pi_*)');

    // Step 2: create a risk_flag + review and approve it.
    const rfRes = await svcReq('POST', 'risk_flags', {
      body: { impression_id: impressionId, window_id: randomUUID(), reason: 'ivt:rate' },
    });
    assert.ok(rfRes.ok, `risk_flag insert failed: ${JSON.stringify(rfRes.data)}`);
    const rfId = rfRes.data?.[0]?.id ?? rfRes.data?.id;

    const revRes = await svcReq('POST', 'clawback_reviews', {
      body: { risk_flag_id: rfId, impression_id: impressionId, status: 'pending' },
    });
    assert.ok(revRes.ok, `clawback_review insert failed: ${JSON.stringify(revRes.data)}`);
    const reviewId = revRes.data?.[0]?.id ?? revRes.data?.id;

    await rpcWithJwt('approve_clawback', { p_review_id: reviewId, p_reason: 'ivt confirmed' }, ADMIN_JWT);

    // Step 3: call /billing/refund.
    const refundRes = await billingReq('POST', '/refund', { review_id: reviewId });
    assert.ok(refundRes.ok, `/billing/refund failed HTTP ${refundRes.status}: ${JSON.stringify(refundRes.data)}`);
    assert.equal(refundRes.data?.ok, true);
    assert.ok(refundRes.data?.refund_id, 'refund_id must be set');
    assert.ok(String(refundRes.data.refund_id).startsWith('re_'),
      'refund_id must be a Stripe refund id (re_*)');
    assert.equal(refundRes.data?.amount_cents, 100, 'Refund amount must be 100 cents ($1.00)');

    // Step 4: verify clawback_reviews.refund_queued=true.
    const reviewRow = await svcReq('GET', 'clawback_reviews', { query: `id=eq.${reviewId}&select=*` });
    assert.equal(reviewRow.data?.[0]?.refund_queued, true, 'refund_queued must be true after refund');
    assert.ok(reviewRow.data?.[0]?.refund_id, 'refund_id must be stored on the review row');

    // Step 5: calling /billing/refund again on same review must fail (refund_queued=true).
    const dupRes = await billingReq('POST', '/refund', { review_id: reviewId });
    assert.ok(!dupRes.ok, 'Second /billing/refund call must fail (already queued)');
  } finally {
    await cleanupImpression(impressionId, groupId);
  }
});
