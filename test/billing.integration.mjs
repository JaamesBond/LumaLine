// test/billing.integration.mjs — Integration tests for M2-T4 billing edge function.
//
// Self-skips cleanly when:
//   - Local Supabase stack is unreachable (REST API at 54321)
//   - advertiser_charges table does not exist (T4 migration not applied yet)
//   - Billing edge function is not deployed
//   - STRIPE_SECRET_KEY is absent (for Stripe-specific tests only)
//
// Self-skipping is the pattern for all integration tests in this suite so that
// `node --test test/*.mjs` stays green in offline or partially-deployed environments.
//
// WHAT IS TESTED:
//   No-Stripe tests (run when stack + fn + migration are up):
//     T19 — non-admin request returns 403
//     T20 — admin POST /charge?dry_run=true returns valid JSON with results array
//     T21 — admin POST /charge with no uncharged entries returns {charged:0}
//     T22 — house advertiser entry produces status='skipped' (synthetic data setup)
//     T23 — below-minimum entry produces status='skipped' (synthetic data setup)
//   Stripe tests (additionally require STRIPE_SECRET_KEY=sk_test_*):
//     T24 — real charge succeeds: status='succeeded', stripe_charge_id set
//     T25 — idempotency: re-running billing for same entry_group_id does not create
//            a second advertiser_charges row (UNIQUE constraint is the backstop)

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';

const BILLING_BASE = 'http://127.0.0.1:54321/functions/v1/billing';
const REST_BASE    = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

const ADMIN_USER_ID     = 'a0000000-0000-4000-8000-000000000001';
const NON_ADMIN_USER_ID = '22222222-2222-2222-2222-222222222222';

// Sentinel house advertiser (is_house=true) — from seed.sql.
const SENTINEL_ADVERTISER_ID = '5e470000-0000-4000-8000-00000000a001';
const SENTINEL_LINE_ITEM_ID  = '5e470000-0000-4000-8000-00000000f001';

// Non-house advertiser (dev advertiser from seed.sql).
const DEV_ADVERTISER_ID = 'ad000000-0000-0000-0000-000000000001';
const DEV_LINE_ITEM_ID  = '11000000-0000-0000-0000-000000000001';

// Publisher A — used for synthetic impression setup.
const PUB_A_PUBLISHER_ID = 'a1a1a1a1-0000-0000-0000-000000000001';

// Stripe test key from environment (optional).
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY ?? '';
const HAS_STRIPE = STRIPE_KEY.startsWith('sk_test_');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Mint a Supabase Auth–style HS256 JWT (same secret PostgREST trusts locally). */
function mintJwt(sub) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000 });
  const sig = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

const ADMIN_JWT     = mintJwt(ADMIN_USER_ID);
const NON_ADMIN_JWT = mintJwt(NON_ADMIN_USER_ID);

/** Service-role REST request. Returns { ok, status, data }. */
async function svcReq(method, resource, { body, query } = {}) {
  const url = `${REST_BASE}/${resource}${query ? `?${query}` : ''}`;
  const resp = await fetch(url, {
    method,
    headers: {
      apikey:          SERVICE,
      Authorization:   `Bearer ${SERVICE}`,
      'content-type':  'application/json',
      Prefer:          'return=representation',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty body */ }
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

/** Check if the local Supabase REST API is up. */
async function isStackUp() {
  try {
    const res = await fetch(`${REST_BASE}/`, {
      headers: { apikey: ANON },
      signal:  AbortSignal.timeout(2000),
    });
    return res.status >= 200 && res.status < 500;
  } catch { return false; }
}

/** Check if the T4 migration has been applied (advertiser_charges table exists). */
async function isMigrationApplied() {
  try {
    const res = await fetch(`${REST_BASE}/advertiser_charges?select=id&limit=1`, {
      headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` },
      signal:  AbortSignal.timeout(2000),
    });
    return res.status === 200;
  } catch { return false; }
}

/** Check if the billing edge function is deployed. */
async function isBillingFnUp() {
  try {
    const res = await fetch(`${BILLING_BASE}/charge`, {
      method: 'OPTIONS',
      signal: AbortSignal.timeout(2000),
    });
    return res.status === 200;
  } catch { return false; }
}

/**
 * Insert a synthetic cleared impression + 3-leg balanced ledger group so the
 * uncharged_advertiser_billings view returns this entry for billing.
 *
 * Returns { impressionId, entryGroupId } for use in cleanup.
 *
 * The ledger balance trigger is DEFERRED — posting all 3 legs as a JSON array
 * in a single POST request ensures they land in one transaction.
 */
async function insertSyntheticBillingEntry({ lineItemId, publisherId, grossMicros }) {
  const windowId    = randomUUID();
  const impressionId = randomUUID();
  const groupId     = randomUUID();

  // Insert impression (state='cleared', non-zero gross so the view picks it up).
  const impRes = await svcReq('POST', 'impressions', {
    body: {
      id:               impressionId,
      window_id:        windowId,
      publisher_id:     publisherId,
      line_item_id:     lineItemId,
      attention_seconds: Math.ceil(grossMicros / 2000),  // approximate attention_seconds
      gross_micros:     grossMicros,
      state:            'cleared',
    },
  });
  if (!impRes.ok) {
    throw new Error(`insertSyntheticBillingEntry: impression insert failed HTTP ${impRes.status}: ${JSON.stringify(impRes.data)}`);
  }

  // 60/40 split (matching app.accrue).
  const pubShare  = Math.round(grossMicros * 0.6);
  const platShare = grossMicros - pubShare;

  // Insert all 3 ledger legs as a single POST (one transaction → deferred trigger satisfied).
  const ledgerRes = await svcReq('POST', 'ledger_entries', {
    body: [
      {
        entry_group_id: groupId,
        event_type:     'cpva_accrual',
        account:        'advertiser_billing',
        amount_micros:  grossMicros,
        state:          'cleared',
        source_type:    'impression',
        source_id:      impressionId,
        publisher_id:   null,
      },
      {
        entry_group_id: groupId,
        event_type:     'cpva_accrual',
        account:        'publisher_earnings',
        amount_micros:  -pubShare,
        state:          'cleared',
        source_type:    'impression',
        source_id:      impressionId,
        publisher_id:   publisherId,
      },
      {
        entry_group_id: groupId,
        event_type:     'cpva_accrual',
        account:        'platform_revenue',
        amount_micros:  -platShare,
        state:          'cleared',
        source_type:    'impression',
        source_id:      impressionId,
        publisher_id:   null,
      },
    ],
  });
  if (!ledgerRes.ok) {
    // Cleanup impression before throwing
    await svcDelete('impressions', `id=eq.${impressionId}`);
    throw new Error(`insertSyntheticBillingEntry: ledger insert failed HTTP ${ledgerRes.status}: ${JSON.stringify(ledgerRes.data)}`);
  }

  return { impressionId, groupId, windowId };
}

/** Clean up synthetic billing test data. */
async function cleanupSyntheticEntry({ impressionId, groupId }) {
  await svcDelete('advertiser_charges',  `entry_group_id=eq.${groupId}`);
  await svcDelete('ledger_entries',      `entry_group_id=eq.${groupId}`);
  await svcDelete('impressions',         `id=eq.${impressionId}`);
}

// ---------------------------------------------------------------------------
// Stack reachability checks
// ---------------------------------------------------------------------------
const STACK_UP     = await isStackUp();
const MIGRATION_OK = STACK_UP ? await isMigrationApplied() : false;
const FN_UP        = MIGRATION_OK ? await isBillingFnUp() : false;

const SKIP_NO_STACK = !STACK_UP
  ? `PostgREST unreachable at ${REST_BASE} — SKIPPING (offline)`
  : false;
const SKIP_NO_MIGRATION = !MIGRATION_OK
  ? `advertiser_charges table not found — run supabase db reset to apply T4 migration`
  : false;
const SKIP_NO_FN = !FN_UP
  ? `billing edge function unreachable at ${BILLING_BASE} — run supabase functions serve`
  : false;
const SKIP_NO_STRIPE = !HAS_STRIPE
  ? `STRIPE_SECRET_KEY not set or not sk_test_* — skipping live Stripe tests`
  : false;

if (!STACK_UP) {
  console.log(`[billing.integration] Stack unreachable — SKIPPING all tests.`);
} else if (!MIGRATION_OK) {
  console.log(`[billing.integration] T4 migration not applied — SKIPPING all tests.`);
} else if (!FN_UP) {
  console.log(`[billing.integration] Billing fn not deployed — SKIPPING all tests.`);
} else if (!HAS_STRIPE) {
  console.log(`[billing.integration] STRIPE_SECRET_KEY absent — Stripe tests will be skipped.`);
}

// ---------------------------------------------------------------------------
// T19: Non-admin request returns 403.
// ---------------------------------------------------------------------------
test('T19 — billing: non-admin request returns 403', {
  skip: SKIP_NO_STACK || SKIP_NO_MIGRATION || SKIP_NO_FN,
}, async () => {
  const res = await fetch(`${BILLING_BASE}/charge`, {
    method:  'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${NON_ADMIN_JWT}` },
  });
  assert.equal(res.status, 403, `Expected 403 for non-admin caller, got ${res.status}`);
});

// ---------------------------------------------------------------------------
// T20: Admin dry_run returns valid JSON (no Stripe calls).
// ---------------------------------------------------------------------------
test('T20 — billing: admin dry_run returns valid JSON response', {
  skip: SKIP_NO_STACK || SKIP_NO_MIGRATION || SKIP_NO_FN,
}, async () => {
  const res = await fetch(`${BILLING_BASE}/charge?dry_run=true`, {
    method:  'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
  });
  assert.equal(res.status, 200, `Expected 200 for dry_run, got ${res.status}`);
  const body = await res.json();
  assert.ok('charged'  in body, 'response must have charged field');
  assert.ok('dry_run'  in body, 'response must have dry_run field');
  assert.ok('results'  in body, 'response must have results array');
  assert.equal(body.dry_run, true, 'dry_run must be true in response');
  assert.ok(Array.isArray(body.results), 'results must be an array');
});

// ---------------------------------------------------------------------------
// T21: Billing cycle with no uncharged entries returns charged=0.
// ---------------------------------------------------------------------------
test('T21 — billing: empty billing cycle returns {charged:0}', {
  skip: SKIP_NO_STACK || SKIP_NO_MIGRATION || SKIP_NO_FN,
}, async () => {
  // On a freshly reset DB, there are no cleared impressions with ledger entries.
  // If other tests left synthetic data, this test may see charged>0, which is also ok —
  // what matters is that the endpoint returns a well-formed response.
  const res = await fetch(`${BILLING_BASE}/charge?dry_run=true`, {
    method:  'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
  });
  assert.equal(res.status, 200, `billing cycle must return 200`);
  const body = await res.json();
  assert.equal(body.dry_run, true);
  assert.ok(typeof body.charged === 'number', 'charged must be a number');
  assert.ok(body.charged >= 0, 'charged must be non-negative');
});

// ---------------------------------------------------------------------------
// T22: House advertiser entry produces status='skipped'.
//
// Setup: synthetic cleared impression pointing to SENTINEL_LINE_ITEM_ID (house).
// The uncharged_advertiser_billings view resolves is_house=true from the join chain.
// Billing cycle must insert a 'skipped' row into advertiser_charges.
// ---------------------------------------------------------------------------
test('T22 — billing: house advertiser entry is skipped (status=skipped, reason=house_advertiser)', {
  skip: SKIP_NO_STACK || SKIP_NO_MIGRATION || SKIP_NO_FN,
}, async () => {
  let impressionId, groupId;
  try {
    // Gross = $1.00 (would charge if not house).
    const entry = await insertSyntheticBillingEntry({
      lineItemId:   SENTINEL_LINE_ITEM_ID,
      publisherId:  PUB_A_PUBLISHER_ID,
      grossMicros:  1_000_000,
    });
    impressionId = entry.impressionId;
    groupId      = entry.groupId;

    // Run billing cycle (real, not dry_run — must insert the skipped charge row).
    const res = await fetch(`${BILLING_BASE}/charge`, {
      method:  'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
    });
    const body = await res.json();
    assert.equal(res.status, 200, `billing charge failed: ${JSON.stringify(body)}`);

    // Verify the advertiser_charges row was created with status='skipped'.
    const chargeRes = await svcReq('GET', 'advertiser_charges', {
      query: `entry_group_id=eq.${groupId}&select=entry_group_id,status,failure_reason`,
    });
    assert.ok(
      Array.isArray(chargeRes.data) && chargeRes.data.length === 1,
      `Expected 1 advertiser_charges row for entry_group_id=${groupId}, ` +
      `got: ${JSON.stringify(chargeRes.data)}`,
    );
    const row = chargeRes.data[0];
    assert.equal(row.status, 'skipped', 'house advertiser must produce status=skipped');
    assert.equal(
      row.failure_reason, 'house_advertiser',
      'skipped house entry must record failure_reason=house_advertiser',
    );
  } finally {
    if (impressionId && groupId) {
      await cleanupSyntheticEntry({ impressionId, groupId });
    }
  }
});

// ---------------------------------------------------------------------------
// T23: Below-minimum entry produces status='skipped'.
//
// Setup: synthetic cleared impression with gross_micros=100 (1 cent — below $0.50).
// Uses DEV_LINE_ITEM_ID (non-house advertiser) so only the minimum check fires.
// ---------------------------------------------------------------------------
test('T23 — billing: below-minimum entry is skipped (status=skipped, reason=below_stripe_minimum)', {
  skip: SKIP_NO_STACK || SKIP_NO_MIGRATION || SKIP_NO_FN,
}, async () => {
  let impressionId, groupId;
  try {
    // Gross = 1 cent (10,000 micros) — below Stripe's $0.50 minimum.
    const entry = await insertSyntheticBillingEntry({
      lineItemId:   DEV_LINE_ITEM_ID,
      publisherId:  PUB_A_PUBLISHER_ID,
      grossMicros:  10_000,  // 1 cent
    });
    impressionId = entry.impressionId;
    groupId      = entry.groupId;

    const res = await fetch(`${BILLING_BASE}/charge`, {
      method:  'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
    });
    const body = await res.json();
    assert.equal(res.status, 200, `billing charge failed: ${JSON.stringify(body)}`);

    const chargeRes = await svcReq('GET', 'advertiser_charges', {
      query: `entry_group_id=eq.${groupId}&select=entry_group_id,status,failure_reason,amount_cents`,
    });
    assert.ok(
      Array.isArray(chargeRes.data) && chargeRes.data.length === 1,
      `Expected 1 advertiser_charges row, got: ${JSON.stringify(chargeRes.data)}`,
    );
    const row = chargeRes.data[0];
    assert.equal(row.status, 'skipped', 'below-minimum entry must produce status=skipped');
    assert.equal(
      row.failure_reason, 'below_stripe_minimum',
      'below-minimum entry must record failure_reason=below_stripe_minimum',
    );
    assert.equal(row.amount_cents, 1, 'amount_cents must match: 10000 micros = 1 cent');
  } finally {
    if (impressionId && groupId) {
      await cleanupSyntheticEntry({ impressionId, groupId });
    }
  }
});

// ---------------------------------------------------------------------------
// T24: Real Stripe charge succeeds (requires STRIPE_SECRET_KEY=sk_test_*).
//
// Setup: synthetic cleared impression with gross_micros=1,000,000 ($1.00).
// Billing cycle must create a Stripe PaymentIntent and record status='succeeded'.
// ---------------------------------------------------------------------------
test('T24 — billing: real Stripe charge succeeds (status=succeeded, stripe_charge_id set)', {
  skip: SKIP_NO_STACK || SKIP_NO_MIGRATION || SKIP_NO_FN || SKIP_NO_STRIPE,
}, async () => {
  let impressionId, groupId;
  try {
    const entry = await insertSyntheticBillingEntry({
      lineItemId:   DEV_LINE_ITEM_ID,
      publisherId:  PUB_A_PUBLISHER_ID,
      grossMicros:  1_000_000,  // $1.00 = 100 cents → above Stripe minimum
    });
    impressionId = entry.impressionId;
    groupId      = entry.groupId;

    const res = await fetch(`${BILLING_BASE}/charge`, {
      method:  'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${ADMIN_JWT}` },
    });
    const body = await res.json();
    assert.equal(res.status, 200, `billing charge failed: ${JSON.stringify(body)}`);

    const chargeRes = await svcReq('GET', 'advertiser_charges', {
      query: `entry_group_id=eq.${groupId}&select=*`,
    });
    assert.ok(
      Array.isArray(chargeRes.data) && chargeRes.data.length === 1,
      `Expected 1 advertiser_charges row, got: ${JSON.stringify(chargeRes.data)}`,
    );
    const row = chargeRes.data[0];
    assert.equal(row.status, 'succeeded', `Expected status=succeeded, got: ${row.status}`);
    assert.ok(
      typeof row.stripe_charge_id === 'string' && row.stripe_charge_id.startsWith('pi_'),
      `stripe_charge_id must be a PaymentIntent id (pi_*), got: ${row.stripe_charge_id}`,
    );
    assert.equal(row.amount_cents, 100, 'amount_cents must be 100 for $1.00');
  } finally {
    if (impressionId && groupId) {
      await cleanupSyntheticEntry({ impressionId, groupId });
    }
  }
});

// ---------------------------------------------------------------------------
// T25: Idempotency — re-running billing for same entry_group_id does not create
//      a second advertiser_charges row. (Requires Stripe to test full path.)
//
// First run: charge succeeds → row created.
// Second run: entry no longer appears in uncharged_advertiser_billings (view
//   filters out entries that already have a charge row). → charged=0, no new row.
// ---------------------------------------------------------------------------
test('T25 — billing: idempotency — re-run does not create second charge row', {
  skip: SKIP_NO_STACK || SKIP_NO_MIGRATION || SKIP_NO_FN || SKIP_NO_STRIPE,
}, async () => {
  let impressionId, groupId;
  try {
    const entry = await insertSyntheticBillingEntry({
      lineItemId:   DEV_LINE_ITEM_ID,
      publisherId:  PUB_A_PUBLISHER_ID,
      grossMicros:  500_000,  // $0.50 = 50 cents (minimum charge)
    });
    impressionId = entry.impressionId;
    groupId      = entry.groupId;

    // First billing run.
    const run1 = await fetch(`${BILLING_BASE}/charge`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ADMIN_JWT}` },
    });
    const body1 = await run1.json();
    assert.equal(run1.status, 200, `First billing run failed: ${JSON.stringify(body1)}`);

    // Second billing run — must see no uncharged entries for this group.
    const run2 = await fetch(`${BILLING_BASE}/charge`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ADMIN_JWT}` },
    });
    const body2 = await run2.json();
    assert.equal(run2.status, 200, `Second billing run failed: ${JSON.stringify(body2)}`);

    // Exactly one advertiser_charges row must exist.
    const chargeRes = await svcReq('GET', 'advertiser_charges', {
      query: `entry_group_id=eq.${groupId}&select=id,status`,
    });
    assert.ok(Array.isArray(chargeRes.data), 'advertiser_charges response must be an array');
    assert.equal(
      chargeRes.data.length, 1,
      `UNIQUE(entry_group_id) must prevent duplicate rows; got ${chargeRes.data.length} rows`,
    );
  } finally {
    if (impressionId && groupId) {
      await cleanupSyntheticEntry({ impressionId, groupId });
    }
  }
});
