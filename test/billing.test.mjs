// test/billing.test.mjs — Hermetic tests for M2-T4 billing logic.
//
// Tests pure billing logic without any network calls, Stripe, or Deno APIs.
// The edge function (supabase/functions/billing/index.ts) uses Deno-specific imports
// (esm.sh, Deno.serve, Deno.env) which cannot be imported in Node. All logic is
// inlined here so the math and guard conditions are independently verified.
//
// WHAT IS TESTED:
//   billing: microsToCents — conversion, rounding, boundary cases
//   billing: idempotencyKey — format, stability, uniqueness
//   billing: house guard — sentinel (is_house=true) always produces status='skipped'
//   billing: below-minimum guard — amountCents < 50 → status='skipped'
//   billing: minimum boundary — exactly 50 cents is not skipped
//   billing: normal charge — amountCents >= 50, not house → status='would_charge'
//   billing: guard priority — house guard fires before below-minimum check

import test from 'node:test';
import assert from 'node:assert/strict';

// ---------------------------------------------------------------------------
// Pure billing helpers — mirrored from supabase/functions/billing/index.ts.
// Keep in sync if the edge function changes.
// ---------------------------------------------------------------------------

/** Convert micro-USD to Stripe cents. 1 cent = 10,000 micro-USD. */
function microsToCents(micros) {
  return Math.round(micros / 10000);
}

/** Stripe idempotency key for a billing group. */
function idempotencyKey(entryGroupId) {
  return `lumaline_grp_${entryGroupId}`;
}

/**
 * Billing decision for a single uncharged entry (pure, no I/O).
 * Returns { status, reason?, amount_cents } for guard cases,
 * or { status: 'would_charge', amount_cents } for the charge path.
 */
function processBillingEntry(entry) {
  const amountCents = microsToCents(entry.amount_micros);

  // Trust invariant: house/sentinel advertisers are never charged.
  if (entry.is_house) {
    return { status: 'skipped', reason: 'house_advertiser', amount_cents: amountCents };
  }

  // Stripe minimum: $0.50 = 50 cents = 500,000 micro-USD.
  // Use the cents value (not micros) to match the edge function.
  if (amountCents < 50) {
    return { status: 'skipped', reason: 'below_stripe_minimum', amount_cents: amountCents };
  }

  return { status: 'would_charge', amount_cents: amountCents };
}

// ---------------------------------------------------------------------------
// microsToCents — conversion, rounding, boundary cases
// ---------------------------------------------------------------------------

test('billing: microsToCents converts $1.00 to 100 cents', () => {
  assert.equal(microsToCents(1_000_000), 100);
});

test('billing: microsToCents converts $0.50 to 50 cents', () => {
  assert.equal(microsToCents(500_000), 50);
});

test('billing: microsToCents converts $0 to 0 cents', () => {
  assert.equal(microsToCents(0), 0);
});

test('billing: microsToCents converts $100 to 10000 cents', () => {
  assert.equal(microsToCents(100_000_000), 10_000);
});

test('billing: microsToCents rounds 495000 micros UP to 50 cents', () => {
  // 495000 / 10000 = 49.5 → rounds to 50 (bankers rounding: Math.round rounds 0.5 up)
  assert.equal(microsToCents(495_000), 50);
});

test('billing: microsToCents rounds 494999 micros DOWN to 49 cents', () => {
  // 494999 / 10000 = 49.4999 → rounds to 49
  assert.equal(microsToCents(494_999), 49);
});

test('billing: microsToCents rounds 499999 micros to 50 cents', () => {
  // 499999 / 10000 = 49.9999 → rounds to 50
  assert.equal(microsToCents(499_999), 50);
});

test('billing: microsToCents rounds 10001 micros to 1 cent', () => {
  // 10001 / 10000 = 1.0001 → rounds to 1
  assert.equal(microsToCents(10_001), 1);
});

// ---------------------------------------------------------------------------
// idempotencyKey — format, stability, uniqueness
// ---------------------------------------------------------------------------

test('billing: idempotencyKey has correct prefix and UUID', () => {
  const uuid = '123e4567-e89b-12d3-a456-426614174000';
  assert.equal(idempotencyKey(uuid), `lumaline_grp_${uuid}`);
});

test('billing: idempotencyKey is stable across repeated calls', () => {
  const uuid = 'aaaaaaaa-0000-4000-8000-000000000001';
  const key  = idempotencyKey(uuid);
  for (let i = 0; i < 5; i++) {
    assert.equal(idempotencyKey(uuid), key, 'idempotency key must be deterministic');
  }
});

test('billing: idempotencyKey is unique per entry_group_id', () => {
  const uuid1 = '11111111-0000-4000-8000-000000000001';
  const uuid2 = '22222222-0000-4000-8000-000000000002';
  assert.notEqual(
    idempotencyKey(uuid1),
    idempotencyKey(uuid2),
    'different entry_group_ids must produce different keys',
  );
});

// ---------------------------------------------------------------------------
// House guard — sentinel/house advertiser always skipped
// ---------------------------------------------------------------------------

test('billing: house advertiser with $1.00 is skipped (is_house=true)', () => {
  const result = processBillingEntry({
    entry_group_id: '5e470000-0000-4000-8000-000000000001',
    advertiser_id:  '5e470000-0000-4000-8000-00000000a001',
    is_house:       true,
    amount_micros:  1_000_000,  // $1.00 — would charge if not house
  });
  assert.equal(result.status, 'skipped', 'house advertiser must always be skipped');
  assert.equal(result.reason, 'house_advertiser');
});

test('billing: house advertiser with zero amount is still skipped', () => {
  const result = processBillingEntry({
    entry_group_id: 'abc',
    advertiser_id:  'def',
    is_house:       true,
    amount_micros:  0,
  });
  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'house_advertiser');
});

// ---------------------------------------------------------------------------
// Below-minimum guard — amount < $0.50 is skipped
// ---------------------------------------------------------------------------

test('billing: 49 cents is below Stripe minimum and is skipped', () => {
  const result = processBillingEntry({
    entry_group_id: 'abc',
    advertiser_id:  'def',
    is_house:       false,
    amount_micros:  490_000,  // 49 cents
  });
  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'below_stripe_minimum');
  assert.equal(result.amount_cents, 49);
});

test('billing: 1 cent is below Stripe minimum and is skipped', () => {
  const result = processBillingEntry({
    entry_group_id: 'abc',
    advertiser_id:  'def',
    is_house:       false,
    amount_micros:  10_000,  // exactly 1 cent
  });
  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'below_stripe_minimum');
});

// ---------------------------------------------------------------------------
// Boundary: exactly $0.50 (50 cents) must NOT be skipped
// ---------------------------------------------------------------------------

test('billing: exactly $0.50 (500000 micros = 50 cents) is not skipped', () => {
  const result = processBillingEntry({
    entry_group_id: 'abc',
    advertiser_id:  'def',
    is_house:       false,
    amount_micros:  500_000,  // exactly 50 cents
  });
  assert.equal(result.status, 'would_charge', 'exactly $0.50 must not be skipped');
  assert.equal(result.amount_cents, 50);
});

// ---------------------------------------------------------------------------
// Normal charge path — non-house, above minimum
// ---------------------------------------------------------------------------

test('billing: $1.00 from non-house advertiser proceeds to charge', () => {
  const result = processBillingEntry({
    entry_group_id: 'abc',
    advertiser_id:  'def',
    is_house:       false,
    amount_micros:  1_000_000,
  });
  assert.equal(result.status, 'would_charge');
  assert.equal(result.amount_cents, 100);
});

test('billing: $10.00 from non-house advertiser proceeds to charge', () => {
  const result = processBillingEntry({
    entry_group_id: 'abc',
    advertiser_id:  'def',
    is_house:       false,
    amount_micros:  10_000_000,
  });
  assert.equal(result.status, 'would_charge');
  assert.equal(result.amount_cents, 1_000);
});

// ---------------------------------------------------------------------------
// Guard priority — house check fires before below-minimum check
// ---------------------------------------------------------------------------

test('billing: house guard fires before below-minimum check (both conditions true)', () => {
  const result = processBillingEntry({
    entry_group_id: 'abc',
    advertiser_id:  'def',
    is_house:       true,
    amount_micros:  100,  // also below minimum, but house check runs first
  });
  assert.equal(result.status, 'skipped');
  assert.equal(result.reason, 'house_advertiser',
    'house_advertiser reason must take priority over below_stripe_minimum');
});

// ===========================================================================
// M2-T5: Reconciliation helpers — mirrored from supabase/functions/billing/index.ts
//
// WHAT IS TESTED:
//   recon: centsToMicros — Stripe cents to micro-USD (exact, no rounding)
//   recon: buildReconReport — matching totals → ok: true
//   recon: buildReconReport — DB > Stripe → ok: false, positive discrepancy
//   recon: buildReconReport — Stripe > DB → ok: false, negative discrepancy
//   recon: buildReconReport — empty both sides → ok: true, all zeros
//   recon: buildReconReport — non-lumaline PI is excluded from Stripe total
//   recon: buildReconReport — non-succeeded PI (declined) is excluded
//   recon: buildReconReport — db_count and stripe_count are correct
// ===========================================================================

/** Convert Stripe cents to micro-USD. 1 cent = 10,000 micro-USD. Exact (no rounding). */
function centsToMicros(cents) {
  return cents * 10000;
}

/**
 * Build a reconciliation report from pre-aggregated DB data and raw Stripe PaymentIntents.
 * Pure function — no I/O.
 *
 * Rules for Stripe side:
 *   - Only PaymentIntents with metadata.source === 'lumaline' are counted.
 *   - Only PaymentIntents with status === 'succeeded' are counted.
 *   - A declined PI has amount set but status !== 'succeeded'; it must NOT inflate the total.
 */
function buildReconReport({ dbTotalMicros, dbCount, stripePaymentIntents, from, to }) {
  const lumalineSucceeded = stripePaymentIntents.filter(
    (pi) => pi.metadata?.source === 'lumaline' && pi.status === 'succeeded',
  );
  const stripeTotalCents  = lumalineSucceeded.reduce((sum, pi) => sum + pi.amount, 0);
  const stripeTotalMicros = centsToMicros(stripeTotalCents);
  const discrepancyMicros = dbTotalMicros - stripeTotalMicros;
  return {
    ok:                  discrepancyMicros === 0,
    period:              { from, to },
    db_total_micros:     dbTotalMicros,
    stripe_total_micros: stripeTotalMicros,
    discrepancy_micros:  discrepancyMicros,
    db_count:            dbCount,
    stripe_count:        lumalineSucceeded.length,
  };
}

// ---------------------------------------------------------------------------
// centsToMicros — Stripe cents to micro-USD conversion
// ---------------------------------------------------------------------------

test('billing: recon centsToMicros converts 100 cents to 1000000 micros', () => {
  // $1.00 = 100 Stripe cents = 1,000,000 micro-USD
  assert.equal(centsToMicros(100), 1_000_000);
});

test('billing: recon centsToMicros converts 50 cents to 500000 micros', () => {
  // $0.50 (Stripe minimum) = 50 cents = 500,000 micro-USD
  assert.equal(centsToMicros(50), 500_000);
});

test('billing: recon centsToMicros converts 0 to 0', () => {
  assert.equal(centsToMicros(0), 0);
});

// ---------------------------------------------------------------------------
// buildReconReport — matching totals
// ---------------------------------------------------------------------------

test('billing: recon matching totals return ok: true and discrepancy: 0', () => {
  // DB has 100 cents cleared (1,000,000 micros); Stripe has one PI for 100 cents.
  const report = buildReconReport({
    dbTotalMicros:        1_000_000,
    dbCount:              1,
    stripePaymentIntents: [
      { amount: 100, metadata: { source: 'lumaline' }, status: 'succeeded' },
    ],
    from: '2026-06-01T00:00:00.000Z',
    to:   '2026-06-30T23:59:59.999Z',
  });
  assert.equal(report.ok, true, 'matched totals must produce ok: true');
  assert.equal(report.discrepancy_micros, 0);
  assert.equal(report.db_total_micros,    1_000_000);
  assert.equal(report.stripe_total_micros, 1_000_000);
  assert.equal(report.db_count,   1);
  assert.equal(report.stripe_count, 1);
});

// ---------------------------------------------------------------------------
// buildReconReport — DB > Stripe (unbilled or failed charge)
// ---------------------------------------------------------------------------

test('billing: recon DB > Stripe returns ok: false with positive discrepancy', () => {
  // DB has 200 cents cleared; Stripe only has 100 cents — a 100-cent billing gap.
  const report = buildReconReport({
    dbTotalMicros:        2_000_000,
    dbCount:              2,
    stripePaymentIntents: [
      { amount: 100, metadata: { source: 'lumaline' }, status: 'succeeded' },
    ],
    from: '2026-06-01T00:00:00.000Z',
    to:   '2026-06-30T23:59:59.999Z',
  });
  assert.equal(report.ok, false, 'DB > Stripe must produce ok: false');
  assert.equal(report.discrepancy_micros, 1_000_000, 'discrepancy = db - stripe');
  assert.equal(report.db_total_micros,    2_000_000);
  assert.equal(report.stripe_total_micros, 1_000_000);
});

// ---------------------------------------------------------------------------
// buildReconReport — Stripe > DB (over-billing bug)
// ---------------------------------------------------------------------------

test('billing: recon Stripe > DB returns ok: false with negative discrepancy', () => {
  // Stripe shows more than DB cleared — should never happen in practice but must flag red.
  const report = buildReconReport({
    dbTotalMicros:        500_000,
    dbCount:              1,
    stripePaymentIntents: [
      { amount: 100, metadata: { source: 'lumaline' }, status: 'succeeded' },
    ],
    from: '2026-06-01T00:00:00.000Z',
    to:   '2026-06-30T23:59:59.999Z',
  });
  assert.equal(report.ok, false, 'Stripe > DB must produce ok: false');
  assert.equal(report.discrepancy_micros, -500_000, 'discrepancy = db - stripe (negative)');
});

// ---------------------------------------------------------------------------
// buildReconReport — empty both sides
// ---------------------------------------------------------------------------

test('billing: recon empty DB and empty Stripe returns ok: true with all zeros', () => {
  const report = buildReconReport({
    dbTotalMicros:        0,
    dbCount:              0,
    stripePaymentIntents: [],
    from: '2020-01-01T00:00:00.000Z',
    to:   '2020-01-31T23:59:59.999Z',
  });
  assert.equal(report.ok, true, 'empty period must produce ok: true');
  assert.equal(report.discrepancy_micros,  0);
  assert.equal(report.db_total_micros,     0);
  assert.equal(report.stripe_total_micros, 0);
  assert.equal(report.db_count,     0);
  assert.equal(report.stripe_count, 0);
});

// ---------------------------------------------------------------------------
// buildReconReport — non-lumaline PIs are excluded from the Stripe total
// ---------------------------------------------------------------------------

test('billing: recon non-lumaline Stripe PIs are excluded (source !== lumaline)', () => {
  // A PI from a different product must not inflate the LumaLine Stripe total.
  const report = buildReconReport({
    dbTotalMicros:        0,
    dbCount:              0,
    stripePaymentIntents: [
      { amount: 500, metadata: { source: 'other_product' }, status: 'succeeded' },
      { amount: 200, metadata: {},                           status: 'succeeded' },
      { amount: 100, metadata: { source: 'lumaline' },       status: 'succeeded' },
    ],
    from: '2026-06-01T00:00:00.000Z',
    to:   '2026-06-30T23:59:59.999Z',
  });
  // Only the 100-cent lumaline PI counts → 100 * 10000 = 1,000,000 micros.
  assert.equal(report.stripe_total_micros, 1_000_000, 'only lumaline PIs should be counted');
  assert.equal(report.stripe_count, 1, 'non-lumaline PIs must not be counted');
  assert.equal(report.ok, false, 'db=0 vs stripe=1000000 should produce ok: false');
});

// ---------------------------------------------------------------------------
// buildReconReport — non-succeeded PIs (declined) are excluded
// ---------------------------------------------------------------------------

test('billing: recon declined Stripe PIs are excluded (status !== succeeded)', () => {
  // A card-declined PI must NOT count on the Stripe side — it signals a failed
  // collection, so the report should show DB > Stripe (red), not green.
  const report = buildReconReport({
    dbTotalMicros:        1_000_000,  // cleared entry exists
    dbCount:              1,
    stripePaymentIntents: [
      { amount: 100, metadata: { source: 'lumaline' }, status: 'requires_payment_method' },
      { amount: 100, metadata: { source: 'lumaline' }, status: 'canceled' },
    ],
    from: '2026-06-01T00:00:00.000Z',
    to:   '2026-06-30T23:59:59.999Z',
  });
  assert.equal(report.stripe_total_micros, 0, 'non-succeeded PIs must not inflate Stripe total');
  assert.equal(report.stripe_count, 0);
  assert.equal(report.ok, false, 'declined PIs must make report red, not green');
  assert.equal(report.discrepancy_micros, 1_000_000, 'full DB amount is the discrepancy');
});
