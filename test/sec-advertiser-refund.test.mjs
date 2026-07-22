// test/sec-advertiser-refund.test.mjs — SECURITY-AUDIT HARDENING regression locks for the
// A4 partial-refund reversal accounting in supabase/functions/_shared/advertiser-logic.mjs.
//
// Hermetic: `node --test`, node: builtins only. Imports the REAL shared module.
//
// THE A4 EXPLOIT: the pre-fix webhook path booked the CUMULATIVE deposit reversal off the Stripe
// charge's `obj.amount` (the FULL original charge). On a PARTIAL refund that reverses the WHOLE
// deposit — clawing back money the advertiser never got refunded. The fix reads `amount_refunded`
// (the cumulative refunded-so-far) for charge.refunded and books only the DELTA over prior
// reversals for the same PI.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isAdvertiserRefundEvent,
  isAdvertiserDisputeEvent,
  reversalTargetMicros,
  reversalDeltaMicros,
  planChargebackSplit,
  chargebackLegsSumToZero,
} from '../supabase/functions/_shared/advertiser-logic.mjs';

// ---------------------------------------------------------------------------
// A4 amount source: charge.refunded reads amount_refunded, NOT amount
// ---------------------------------------------------------------------------

test('sec A4: charge.refunded target = amount_refunded (€5), NEVER amount (€100 — the bug)', () => {
  // Partial refund: €5 refunded on a €100 charge. Pre-fix used obj.amount -> 100_000_000 (€100),
  // reversing the whole deposit. Post-fix uses amount_refunded -> 5_000_000 (€5).
  const target = reversalTargetMicros('charge.refunded', { amount: 10_000, amount_refunded: 500 });
  assert.equal(target, 5_000_000);
  assert.notEqual(target, 100_000_000);
});

test('sec A4: dispute events still read obj.amount (the disputed amount)', () => {
  assert.equal(
    reversalTargetMicros('charge.dispute.funds_withdrawn', { amount: 10_000 }),
    100_000_000,
  );
  assert.equal(reversalTargetMicros('charge.dispute.created', { amount: 250 }), 2_500_000);
});

test('sec A4: missing amount fields => 0 target (no accidental reversal)', () => {
  assert.equal(reversalTargetMicros('charge.refunded', {}), 0);
  assert.equal(reversalTargetMicros('charge.refunded', undefined), 0);
  assert.equal(reversalTargetMicros('charge.dispute.created', {}), 0);
});

// ---------------------------------------------------------------------------
// A4 delta: book only the increase of the cumulative target over prior reversals
// ---------------------------------------------------------------------------

test('sec A4: first partial refund books the full cumulative target', () => {
  assert.equal(reversalDeltaMicros(5_000_000, 0), 5_000_000);
});

test('sec A4: second partial books only the incremental delta (€8 cum − €5 already = €3)', () => {
  assert.equal(reversalDeltaMicros(8_000_000, 5_000_000), 3_000_000);
});

test('sec A4: replay (target == already) books 0 — idempotent no-op', () => {
  assert.equal(reversalDeltaMicros(5_000_000, 5_000_000), 0);
});

test('sec A4: out-of-order lower cumulative is clamped to 0 (never a negative reversal)', () => {
  assert.equal(reversalDeltaMicros(3_000_000, 5_000_000), 0);
});

test('sec A4: garbage inputs coerce to 0, never NaN', () => {
  assert.equal(reversalDeltaMicros(undefined, undefined), 0);
  assert.equal(reversalDeltaMicros('x', 'y'), 0);
});

// ---------------------------------------------------------------------------
// A4 reuse: the delta feeds the zero-sum chargeback split (legs always balance)
// ---------------------------------------------------------------------------

test('sec A4: delta -> planChargebackSplit legs sum to zero for delta<bal, ==bal, >bal', () => {
  const cases = [
    { delta: reversalDeltaMicros(3_000_000, 0), bal: 10_000_000 }, // delta < bal
    { delta: reversalDeltaMicros(10_000_000, 0), bal: 10_000_000 }, // delta == bal
    { delta: reversalDeltaMicros(15_000_000, 0), bal: 10_000_000 }, // delta > bal (bad debt)
  ];
  for (const { delta, bal } of cases) {
    assert.equal(chargebackLegsSumToZero(delta, bal), true, `legs must balance for delta=${delta} bal=${bal}`);
    const { reclaimMicros, badDebtMicros } = planChargebackSplit(delta, bal);
    assert.equal(reclaimMicros + badDebtMicros, delta); // reclaim + badDebt == R
  }
});

// ---------------------------------------------------------------------------
// A4 discriminator: refund vs dispute classification
// ---------------------------------------------------------------------------

test('sec A4: isAdvertiserRefundEvent distinguishes charge.refunded from disputes', () => {
  assert.equal(isAdvertiserRefundEvent('charge.refunded'), true);
  assert.equal(isAdvertiserRefundEvent('charge.dispute.created'), false);
  assert.equal(isAdvertiserRefundEvent('charge.dispute.funds_withdrawn'), false);
});

test('sec A4: the umbrella isAdvertiserDisputeEvent still matches charge.refunded (branch entered)', () => {
  assert.equal(isAdvertiserDisputeEvent('charge.refunded'), true);
});
