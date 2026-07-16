// test/manual-clawback-logic.test.mjs — hermetic (no-DB) coverage of the manual-clawback refusal
// decision table, mirroring how monitor-logic.test.mjs covers evalReversedChargeUnrefunded.
//
// The SQL RPC public.admin_open_clawback (20260716140000) is the single most dangerous NEW
// money-mutating surface; its refusal precedence is the branch table that decides whether real
// money is reversed. That table lives only in PL/pgSQL, exercised by a self-skipping integration
// suite — so this pure test locks the precedence in the REQUIRED node --test gate.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  manualClawbackAllowed,
  MANUAL_CLAWBACK_REASONS,
  CLAWBACKABLE_STATES,
} from '../supabase/functions/_shared/manual-clawback-logic.mjs';

// A fully-allowed baseline (fresh cleared, unpaid, no CPC, no review, gross > 0) that each case perturbs.
const OK = {
  state: 'cleared',
  activePayout: false,
  windowHasSucceededCpcCharge: false,
  existingReview: false,
  earningAlreadyPaid: false,
  gross: 1_000_000,
};

test('the clean allow path reverses', () => {
  const r = manualClawbackAllowed(OK);
  assert.deepEqual(r, { allowed: true, effect: 'reverse', reason: 'ok' });
});

test('provisional is also clawbackable', () => {
  assert.equal(manualClawbackAllowed({ ...OK, state: 'provisional' }).reason, 'ok');
});

test('non-billable states → already_clawed_back (idempotent)', () => {
  for (const state of ['clawed_back', 'void', 'expired', 'unknown', '', null, undefined]) {
    const r = manualClawbackAllowed({ ...OK, state });
    assert.equal(r.allowed, false, `state=${state} must be refused`);
    assert.equal(r.reason, 'already_clawed_back');
  }
});

test('an active payout → payout_active', () => {
  const r = manualClawbackAllowed({ ...OK, activePayout: true });
  assert.deepEqual(r, { allowed: false, effect: 'refused', reason: 'payout_active' });
});

test('a succeeded CPC charge on the window → cpc_charge_present_no_refund_path', () => {
  const r = manualClawbackAllowed({ ...OK, windowHasSucceededCpcCharge: true });
  assert.equal(r.reason, 'cpc_charge_present_no_refund_path');
});

test('an existing non-rejected review → review_exists', () => {
  assert.equal(manualClawbackAllowed({ ...OK, existingReview: true }).reason, 'review_exists');
});

test('sentinel/house gross<=0 → allowed no-op (no_op_gross_zero)', () => {
  for (const gross of [0, -1, -1_000_000, null, undefined, NaN, 'x']) {
    const r = manualClawbackAllowed({ ...OK, gross });
    assert.equal(r.allowed, true, `gross=${gross} is a no-op, still "allowed"`);
    assert.equal(r.effect, 'no_op');
    assert.equal(r.reason, 'no_op_gross_zero');
  }
});

test('MONEY-SAFETY: a paid/covered earning → earning_already_paid', () => {
  const r = manualClawbackAllowed({ ...OK, earningAlreadyPaid: true });
  assert.deepEqual(r, { allowed: false, effect: 'refused', reason: 'earning_already_paid' });
});

// ---- precedence: earlier refusals win over later ones (mirrors the SQL early-returns) ----------
test('precedence: already_clawed_back beats every other condition', () => {
  const r = manualClawbackAllowed({
    state: 'clawed_back',
    activePayout: true,
    windowHasSucceededCpcCharge: true,
    existingReview: true,
    earningAlreadyPaid: true,
    gross: 0,
  });
  assert.equal(r.reason, 'already_clawed_back');
});

test('precedence: payout_active beats cpc/review/paid', () => {
  const r = manualClawbackAllowed({
    ...OK,
    activePayout: true,
    windowHasSucceededCpcCharge: true,
    existingReview: true,
    earningAlreadyPaid: true,
  });
  assert.equal(r.reason, 'payout_active');
});

test('precedence: cpc_charge beats review/paid', () => {
  const r = manualClawbackAllowed({
    ...OK,
    windowHasSucceededCpcCharge: true,
    existingReview: true,
    earningAlreadyPaid: true,
  });
  assert.equal(r.reason, 'cpc_charge_present_no_refund_path');
});

test('precedence: review_exists beats paid', () => {
  const r = manualClawbackAllowed({ ...OK, existingReview: true, earningAlreadyPaid: true });
  assert.equal(r.reason, 'review_exists');
});

test('precedence: sentinel (gross<=0) short-circuits BEFORE the paid-watermark check', () => {
  // A gross-0 sentinel that would ALSO be "already paid" must still return the no-op, not a refusal
  // — exactly as the SQL orders the gross<=0 no-op before app.impression_earning_paid().
  const r = manualClawbackAllowed({ ...OK, gross: 0, earningAlreadyPaid: true });
  assert.equal(r.effect, 'no_op');
  assert.equal(r.reason, 'no_op_gross_zero');
});

test('every emitted reason is a member of the exported reason set', () => {
  const cases = [
    { ...OK },
    { ...OK, state: 'void' },
    { ...OK, activePayout: true },
    { ...OK, windowHasSucceededCpcCharge: true },
    { ...OK, existingReview: true },
    { ...OK, gross: 0 },
    { ...OK, earningAlreadyPaid: true },
  ];
  for (const c of cases) {
    assert.ok(MANUAL_CLAWBACK_REASONS.includes(manualClawbackAllowed(c).reason));
  }
  assert.deepEqual(CLAWBACKABLE_STATES, ['provisional', 'cleared']);
});
