// Pure decision logic for the M8-T7 manual clawback (SQL RPC: public.admin_open_clawback,
// migration 20260716140000). Deliberately ZERO runtime deps and NO Deno/Postgres globals so it can
// be imported by both the edge/UI layer and `node --test` (test/manual-clawback-logic.test.mjs) —
// same precedent as monitor-logic.mjs / payout-logic.mjs.
//
// WHY THIS EXISTS: the refusal decision table that decides whether REAL money gets reversed lives
// in the PL/pgSQL body of admin_open_clawback, exercised only by test/admin-open-clawback.integration.mjs,
// which self-skips in CI (no local Supabase stack). This module mirrors that precedence table 1:1 as
// a pure function so the branch logic has coverage in the REQUIRED node --test gate, and so the UI
// can predict/label the server's answer. The SQL is still the authority; this must stay in lock-step
// with it (any change to admin_open_clawback's refusal order must change here + the test together).
//
// PRECEDENCE (identical to admin_open_clawback's in-body order, after the aal2 gate + reason check):
//   1. state not in {provisional, cleared}          -> refused: already_clawed_back   (idempotent)
//   2. an active payout (pending|in_transit) exists -> refused: payout_active
//   3. the window carries a succeeded CPC charge     -> refused: cpc_charge_present_no_refund_path
//   4. a non-rejected review already exists          -> refused: review_exists
//   5. gross <= 0 / null (sentinel/house)            -> allowed no-op: no_op_gross_zero
//   6. the earning is within the already-paid tranche-> refused: earning_already_paid   (money-safety)
//   7. otherwise                                     -> allowed reversal: ok
//
// NOTE the ordering of 5 before 6: a sentinel (gross 0) has no earning to be paid, so it short-circuits
// to the clean no-op BEFORE the paid-watermark check — exactly as the SQL does.

// The impression states from which a clawback may proceed (billable, not yet reversed/void).
export const CLAWBACKABLE_STATES = ['provisional', 'cleared'];

// Every reason string this decision can emit — the single source the UI copy map keys on.
export const MANUAL_CLAWBACK_REASONS = [
  'already_clawed_back',
  'payout_active',
  'cpc_charge_present_no_refund_path',
  'review_exists',
  'no_op_gross_zero',
  'earning_already_paid',
  'ok',
];

function refused(reason) {
  return { allowed: false, effect: 'refused', reason };
}

/**
 * Decide whether a manual clawback of an impression is allowed, and if not, why — mirroring
 * public.admin_open_clawback's in-body refusal precedence EXACTLY.
 *
 * @param {object} input
 * @param {string}  input.state                     impression state (e.g. 'cleared','provisional','clawed_back','void')
 * @param {boolean} input.activePayout              a pending/in_transit payout exists for the publisher
 * @param {boolean} input.windowHasSucceededCpcCharge  the window carries a succeeded click-sourced charge
 * @param {boolean} input.existingReview            a non-rejected clawback_reviews row already exists for the impression
 * @param {boolean} input.earningAlreadyPaid        the impression's earning is within the paid FIFO tranche (app.impression_earning_paid)
 * @param {number|null|undefined} input.gross       impression gross_micros (<=0/null = sentinel/house no-op)
 * @returns {{allowed: boolean, effect: 'refused'|'no_op'|'reverse', reason: string}}
 */
export function manualClawbackAllowed({
  state,
  activePayout = false,
  windowHasSucceededCpcCharge = false,
  existingReview = false,
  earningAlreadyPaid = false,
  gross = null,
} = {}) {
  if (!CLAWBACKABLE_STATES.includes(String(state))) return refused('already_clawed_back');
  if (activePayout === true) return refused('payout_active');
  if (windowHasSucceededCpcCharge === true) return refused('cpc_charge_present_no_refund_path');
  if (existingReview === true) return refused('review_exists');

  // Sentinel/house/zero-bid: nothing financial to reverse → clean no-op BEFORE the paid check.
  const g = typeof gross === 'number' ? gross : Number(gross);
  if (!Number.isFinite(g) || g <= 0) return { allowed: true, effect: 'no_op', reason: 'no_op_gross_zero' };

  // Money-safety: a paid/covered earning can never be reversed (hold 7d > clawback 72h).
  if (earningAlreadyPaid === true) return refused('earning_already_paid');

  return { allowed: true, effect: 'reverse', reason: 'ok' };
}
