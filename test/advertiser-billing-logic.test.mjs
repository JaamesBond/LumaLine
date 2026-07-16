// test/advertiser-billing-logic.test.mjs — M9 hermetic unit tests for the advertiser money +
// content decision helpers. ALWAYS RUN (no stack, no network, no Stripe): imports the REAL shared
// modules the edge functions use, so the money-safety + content-safety logic is exercised on the
// protected-main `node --test` gate even when every advertiser INTEGRATION suite self-skips.
//
// Covers the spec's "Hermetic unit" test plan + the review must-fixes:
//   * planAdvertiserDrawDown       — draw / insufficient (pause, no partial) / reserved_underflow
//   * planChargebackSplit          — reclaim/badDebt/newBalance for R<bal, R==bal, R>bal; legs sum 0
//   * available / reserve estimate — balance-reserved; ceil(dwell/1000)*cpva
//   * validateCreativeContent      — parity with app.validate_creative_content (ESC/OSC-8/CR/LF,
//                                    lengths, https-only, dest control/whitespace)
//   * isAllowedDisclosureLabel     — the structural disclosure allow-list
//   * evaluateDepositEvent         — credit ONLY on a paid checkout.session; 'processing'/unpaid = none
//   * refundBranch                 — settled_via 'stripe'->card, 'balance'->re-credit (never both)
//   * planAdvertiserCharges        — prepay routes to draw_prepay regardless of the 50c minimum

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  planAdvertiserDrawDown,
  planAdvertiserCharges,
  microsToCents as billingMicrosToCents,
} from '../supabase/functions/_shared/billing-logic.mjs';
import {
  availableMicros,
  reserveEstimateMicros,
  planChargebackSplit,
  chargebackLegsSumToZero,
  evaluateDepositEvent,
  isAdvertiserDisputeEvent,
  refundBranch,
  piIdOf,
  centsToMicros,
  microsToCents,
  validateCreativeContent,
  isAllowedDisclosureLabel,
} from '../supabase/functions/_shared/advertiser-logic.mjs';

const ESC = String.fromCharCode(0x1b);   // OSC-8 / ANSI intro
const BEL = String.fromCharCode(0x07);
const CR = String.fromCharCode(0x0d);
const LF = String.fromCharCode(0x0a);
const NUL = String.fromCharCode(0x00);

// ---------------------------------------------------------------------------
// planAdvertiserDrawDown — mirrors app.advertiser_draw_down_batch's guards
// ---------------------------------------------------------------------------
test('drawdown: balance >= sum → draws the full micros', () => {
  const r = planAdvertiserDrawDown({ balanceMicros: 100, reservedMicros: 40, sumMicros: 40 });
  assert.deepEqual(r, { draw: true, reason: 'ok', reservedUnderflow: false, amountMicros: 40 });
});

test('drawdown: balance < sum → insufficient (pause, NO partial draw)', () => {
  const r = planAdvertiserDrawDown({ balanceMicros: 30, reservedMicros: 40, sumMicros: 40 });
  assert.equal(r.draw, false);
  assert.equal(r.reason, 'insufficient_balance');
  assert.equal(r.amountMicros, 0);
});

test('drawdown: reserved < sum → LOUD reservedUnderflow signal (still draws if balance covers)', () => {
  const r = planAdvertiserDrawDown({ balanceMicros: 100, reservedMicros: 10, sumMicros: 40 });
  assert.equal(r.draw, true);
  assert.equal(r.reservedUnderflow, true);   // never hidden
});

test('drawdown: reservedUnderflow surfaced even on the insufficient path', () => {
  const r = planAdvertiserDrawDown({ balanceMicros: 5, reservedMicros: 1, sumMicros: 40 });
  assert.equal(r.draw, false);
  assert.equal(r.reason, 'insufficient_balance');
  assert.equal(r.reservedUnderflow, true);
});

test('drawdown: sum <= 0 → nothing_to_draw', () => {
  assert.equal(planAdvertiserDrawDown({ balanceMicros: 100, reservedMicros: 0, sumMicros: 0 }).reason, 'nothing_to_draw');
});

// ---------------------------------------------------------------------------
// planChargebackSplit + chargebackLegsSumToZero — the bad-debt write-off math
// ---------------------------------------------------------------------------
test('chargeback: R < balance → reclaim=R, badDebt=0, newBalance=bal-R', () => {
  const r = planChargebackSplit(30, 100);
  assert.deepEqual(r, { reclaimMicros: 30, badDebtMicros: 0, newBalanceMicros: 70 });
  assert.equal(chargebackLegsSumToZero(30, 100), true);
});

test('chargeback: R == balance → reclaim=R, badDebt=0, newBalance=0', () => {
  const r = planChargebackSplit(100, 100);
  assert.deepEqual(r, { reclaimMicros: 100, badDebtMicros: 0, newBalanceMicros: 0 });
  assert.equal(chargebackLegsSumToZero(100, 100), true);
});

test('chargeback: R > balance (spent) → reclaim=bal, badDebt=R-bal, newBalance clamps at 0', () => {
  // deposit 100, spent 70 (balance 30 left), dispute 100 → reclaim 30, bad debt 70, balance 0.
  const r = planChargebackSplit(100, 30);
  assert.deepEqual(r, { reclaimMicros: 30, badDebtMicros: 70, newBalanceMicros: 0 });
  assert.equal(chargebackLegsSumToZero(100, 30), true);
});

test('chargeback: legs always sum to zero across a range', () => {
  for (const [R, bal] of [[1, 0], [0, 5], [50, 50], [999, 1000], [1000, 1]]) {
    assert.equal(chargebackLegsSumToZero(R, bal), true, `R=${R} bal=${bal}`);
  }
});

// ---------------------------------------------------------------------------
// available / reserve estimate
// ---------------------------------------------------------------------------
test('availableMicros = balance - reserved', () => {
  assert.equal(availableMicros(100, 40), 60);
  assert.equal(availableMicros(40, 40), 0);
  assert.equal(availableMicros(0, 0), 0);
});

test('reserveEstimateMicros = ceil(dwell/1000) * cpva (5s default → 5*bid)', () => {
  assert.equal(reserveEstimateMicros(5000, 1000), 5000);       // 5 * 1000
  assert.equal(reserveEstimateMicros(4001, 1000), 5000);       // ceil(4.001)=5
  assert.equal(reserveEstimateMicros(1000, 250), 250);
  assert.equal(reserveEstimateMicros(0, 1000), 0);
});

// ---------------------------------------------------------------------------
// micros/cents + whole-cent
// ---------------------------------------------------------------------------
test('micros<->cents round-trip; 1 cent = 10,000 micros', () => {
  assert.equal(centsToMicros(110), 1_100_000);   // €1.10
  assert.equal(microsToCents(1_100_000), 110);
  assert.equal(billingMicrosToCents(1_100_000), 110);
});

// ---------------------------------------------------------------------------
// validateCreativeContent — parity with app.validate_creative_content
// ---------------------------------------------------------------------------
test('content: clean copy passes', () => {
  assert.equal(validateCreativeContent('Try LumaLine — honest ads', 'sponsored', 'https://lumaline.dev'), null);
  assert.equal(validateCreativeContent('No dest is fine', 'ad', null), null);
});

test('content: empty line/label rejected', () => {
  assert.equal(validateCreativeContent('', 'sponsored', null), 'line_empty');
  assert.equal(validateCreativeContent('ok', '', null), 'label_empty');
});

test('content: length caps (line<=120, label<=30)', () => {
  assert.equal(validateCreativeContent('x'.repeat(121), 'sponsored', null), 'line_too_long');
  assert.equal(validateCreativeContent('ok', 'x'.repeat(31), null), 'label_too_long');
  assert.equal(validateCreativeContent('x'.repeat(120), 'sponsored', null), null);
});

test('content: control / ESC / OSC-8 / CR / LF bytes rejected in line and label', () => {
  assert.equal(validateCreativeContent(`a${ESC}[31mred`, 'sponsored', null), 'line_control_bytes');
  assert.equal(validateCreativeContent(`a${ESC}]8;;http://x${BEL}link`, 'sponsored', null), 'line_control_bytes');
  assert.equal(validateCreativeContent(`a${CR}${LF}b`, 'sponsored', null), 'line_control_bytes');
  assert.equal(validateCreativeContent(`a${NUL}b`, 'sponsored', null), 'line_control_bytes');
  assert.equal(validateCreativeContent('ok', `s${ESC}p`, null), 'label_control_bytes');
});

test('content: dest_url must be https:// (lowercase, no http/data/js)', () => {
  assert.equal(validateCreativeContent('ok', 'sponsored', 'http://x.com'), 'dest_not_https');
  assert.equal(validateCreativeContent('ok', 'sponsored', 'HTTPS://x.com'), 'dest_not_https'); // case-sensitive
  assert.equal(validateCreativeContent('ok', 'sponsored', 'javascript:alert(1)'), 'dest_not_https');
});

test('content: dest_url byte-sanitized — CR/LF/ESC/OSC-8/whitespace after https rejected', () => {
  assert.equal(validateCreativeContent('ok', 'sponsored', `https://ok.com/${CR}${LF}evil`), 'dest_control_bytes');
  assert.equal(validateCreativeContent('ok', 'sponsored', `https://ok.com${ESC}]8;;x${BEL}`), 'dest_control_bytes');
  assert.equal(validateCreativeContent('ok', 'sponsored', 'https://ok.com/a b'), 'dest_control_bytes'); // space
});

// ---------------------------------------------------------------------------
// disclosure label allow-list (structural, not review-dependent)
// ---------------------------------------------------------------------------
test('label allow-list: only sponsored / ad / promoted', () => {
  for (const ok of ['sponsored', 'ad', 'promoted']) assert.equal(isAllowedDisclosureLabel(ok), true, ok);
  for (const bad of ['tip', 'note', 'free', 'official', 'Sponsored', 'SPONSORED', '']) {
    assert.equal(isAllowedDisclosureLabel(bad), false, bad);
  }
});

test('label allow-list: Cyrillic-homoglyph "ѕponsored" (U+0455) is rejected', () => {
  const homoglyph = 'ѕponsored';   // looks like "sponsored" but is not ASCII
  assert.notEqual(homoglyph, 'sponsored');
  assert.equal(isAllowedDisclosureLabel(homoglyph), false);
});

// ---------------------------------------------------------------------------
// evaluateDepositEvent — credit ONLY on a captured (paid) session
// ---------------------------------------------------------------------------
test('deposit: checkout.session.completed with payment_status=paid → credit', () => {
  const r = evaluateDepositEvent({
    type: 'checkout.session.completed',
    data: { object: { id: 'cs_1', payment_status: 'paid', payment_intent: 'pi_1' } },
  });
  assert.equal(r.action, 'credit');
  assert.equal(r.sessionId, 'cs_1');
  assert.equal(r.piId, 'pi_1');
});

test('deposit: session with payment_status != paid credits NOTHING', () => {
  for (const st of ['unpaid', 'no_payment_required', 'processing']) {
    const r = evaluateDepositEvent({
      type: 'checkout.session.completed',
      data: { object: { id: 'cs_x', payment_status: st, payment_intent: 'pi_x' } },
    });
    assert.equal(r.action, 'ignore', st);
    assert.equal(r.reason, 'session_not_paid', st);
  }
});

test('deposit: a bare payment_intent.processing / .succeeded never credits', () => {
  assert.equal(evaluateDepositEvent({ type: 'payment_intent.processing', data: { object: { id: 'pi_2' } } }).action, 'ignore');
  assert.equal(evaluateDepositEvent({ type: 'payment_intent.succeeded', data: { object: { id: 'pi_3', status: 'succeeded' } } }).action, 'ignore');
});

test('deposit: piIdOf normalizes a string id or an expanded object', () => {
  assert.equal(piIdOf('pi_abc'), 'pi_abc');
  assert.equal(piIdOf({ id: 'pi_def' }), 'pi_def');
  assert.equal(piIdOf(null), null);
});

// ---------------------------------------------------------------------------
// dispute classification + refund branch
// ---------------------------------------------------------------------------
test('dispute events classified for the bad-debt reversal path', () => {
  for (const t of ['charge.dispute.funds_withdrawn', 'charge.dispute.created', 'charge.refunded']) {
    assert.equal(isAdvertiserDisputeEvent(t), true, t);
  }
  for (const t of ['checkout.session.completed', 'payment_intent.succeeded', 'account.updated']) {
    assert.equal(isAdvertiserDisputeEvent(t), false, t);
  }
});

test('refundBranch: stripe→card refund, balance→re-credit (never both)', () => {
  assert.equal(refundBranch('stripe'), 'stripe_refund');
  assert.equal(refundBranch('balance'), 'balance_clawback');
  assert.equal(refundBranch(undefined), 'stripe_refund');   // default/legacy = stripe
});

// ---------------------------------------------------------------------------
// planAdvertiserCharges — prepay routing
// ---------------------------------------------------------------------------
test('plan: a prepay advertiser routes to draw_prepay even below the 50c Stripe minimum', () => {
  const plans = planAdvertiserCharges([
    { advertiser_id: 'a1', billing_mode: 'prepay', entry_group_id: 'g1', amount_micros: 50_000 }, // 5 cents
  ]);
  assert.equal(plans.length, 1);
  assert.equal(plans[0].action, 'draw_prepay');
});

test('plan: house is skip_house; postpay respects the 50c minimum', () => {
  const plans = planAdvertiserCharges([
    { advertiser_id: 'house', is_house: true, billing_mode: 'postpay', entry_group_id: 'gh', amount_micros: 9_000_000 },
    { advertiser_id: 'lo', billing_mode: 'postpay', entry_group_id: 'gl', amount_micros: 50_000 },      // 5c < 50c
    { advertiser_id: 'hi', billing_mode: 'postpay', entry_group_id: 'gg', amount_micros: 9_000_000 },   // €9
  ]);
  const byId = Object.fromEntries(plans.map((p) => [p.advertiser_id, p.action]));
  assert.equal(byId.house, 'skip_house');
  assert.equal(byId.lo, 'skip_below_min');
  assert.equal(byId.hi, 'charge');
});

test('plan: missing billing_mode defaults to postpay (legacy rows unaffected)', () => {
  const plans = planAdvertiserCharges([
    { advertiser_id: 'legacy', entry_group_id: 'g', amount_micros: 9_000_000 },
  ]);
  assert.equal(plans[0].billing_mode, 'postpay');
  assert.equal(plans[0].action, 'charge');
});
