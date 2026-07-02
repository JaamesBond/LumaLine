// test/monitor-logic.test.mjs — hermetic unit tests for the T6 money-path monitor's
// pure decision functions (supabase/functions/_shared/monitor-logic.mjs).
//
// No network, no DB, no Deno — plain `node --test` over the shared .mjs module, the same
// pattern as payout-logic (stripe-connect-logic.test.mjs) and webhook-secrets.
//
// WHAT IS TESTED:
//   ML1–ML8   ledger_zero_sum   — balanced pass, per-group + global imbalance, rounding
//                                 edges (string/fractional/unreadable), dedup keys, drill
//                                 payloads get NO special-casing.
//   ML9–ML15  payout_stuck      — 6h age boundary (== not stuck, +1ms stuck), terminal
//                                 statuses never fire, unparseable created_at fails loud.
//   ML16–ML18 payout_failed     — per-id alerts + dedup key derivation.
//   ML19–ML22 charge_failed     — charges + billing-paused line items, dedup keys.
//   ML23–ML30 recon drift       — exact-zero tolerance (mirrors /reconcile), cents→micros
//                                 math incl. the sub-cent floor drift, PI filter mirrors
//                                 billing (source=lumaline AND succeeded only), unreadable
//                                 totals -> status 'error'.
//   ML31–ML34 error/resolve     — errorCheck shape, resolvableCheckNames excludes errors.
//   ML35–ML38 email decision    — fired/resolved/none; buildAlertEmail content, no secrets.
//   ML39–ML43 timingSafeEqualStrings — equal/differing/length-mismatch/empty.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CHECK_NAMES,
  FAILURE_LOOKBACK_MS,
  NON_TERMINAL_PAYOUT_STATUSES,
  PAYOUT_STUCK_MAX_AGE_MS,
  RECON_WINDOW_DAYS,
  buildAlertEmail,
  errorCheck,
  evalChargeFailed,
  evalLedgerZeroSum,
  evalPayoutFailed,
  evalPayoutStuck,
  evalReconDrift,
  resolvableCheckNames,
  shouldSendEmail,
  sumLumalinePaymentIntents,
  timingSafeEqualStrings,
  toMicros,
} from '../supabase/functions/_shared/monitor-logic.mjs';

const G1 = '11111111-1111-4111-8111-111111111111';
const G2 = '22222222-2222-4222-8222-222222222222';

// ---------------------------------------------------------------------------
// ledger_zero_sum
// ---------------------------------------------------------------------------

test('ML1: balanced ledger (no groups, global 0) passes with no alerts', () => {
  const r = evalLedgerZeroSum({ groups: [], global_sum_micros: 0 });
  assert.equal(r.status, 'pass');
  assert.deepEqual(r.alerts, []);
});

test('ML2: one unbalanced group fires a critical alert with dedup grp:<id>', () => {
  const r = evalLedgerZeroSum({ groups: [{ entry_group_id: G1, sum_micros: 12345 }], global_sum_micros: 12345 });
  assert.equal(r.status, 'fail');
  const grp = r.alerts.find((a) => a.dedup_key === `grp:${G1}`);
  assert.ok(grp, 'per-group alert present');
  assert.equal(grp.severity, 'critical');
  assert.equal(grp.check_name, 'ledger_zero_sum');
  assert.equal(grp.payload.sum_micros, 12345);
});

test('ML3: non-zero global sum fires the dedup_key=global alert even with no groups listed', () => {
  const r = evalLedgerZeroSum({ groups: [], global_sum_micros: -1 });
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts.length, 1);
  assert.equal(r.alerts[0].dedup_key, 'global');
  assert.equal(r.alerts[0].severity, 'critical');
});

test('ML4: PostgREST bigint-as-string "0" is treated as balanced (rounding/serialization edge)', () => {
  const r = evalLedgerZeroSum({ groups: [], global_sum_micros: '0' });
  assert.equal(r.status, 'pass');
});

test('ML5: fractional group sum (0.5 micros — should be impossible, but) still fires', () => {
  const r = evalLedgerZeroSum({ groups: [{ entry_group_id: G1, sum_micros: 0.5 }], global_sum_micros: 0 });
  assert.equal(r.status, 'fail');
  assert.ok(r.alerts.some((a) => a.dedup_key === `grp:${G1}`));
});

test('ML6: unreadable global sum fails loud (never silently green)', () => {
  const r = evalLedgerZeroSum({ groups: [], global_sum_micros: 'not-a-number' });
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].dedup_key, 'global');
});

test('ML7: multiple unbalanced groups each get their own dedup key', () => {
  const r = evalLedgerZeroSum({
    groups: [
      { entry_group_id: G1, sum_micros: 100 },
      { entry_group_id: G2, sum_micros: -100 },
    ],
    global_sum_micros: 0,
  });
  assert.equal(r.status, 'fail');
  const keys = r.alerts.map((a) => a.dedup_key).sort();
  assert.deepEqual(keys, [`grp:${G1}`, `grp:${G2}`]);
});

test('ML8: DRILL — a T6-DRILL-marked synthetic group fires exactly like a real fault (no special-casing)', () => {
  // The controller injects an imbalanced group whose payload/memo says T6-DRILL. The
  // evaluator must not look at any marker — only at the sum.
  const r = evalLedgerZeroSum({
    groups: [{ entry_group_id: G1, sum_micros: 999999, memo: 'T6-DRILL synthetic fault' }],
    global_sum_micros: 999999,
  });
  assert.equal(r.status, 'fail');
  assert.ok(r.alerts.some((a) => a.dedup_key === `grp:${G1}` && a.severity === 'critical'));
});

// ---------------------------------------------------------------------------
// payout_stuck
// ---------------------------------------------------------------------------

const NOW = Date.parse('2026-07-02T12:00:00Z');
const iso = (msAgo) => new Date(NOW - msAgo).toISOString();

test('ML9: pending payout exactly at the 6h boundary is NOT stuck (strictly older fires)', () => {
  const r = evalPayoutStuck([{ id: 'p1', status: 'pending', created_at: iso(PAYOUT_STUCK_MAX_AGE_MS) }], NOW);
  assert.equal(r.status, 'pass');
});

test('ML10: pending payout 6h + 1ms old IS stuck', () => {
  const r = evalPayoutStuck([{ id: 'p1', status: 'pending', created_at: iso(PAYOUT_STUCK_MAX_AGE_MS + 1) }], NOW);
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].dedup_key, 'payout:p1');
  assert.equal(r.alerts[0].severity, 'high');
  assert.equal(r.alerts[0].payload.age_ms, PAYOUT_STUCK_MAX_AGE_MS + 1);
});

test('ML11: in_transit is non-terminal and can be stuck', () => {
  assert.deepEqual(NON_TERMINAL_PAYOUT_STATUSES, ['pending', 'in_transit']);
  const r = evalPayoutStuck([{ id: 'p2', status: 'in_transit', created_at: iso(7 * 3600e3) }], NOW);
  assert.equal(r.status, 'fail');
});

test('ML12: terminal statuses (paid/failed/canceled) never fire regardless of age', () => {
  const old = iso(400 * 24 * 3600e3);
  const r = evalPayoutStuck([
    { id: 'a', status: 'paid', created_at: old },
    { id: 'b', status: 'failed', created_at: old },
    { id: 'c', status: 'canceled', created_at: old },
  ], NOW);
  assert.equal(r.status, 'pass');
});

test('ML13: fresh pending payout does not fire', () => {
  const r = evalPayoutStuck([{ id: 'p1', status: 'pending', created_at: iso(60_000) }], NOW);
  assert.equal(r.status, 'pass');
});

test('ML14: unparseable created_at on a non-terminal payout fails loud (treated as stuck)', () => {
  const r = evalPayoutStuck([{ id: 'p1', status: 'pending', created_at: 'garbage' }], NOW);
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].payload.age_ms, null);
});

test('ML15: empty payout list passes', () => {
  assert.equal(evalPayoutStuck([], NOW).status, 'pass');
});

// ---------------------------------------------------------------------------
// payout_failed
// ---------------------------------------------------------------------------

test('ML16: failed payouts produce one high alert per payout id', () => {
  const r = evalPayoutFailed([
    { id: 'p1', failure_reason: 'no_connected_account', created_at: iso(3600e3) },
    { id: 'p2', failure_reason: 'transfer_reversed', created_at: iso(7200e3) },
  ]);
  assert.equal(r.status, 'fail');
  assert.deepEqual(r.alerts.map((a) => a.dedup_key).sort(), ['payout:p1', 'payout:p2']);
  assert.ok(r.alerts.every((a) => a.severity === 'high' && a.check_name === 'payout_failed'));
});

test('ML17: payout_failed carries failure_reason in the payload', () => {
  const r = evalPayoutFailed([{ id: 'p1', failure_reason: 'insufficient_funds', created_at: iso(1) }]);
  assert.equal(r.alerts[0].payload.failure_reason, 'insufficient_funds');
});

test('ML18: no failed payouts passes', () => {
  assert.equal(evalPayoutFailed([]).status, 'pass');
});

// ---------------------------------------------------------------------------
// charge_failed
// ---------------------------------------------------------------------------

test('ML19: failed charges fire per charge id with dedup charge:<id>', () => {
  const r = evalChargeFailed({
    failedCharges: [{ id: 'c1', advertiser_id: 'a1', failure_reason: 'card_declined', amount_cents: 120 }],
    pausedLineItems: [],
  });
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].dedup_key, 'charge:c1');
  assert.equal(r.alerts[0].severity, 'high');
  assert.equal(r.alerts[0].payload.failure_reason, 'card_declined');
});

test('ML20: billing-paused line items fire per line item with dedup paused_li:<id>', () => {
  const r = evalChargeFailed({
    failedCharges: [{ id: 'c1', advertiser_id: 'a1' }],
    pausedLineItems: [{ id: 'li1', campaign_id: 'cmp1', advertiser_id: 'a1' }],
  });
  const li = r.alerts.find((a) => a.dedup_key === 'paused_li:li1');
  assert.ok(li);
  assert.equal(li.payload.reason, 'paused_after_charge_failure');
});

test('ML21: clean (no failed charges, no paused items) passes', () => {
  assert.equal(evalChargeFailed({ failedCharges: [], pausedLineItems: [] }).status, 'pass');
});

test('ML22: detail counts both charges and paused line items', () => {
  const r = evalChargeFailed({
    failedCharges: [{ id: 'c1' }, { id: 'c2' }],
    pausedLineItems: [{ id: 'li1' }],
  });
  assert.equal(r.alerts.length, 3);
  assert.match(r.detail, /2 failed charge/);
  assert.match(r.detail, /1 billing-paused/);
});

// ---------------------------------------------------------------------------
// recon drift (e/f) + Stripe-side sums
// ---------------------------------------------------------------------------

test('ML23: equal totals pass (tolerance is EXACTLY zero, mirroring /reconcile ok===0)', () => {
  const r = evalReconDrift('billing_recon_drift', 500000, 500000);
  assert.equal(r.status, 'pass');
});

test('ML24: 1-micro drift fires critical with both totals in the payload', () => {
  const r = evalReconDrift('billing_recon_drift', 500001, 500000, { db_count: 1, stripe_count: 1 });
  assert.equal(r.status, 'fail');
  const a = r.alerts[0];
  assert.equal(a.severity, 'critical');
  assert.equal(a.dedup_key, 'drift');
  assert.equal(a.payload.db_total_micros, 500001);
  assert.equal(a.payload.stripe_total_micros, 500000);
  assert.equal(a.payload.discrepancy_micros, 1);
  assert.equal(a.payload.db_count, 1);
});

test('ML25: sub-cent floor drift — DB 50.5 cents in micros vs Stripe 50 whole cents fires with drift 5000', () => {
  // Mirrors the existing recon behavior: DB sums exact micros; Stripe only ever carries
  // whole cents (1 cent = 10,000 micros), so a sub-cent ledger remainder IS a drift.
  const dbMicros = 505000;                 // 50.5 cents
  const stripeMicros = 50 * 10000;         // 50 cents charged
  const r = evalReconDrift('billing_recon_drift', dbMicros, stripeMicros);
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].payload.discrepancy_micros, 5000);
});

test('ML26: negative drift (Stripe > DB) also fires', () => {
  const r = evalReconDrift('payout_recon_drift', 0, 10000);
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].payload.discrepancy_micros, -10000);
});

test('ML27: unreadable totals produce status error (fail loud), not pass', () => {
  const r = evalReconDrift('payout_recon_drift', 'garbage', 0);
  assert.equal(r.status, 'error');
  assert.equal(r.alerts[0].severity, 'high');
  assert.equal(r.alerts[0].dedup_key, 'check_error');
});

test('ML28: string bigints from PostgREST reconcile correctly', () => {
  const r = evalReconDrift('billing_recon_drift', '1500000', 1500000);
  assert.equal(r.status, 'pass');
});

test('ML29: sumLumalinePaymentIntents mirrors billing /reconcile — succeeded source=lumaline only, cents*10000', () => {
  const { totalMicros, count } = sumLumalinePaymentIntents([
    { amount: 50, status: 'succeeded', metadata: { source: 'lumaline' } },        // counted
    { amount: 999, status: 'requires_payment_method', metadata: { source: 'lumaline' } }, // declined: NOT counted
    { amount: 77, status: 'succeeded', metadata: { source: 'other' } },           // foreign: NOT counted
    { amount: 33, status: 'succeeded' },                                          // no metadata: NOT counted
  ]);
  assert.equal(totalMicros, 50 * 10000);
  assert.equal(count, 1);
});

test('ML30: toMicros edges — number passes through, string parses, null/undefined/garbage are NaN', () => {
  assert.equal(toMicros(42), 42);
  assert.equal(toMicros('42'), 42);
  assert.ok(Number.isNaN(toMicros(null)));
  assert.ok(Number.isNaN(toMicros(undefined)));
  assert.ok(Number.isNaN(toMicros('12abc')));
  assert.ok(Number.isNaN(toMicros('')));
});

// ---------------------------------------------------------------------------
// errorCheck + resolvable set
// ---------------------------------------------------------------------------

test('ML31: errorCheck reports status error with one HIGH check_error alert', () => {
  const r = errorCheck('billing_recon_drift', 'Stripe API unreachable');
  assert.equal(r.status, 'error');
  assert.equal(r.alerts.length, 1);
  assert.equal(r.alerts[0].severity, 'high');
  assert.equal(r.alerts[0].dedup_key, 'check_error');
  assert.equal(r.alerts[0].payload.error, 'Stripe API unreachable');
});

test('ML32: resolvableCheckNames includes pass+fail, excludes error (an unobservable check must not auto-resolve its alerts)', () => {
  const names = resolvableCheckNames([
    { name: 'ledger_zero_sum', status: 'pass' },
    { name: 'payout_stuck', status: 'fail' },
    { name: 'billing_recon_drift', status: 'error' },
  ]);
  assert.deepEqual(names, ['ledger_zero_sum', 'payout_stuck']);
});

test('ML33: CHECK_NAMES covers all six T6 checks', () => {
  assert.deepEqual(CHECK_NAMES, [
    'ledger_zero_sum', 'payout_stuck', 'payout_failed',
    'charge_failed', 'billing_recon_drift', 'payout_recon_drift',
  ]);
});

test('ML34: window constants — 35-day recon window, 24h failure lookback', () => {
  assert.equal(RECON_WINDOW_DAYS, 35);
  assert.equal(FAILURE_LOOKBACK_MS, 24 * 3600e3);
});

// ---------------------------------------------------------------------------
// email decision + content
// ---------------------------------------------------------------------------

test('ML35: shouldSendEmail — fired only, resolved only, both → true', () => {
  assert.equal(shouldSendEmail([{}], []), true);
  assert.equal(shouldSendEmail([], [{}]), true);
  assert.equal(shouldSendEmail([{}], [{}]), true);
});

test('ML36: shouldSendEmail — all-green / no-change run → false (never email)', () => {
  assert.equal(shouldSendEmail([], []), false);
  assert.equal(shouldSendEmail(undefined, undefined), false);
});

test('ML37: buildAlertEmail subject reflects worst severity and counts', () => {
  const { subject } = buildAlertEmail(
    [{ check_name: 'ledger_zero_sum', severity: 'critical', dedup_key: 'grp:x' }],
    [],
    [{ name: 'ledger_zero_sum', status: 'fail', detail: '1 imbalance' }],
  );
  assert.match(subject, /CRITICAL/);
  assert.match(subject, /1 fired, 0 resolved/);
});

test('ML38: buildAlertEmail body lists fired, resolved, and the check summary', () => {
  const { subject, text } = buildAlertEmail(
    [{ check_name: 'payout_stuck', severity: 'high', dedup_key: 'payout:p1' }],
    [{ check_name: 'charge_failed', dedup_key: 'charge:c1' }],
    [
      { name: 'payout_stuck', status: 'fail', detail: '1 payout(s) stuck' },
      { name: 'ledger_zero_sum', status: 'pass', detail: 'all balance' },
    ],
  );
  assert.match(subject, /HIGH/);
  assert.match(text, /NEWLY FIRED:/);
  assert.match(text, /payout_stuck \(payout:p1\)/);
  assert.match(text, /NEWLY RESOLVED:/);
  assert.match(text, /charge_failed \(charge:c1\)/);
  assert.match(text, /ledger_zero_sum: pass/);
});

// ---------------------------------------------------------------------------
// timingSafeEqualStrings (auth compare)
// ---------------------------------------------------------------------------

test('ML39: equal secrets compare true', async () => {
  assert.equal(await timingSafeEqualStrings('s3cret-value', 's3cret-value'), true);
});

test('ML40: different secrets of equal length compare false', async () => {
  assert.equal(await timingSafeEqualStrings('aaaaaaaa', 'aaaaaaab'), false);
});

test('ML41: different lengths compare false', async () => {
  assert.equal(await timingSafeEqualStrings('short', 'a-much-longer-secret'), false);
});

test('ML42: empty or missing values NEVER authorize (unset env must not match empty header)', async () => {
  assert.equal(await timingSafeEqualStrings('', ''), false);
  assert.equal(await timingSafeEqualStrings('x', ''), false);
  assert.equal(await timingSafeEqualStrings('', 'x'), false);
  assert.equal(await timingSafeEqualStrings(undefined, undefined), false);
});

test('ML43: unicode-equal strings compare true (digest over UTF-8 bytes)', async () => {
  assert.equal(await timingSafeEqualStrings('sécret✓', 'sécret✓'), true);
});
