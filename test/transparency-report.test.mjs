// test/transparency-report.test.mjs — hermetic unit tests for the M6-T5 public transparency report's
// pure logic (scripts/ops/lib/transparency.mjs). No network, no DB — plain `node --test`, same pattern
// as monitor-logic / stripe-connect-logic.
//
// WHAT IS TESTED:
//   T1  buildReport  — cleared accrual aggregation: gross = publisher + platform, 60% split, prices.
//   T2  buildReport  — clawback rate from reversed accrual gross.
//   T3  buildReport  — empty ledger (the current live state) reconciles all-ok.
//   T4  reconcile    — a ledger imbalance flips zero_sum_ok / all_ok to false.
//   T5  reconcile    — a broken accrual identity (gross != pub+plat) is caught independently.
//   T6  delivery     — fill rate + credited views math.
//   T7  assertNonPII — a clean report passes.
//   T8  assertNonPII — a UUID value is rejected.
//   T9  assertNonPII — a non-whitelisted key is rejected.
//   T10 assertNonPII — a banned cost/token/ip substring is rejected.
//   T11 bps          — zero denominator -> null (n/a, not a misleading 0%).
//   T12 toMarkdown   — renders + the rendered report still passes the non-PII guard.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildReport,
  reconcile,
  assertNonPII,
  toMarkdown,
  bps,
} from '../scripts/ops/lib/transparency.mjs';

// Three cleared CPVA views @ €0.05 gross each -> pub €0.03, plat €0.02 each.
const CLEARED_FIXTURE = {
  ledger: [
    { account: 'advertiser_billing', state: 'cleared', event_type: 'cpva_accrual', amount_micros: 150000, n: 3 },
    { account: 'publisher_earnings', state: 'cleared', event_type: 'cpva_accrual', amount_micros: -90000, n: 3 },
    { account: 'platform_revenue', state: 'cleared', event_type: 'cpva_accrual', amount_micros: -60000, n: 3 },
  ],
  ledger_global_sum_micros: 0,
  unbalanced_group_count: 0,
  windows: { open: 2, credited: 4, abandoned: 10, void: 1 },
  impressions: [
    { state: 'cleared', n: 3, gross_micros: 150000, attention_seconds: 15 },
    { state: 'provisional', n: 1, gross_micros: 50000, attention_seconds: 0 },
  ],
  clicks_credited: 0,
};

test('T1 buildReport — cleared accrual: gross = pub + plat, 60/40 split, clearing prices', () => {
  const r = buildReport(CLEARED_FIXTURE);
  assert.equal(r.cleared.gross_micros, 150000);
  assert.equal(r.cleared.publisher_micros, 90000);
  assert.equal(r.cleared.platform_micros, 60000);
  assert.equal(r.cleared.gross_micros, r.cleared.publisher_micros + r.cleared.platform_micros);
  assert.equal(r.cleared.publisher_share_bps, 6000); // exactly 60%
  assert.equal(r.cleared.view_count, 3);
  assert.equal(r.cleared.attention_seconds, 15);
  assert.equal(r.cleared.avg_gross_per_view_micros, 50000);
  assert.equal(r.cleared.avg_gross_per_attention_second_micros, 10000);
  assert.equal(r.provisional.gross_micros, 50000);
  assert.equal(r.provisional.view_count, 1);
  assert.equal(r.reconciliation.all_ok, true);
});

test('T2 buildReport — clawback rate from reversed accrual gross', () => {
  const input = {
    ...CLEARED_FIXTURE,
    ledger: [
      ...CLEARED_FIXTURE.ledger,
      // one reversed group (amounts unchanged, still sums to 0 within the group)
      { account: 'advertiser_billing', state: 'reversed', event_type: 'cpva_accrual', amount_micros: 50000, n: 1 },
      { account: 'publisher_earnings', state: 'reversed', event_type: 'cpva_accrual', amount_micros: -30000, n: 1 },
      { account: 'platform_revenue', state: 'reversed', event_type: 'cpva_accrual', amount_micros: -20000, n: 1 },
    ],
  };
  const r = buildReport(input);
  assert.equal(r.clawback.reversed_gross_micros, 50000);
  assert.equal(r.clawback.reversed_group_count, 1);
  // 50000 / (150000 cleared + 50000 reversed) = 25%
  assert.equal(r.clawback.clawback_rate_bps, 2500);
  assert.equal(r.reconciliation.all_ok, true); // reversed groups keep zero-sum
});

test('T3 buildReport — empty ledger (current live state) reconciles all-ok', () => {
  const r = buildReport({
    ledger: [],
    ledger_global_sum_micros: 0,
    unbalanced_group_count: 0,
    windows: { open: 25, credited: 1405, abandoned: 25987, void: 0 },
    // 1405 recorded provisional impressions, but only 1 is billable (gross>0) — the rest are house.
    impressions: [{ state: 'provisional', n: 1405, billable_n: 1, gross_micros: 50000, attention_seconds: 5 }],
    clicks_credited: 0,
  });
  assert.equal(r.cleared.gross_micros, 0);
  assert.equal(r.cleared.publisher_share_bps, null); // n/a, not 0%
  assert.equal(r.provisional.gross_micros, 50000);
  assert.equal(r.provisional.view_count, 1); // billable only, not the 1405 house views
  assert.equal(r.delivery.credited_views, 1405); // delivery counts every recorded impression
  assert.equal(r.reconciliation.zero_sum_ok, true);
  assert.equal(r.reconciliation.accrual_identity_ok, true); // 0 == 0 + 0
  assert.equal(r.reconciliation.publisher_split_ok, true); // gross==0 -> vacuously ok
  assert.equal(r.reconciliation.all_ok, true);
});

test('T4 reconcile — ledger imbalance fails zero_sum_ok and all_ok', () => {
  const r = buildReport({ ...CLEARED_FIXTURE, ledger_global_sum_micros: 5 });
  assert.equal(r.reconciliation.zero_sum_ok, false);
  assert.equal(r.reconciliation.all_ok, false);

  const r2 = buildReport({ ...CLEARED_FIXTURE, unbalanced_group_count: 1 });
  assert.equal(r2.reconciliation.zero_sum_ok, false);
  assert.equal(r2.reconciliation.all_ok, false);
});

test('T5 reconcile — broken accrual identity (gross != pub + plat) is caught', () => {
  const r = buildReport({
    ...CLEARED_FIXTURE,
    // platform short by 5000 -> gross(150000) != pub(90000)+plat(55000)
    ledger: [
      { account: 'advertiser_billing', state: 'cleared', event_type: 'cpva_accrual', amount_micros: 150000, n: 3 },
      { account: 'publisher_earnings', state: 'cleared', event_type: 'cpva_accrual', amount_micros: -90000, n: 3 },
      { account: 'platform_revenue', state: 'cleared', event_type: 'cpva_accrual', amount_micros: -55000, n: 3 },
    ],
    ledger_global_sum_micros: 0, // pretend the global still nets (isolates the identity check)
    unbalanced_group_count: 0,
  });
  assert.equal(r.reconciliation.zero_sum_ok, true);
  assert.equal(r.reconciliation.accrual_identity_ok, false);
  assert.equal(r.reconciliation.all_ok, false);
});

test('T6 delivery — fill rate + credited views', () => {
  const r = buildReport(CLEARED_FIXTURE);
  assert.equal(r.delivery.windows_terminal, 15); // 4 + 10 + 1 (open excluded)
  assert.equal(r.delivery.fill_rate_bps, Math.round((4 / 15) * 10000)); // 2667
  assert.equal(r.delivery.credited_views, 4); // 3 cleared + 1 provisional impressions
});

test('T7 assertNonPII — clean report passes', () => {
  const r = buildReport({ ...CLEARED_FIXTURE, generated_at: '2026-07-03T17:00:00.000Z' });
  assert.doesNotThrow(() => assertNonPII(r));
});

test('T8 assertNonPII — a UUID value is rejected', () => {
  const r = buildReport(CLEARED_FIXTURE);
  r.currency = '4779db17-99e9-4bde-9723-ffe7dd4f7e58'; // allowed key, forbidden value
  assert.throws(() => assertNonPII(r), /UUID/);
});

test('T9 assertNonPII — a non-whitelisted key is rejected', () => {
  const r = buildReport(CLEARED_FIXTURE);
  r.extra_field = 1;
  assert.throws(() => assertNonPII(r), /non-whitelisted key/);
});

test('T10 assertNonPII — banned cost/token/ip substrings are rejected', () => {
  for (const bad of ['ip_hash-leak', 'raw total_cost', 'input_tokens=5', 'device fingerprint']) {
    const r = buildReport(CLEARED_FIXTURE);
    r.currency = bad;
    assert.throws(() => assertNonPII(r), /banned substring/, `expected reject: ${bad}`);
  }
});

test('T11 bps — zero denominator -> null', () => {
  assert.equal(bps(5, 0), null);
  assert.equal(bps(0, 0), null);
  assert.equal(bps(90000, 150000), 6000);
});

test('T12 toMarkdown — renders and the report still passes the non-PII guard', () => {
  const r = buildReport({ ...CLEARED_FIXTURE, generated_at: '2026-07-03T17:00:00.000Z' });
  const md = toMarkdown(r);
  assert.match(md, /LumaLine transparency report/);
  assert.match(md, /\*\*All checks pass\*\* \| ✓/);
  assert.doesNotThrow(() => assertNonPII(r)); // the object we rendered carries no PII
});
