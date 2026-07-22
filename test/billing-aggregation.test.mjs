// Exhaustive PURE unit tests for the per-advertiser charge aggregation
// (supabase/functions/_shared/billing-logic.mjs). No stack, no Stripe — gates CI.
//
// WHY: CPVA bills ~€0.05/view, permanently below Stripe's 50-cent minimum, so charges MUST be
// summed per advertiser into one PaymentIntent. These tests pin the decision logic the billing
// edge fn relies on: which advertisers charge, which skip (house / below-min NON-terminal), the
// exact 50-cent boundary + micros→cents rounding, and the crash-safe aggregate idempotency key.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  microsToCents,
  batchIdempotencyKey,
  partitionPendingByBatch,
  planAdvertiserCharges,
} from '../supabase/functions/_shared/billing-logic.mjs';

const row = (o) => ({
  advertiser_id: 'adv',
  advertiser_name: 'Adv',
  is_house: false,
  stripe_customer_id: null,
  entry_group_id: `g-${Math.random().toString(36).slice(2)}`,
  amount_micros: 50000,
  impression_id: null,
  publisher_id: null,
  ...o,
});

// ---------------------------------------------------------------------------
// microsToCents — conversion + rounding boundaries
// ---------------------------------------------------------------------------
test('microsToCents: whole-cent conversions', () => {
  assert.equal(microsToCents(1_000_000), 100);
  assert.equal(microsToCents(500_000), 50);
  assert.equal(microsToCents(1_100_000), 110); // Degen: 22 × 50000
  assert.equal(microsToCents(0), 0);
});
test('microsToCents: FLOORS at the half-cent (F4 — never round up / phantom overcharge)', () => {
  assert.equal(microsToCents(495_000), 49, '49.5 floors to 49 (never round up — F4)');
  assert.equal(microsToCents(494_999), 49, '49.4999 → 49');
  assert.equal(microsToCents(999_999), 99, '99.9999 floors to 99 (never round up — F4)');
  assert.equal(microsToCents(10_001), 1);
});
test('microsToCents: coerces numeric strings', () => {
  assert.equal(microsToCents('50000'), 5);
});

// ---------------------------------------------------------------------------
// batchIdempotencyKey — derived from the IMMUTABLE batch id, NOT the group set (the F1 fix)
// ---------------------------------------------------------------------------
test('batchIdempotencyKey: prefix + the batch id', () => {
  assert.equal(batchIdempotencyKey('b1'), 'lumaline_agg_b1');
});
test('batchIdempotencyKey: deterministic (same batch → same key = crash-safe retry)', () => {
  const b = 'a1a1a1a1-0000-0000-0000-000000000001';
  assert.equal(batchIdempotencyKey(b), batchIdempotencyKey(b));
});
test('batchIdempotencyKey: does NOT depend on the group set (the whole point of F1)', () => {
  // The key is a function of the batch id ALONE. A crash/recovery that re-issues the same batch
  // gets the same key EVEN IF the code recomputes the member list — so Stripe dedups to one PI, and
  // freshly-accrued impressions (which form a DIFFERENT batch) can never re-charge the billed ones.
  assert.equal(batchIdempotencyKey('batch-X'), 'lumaline_agg_batch-X');
  assert.notEqual(batchIdempotencyKey('batch-X'), batchIdempotencyKey('batch-Y'));
});

// ---------------------------------------------------------------------------
// partitionPendingByBatch — recovery groups reserved rows by their frozen batch id
// ---------------------------------------------------------------------------
test('partitionPendingByBatch: groups rows by charge_batch_id, carrying advertiser + rows', () => {
  const rows = [
    { charge_batch_id: 'b1', advertiser_id: 'A', entry_group_id: 'g1' },
    { charge_batch_id: 'b1', advertiser_id: 'A', entry_group_id: 'g2' },
    { charge_batch_id: 'b2', advertiser_id: 'B', entry_group_id: 'g3' },
  ];
  const m = partitionPendingByBatch(rows);
  assert.equal(m.size, 2);
  assert.equal(m.get('b1').advertiser_id, 'A');
  assert.equal(m.get('b1').rows.length, 2);
  assert.equal(m.get('b2').advertiser_id, 'B');
  assert.equal(m.get('b2').rows.length, 1);
});
test('partitionPendingByBatch: two DISTINCT batches for one advertiser stay separate (never merged)', () => {
  const rows = [
    { charge_batch_id: 'b1', advertiser_id: 'A', entry_group_id: 'g1' },
    { charge_batch_id: 'b2', advertiser_id: 'A', entry_group_id: 'g2' },
  ];
  const m = partitionPendingByBatch(rows);
  assert.equal(m.size, 2, 'same advertiser, two batches → two independent PIs, never one merged charge');
});
test('partitionPendingByBatch: null batch id → sentinel "" bucket (released, never charged)', () => {
  const m = partitionPendingByBatch([{ charge_batch_id: null, advertiser_id: 'A', entry_group_id: 'g1' }]);
  assert.ok(m.has(''), 'legacy/malformed rows land under "" so the fn releases them, not charges them');
});
test('partitionPendingByBatch: empty/undefined → empty map', () => {
  assert.equal(partitionPendingByBatch([]).size, 0);
  assert.equal(partitionPendingByBatch(undefined).size, 0);
});

// ---------------------------------------------------------------------------
// planAdvertiserCharges — grouping + action decision
// ---------------------------------------------------------------------------
test('the Degen case: 22 × €0.05 under one advertiser → ONE charge plan of €1.10', () => {
  const rows = Array.from({ length: 22 }, () => row({ advertiser_id: 'degen', amount_micros: 50000 }));
  const plans = planAdvertiserCharges(rows);
  assert.equal(plans.length, 1);
  const p = plans[0];
  assert.equal(p.advertiser_id, 'degen');
  assert.equal(p.sumMicros, 1_100_000);
  assert.equal(p.sumCents, 110);
  assert.equal(p.action, 'charge');
  assert.equal(p.groups.length, 22);
  assert.equal(p.entryGroupIds.length, 22);
});

test('per-impression charging would NEVER clear the minimum — aggregation is the whole point', () => {
  // Each 5-cent impression alone is below 50; only the sum crosses it.
  const one = planAdvertiserCharges([row({ amount_micros: 50000 })]);
  assert.equal(one[0].action, 'skip_below_min', 'a single €0.05 impression is below-min');
  const ten = planAdvertiserCharges(Array.from({ length: 10 }, () => row({ amount_micros: 50000 })));
  assert.equal(ten[0].action, 'charge', '10 × €0.05 = €0.50 = the minimum → charge');
});

test('below-minimum aggregate → skip_below_min (NON-terminal: no charge row written by the fn)', () => {
  const rows = Array.from({ length: 9 }, () => row({ amount_micros: 50000 })); // 45c
  const [p] = planAdvertiserCharges(rows);
  assert.equal(p.sumCents, 45);
  assert.equal(p.action, 'skip_below_min');
});

test('exact 50-cent boundary + rounding decide charge vs skip', () => {
  assert.equal(planAdvertiserCharges([row({ amount_micros: 500_000 })])[0].action, 'charge', '50c → charge');
  assert.equal(planAdvertiserCharges([row({ amount_micros: 495_000 })])[0].action, 'skip_below_min', '49.5c floors to 49 < 50 → skip (never overcharge to 50c — F4)');
  assert.equal(planAdvertiserCharges([row({ amount_micros: 494_999 })])[0].action, 'skip_below_min', '49.4999c → 49 → skip');
  assert.equal(planAdvertiserCharges([row({ amount_micros: 490_000 })])[0].action, 'skip_below_min', '49c → skip');
});

test('house advertiser is skip_house regardless of amount', () => {
  const rows = [row({ is_house: true, amount_micros: 10_000_000 })]; // €10, but house
  const [p] = planAdvertiserCharges(rows);
  assert.equal(p.action, 'skip_house');
});

test('multiple advertisers are grouped + decided INDEPENDENTLY', () => {
  const rows = [
    ...Array.from({ length: 22 }, () => row({ advertiser_id: 'A', amount_micros: 50000 })), // €1.10 → charge
    ...Array.from({ length: 3 }, () => row({ advertiser_id: 'B', amount_micros: 50000 })),  // €0.15 → skip
    row({ advertiser_id: 'H', is_house: true, amount_micros: 50000 }),                       // house
  ];
  const plans = planAdvertiserCharges(rows);
  const byId = Object.fromEntries(plans.map((p) => [p.advertiser_id, p]));
  assert.equal(byId.A.action, 'charge');
  assert.equal(byId.A.sumCents, 110);
  assert.equal(byId.B.action, 'skip_below_min');
  assert.equal(byId.B.sumCents, 15);
  assert.equal(byId.H.action, 'skip_house');
});

test('groups carry impression_id + publisher_id for stamping + refund lookup', () => {
  const rows = [
    row({ advertiser_id: 'A', entry_group_id: 'g1', impression_id: 'i1', publisher_id: 'p1' }),
    row({ advertiser_id: 'A', entry_group_id: 'g2', impression_id: 'i2', publisher_id: 'p2' }),
  ];
  const [p] = planAdvertiserCharges(rows);
  assert.deepEqual(p.groups.map((g) => g.impression_id).sort(), ['i1', 'i2']);
  assert.deepEqual(p.groups.map((g) => g.publisher_id).sort(), ['p1', 'p2']);
});

test('advertiser_name + stripe_customer_id are carried onto the plan', () => {
  const rows = [row({ advertiser_id: 'A', advertiser_name: 'Acme', stripe_customer_id: 'cus_1' })];
  const [p] = planAdvertiserCharges(rows);
  assert.equal(p.advertiser_name, 'Acme');
  assert.equal(p.stripe_customer_id, 'cus_1');
});

test('sum is authoritative: sumMicros is the exact total; sumCents = round(total/10000)', () => {
  const rows = [
    row({ advertiser_id: 'A', amount_micros: 333_333 }),
    row({ advertiser_id: 'A', amount_micros: 333_333 }),
    row({ advertiser_id: 'A', amount_micros: 333_334 }),
  ];
  const [p] = planAdvertiserCharges(rows);
  assert.equal(p.sumMicros, 1_000_000);
  assert.equal(p.sumCents, 100);
  assert.equal(p.action, 'charge');
});

test('numeric-string amount_micros is coerced (defensive against PostgREST numeric JSON)', () => {
  const rows = Array.from({ length: 10 }, () => row({ advertiser_id: 'A', amount_micros: '50000' }));
  const [p] = planAdvertiserCharges(rows);
  assert.equal(p.sumMicros, 500_000);
  assert.equal(p.action, 'charge');
});

test('empty input → empty plan list', () => {
  assert.deepEqual(planAdvertiserCharges([]), []);
  assert.deepEqual(planAdvertiserCharges(undefined), []);
});

test('minCents is configurable (defends against a silent Stripe-minimum change)', () => {
  const rows = [row({ amount_micros: 500_000 })]; // 50c
  assert.equal(planAdvertiserCharges(rows, { minCents: 100 })[0].action, 'skip_below_min', '50c < 100c min');
  assert.equal(planAdvertiserCharges(rows, { minCents: 50 })[0].action, 'charge');
});
