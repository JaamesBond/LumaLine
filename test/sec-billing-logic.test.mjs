// test/sec-billing-logic.test.mjs — SECURITY-AUDIT HARDENING regression locks for the pure
// billing decision helpers (supabase/functions/_shared/billing-logic.mjs).
//
// Hermetic: `node --test`, node: builtins only, no DB / no Deno / no Stripe. Imports the REAL
// shared module so these exercise production logic, not a copy.
//
// Covers:
//   F4/A7  microsToCents — must FLOOR, never round up (no phantom overcharge; Σ⌊gᵢ⌋ ≤ ⌊Σ⌋).
//   A1     shouldAdoptPi — only live/settled PIs are adopted; canceled/needs-PM => fresh create.
//   A11    chooseSettleRoute — recovery honors the FROZEN settle_mode, not the advertiser's
//          current billing_mode (a mode flip mid-batch must not double-collect).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  microsToCents,
  shouldAdoptPi,
  chooseSettleRoute,
} from '../supabase/functions/_shared/billing-logic.mjs';

// ---------------------------------------------------------------------------
// F4 — microsToCents FLOORS (pre-fix Math.round would round 49.5c up to 50c)
// ---------------------------------------------------------------------------

test('sec F4: 495_000 micros (49.5c) FLOORS to 49 — never rounds up to 50 (phantom overcharge)', () => {
  // Pre-fix (Math.round): 49.5 -> 50. This assertion FAILS pre-fix, PASSES post-fix.
  assert.equal(microsToCents(495_000), 49);
});

test('sec F4: 1_105_000 micros (110.5c) FLOORS to 110 — never 111', () => {
  assert.equal(microsToCents(1_105_000), 110);
});

test('sec F4: 999_999 micros (99.9999c) FLOORS to 99 — never rounds up to 100', () => {
  // Pre-fix (Math.round): 99.9999 -> 100. FAILS pre-fix, PASSES post-fix.
  assert.equal(microsToCents(999_999), 99);
});

test('sec F4: cent-aligned + sub-cent-floor inputs unchanged (floor == round there)', () => {
  assert.equal(microsToCents(494_999), 49);   // 49.4999 -> 49 either way
  assert.equal(microsToCents(500_000), 50);   // exact
  assert.equal(microsToCents(1_100_000), 110);
  assert.equal(microsToCents(0), 0);
});

test('sec F4: Σ⌊gᵢ⌋ ≤ ⌊Σgᵢ⌋ — per-group floors can never cumulatively exceed the batch floor', () => {
  // Three groups summing to exactly 100c; the sub-cent remainders must be dropped, not rounded up.
  const groups = [333_333, 333_333, 333_334];
  const sumMicros = groups.reduce((a, b) => a + b, 0); // 1_000_000
  const batchCents = microsToCents(sumMicros);
  const perGroupCents = groups.map(microsToCents).reduce((a, b) => a + b, 0);
  assert.equal(batchCents, 100);
  assert.ok(perGroupCents <= batchCents, `Σ⌊gᵢ⌋ (${perGroupCents}) must be ≤ ⌊Σ⌋ (${batchCents})`);
  assert.equal(perGroupCents, 99); // 33 + 33 + 33 — the residual cent is honestly under-billed
});

// ---------------------------------------------------------------------------
// A1 — shouldAdoptPi: adopt only PIs where money has moved / is moving
// ---------------------------------------------------------------------------

test('sec A1: adopts succeeded / processing / requires_capture PaymentIntents', () => {
  assert.equal(shouldAdoptPi('succeeded'), true);
  assert.equal(shouldAdoptPi('processing'), true);
  assert.equal(shouldAdoptPi('requires_capture'), true);
});

test('sec A1: does NOT adopt canceled / requires_payment_method / unknown — a fresh create is correct', () => {
  assert.equal(shouldAdoptPi('canceled'), false);
  assert.equal(shouldAdoptPi('requires_payment_method'), false);
  assert.equal(shouldAdoptPi('requires_confirmation'), false);
  assert.equal(shouldAdoptPi(undefined), false);
  assert.equal(shouldAdoptPi(null), false);
  assert.equal(shouldAdoptPi(''), false);
});

// ---------------------------------------------------------------------------
// A11 — chooseSettleRoute: recovery honors the FROZEN route
// ---------------------------------------------------------------------------

test('sec A11: frozen settle_mode is honored regardless of the advertiser current billing_mode', () => {
  // Batch reserved as prepay, advertiser later flipped to postpay -> MUST still settle prepay.
  assert.equal(chooseSettleRoute('prepay', 'postpay'), 'prepay');
  // Batch reserved as postpay, advertiser later flipped to prepay -> MUST still settle postpay
  // (else it would draw prepay AND charge the PI = double-collect).
  assert.equal(chooseSettleRoute('postpay', 'prepay'), 'postpay');
});

test('sec A11: legacy rows (settle_mode NULL) fall back to the advertiser current billing_mode', () => {
  assert.equal(chooseSettleRoute(null, 'prepay'), 'prepay');
  assert.equal(chooseSettleRoute(null, 'postpay'), 'postpay');
  assert.equal(chooseSettleRoute(undefined, undefined), 'postpay'); // safe default
  assert.equal(chooseSettleRoute('garbage', 'prepay'), 'prepay');   // unknown frozen -> fallback
});
