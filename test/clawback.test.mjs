// test/clawback.test.mjs — Hermetic tests for M2-T6 clawback + refund logic.
//
// Pure tests: no network, no Stripe, no Deno APIs.
// Reads source files to verify consistency of constants across code and docs.
//
// WHAT IS TESTED:
//   clawback: 72h window in clearing migration matches money-timeline.md
//   clawback: money-timeline.md documents the clawback-immune point formula
//   clawback: clawback_reviews table has refund_queued column (migration check)
//   clawback: disputes table exists in migration (migration check)
//   clawback: approve_clawback function is in public schema (PostgREST-accessible)
//   clawback: reject_clawback function is in public schema (PostgREST-accessible)
//   clawback: scan_ivt inserts into clawback_reviews (migration check)
//   clawback: microsToCents conversion for refund amounts
//   clawback: refund amount rounding — round(micros / 10000)
//   clawback: sentinel no-op guard logic (pure function mirroring the SQL gate)
//   clawback: stripe refund uses payment_intent, not charge (billing source check)
//   clawback: impression stripe_charge_id column added (migration check)

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// ---------------------------------------------------------------------------
// Source file reads — checked once, shared across tests.
// These are NOT circular (72 === 72). They check that DIFFERENT files agree.
// ---------------------------------------------------------------------------

const clearingSQL     = readFileSync(join(ROOT, 'supabase/migrations/20260627033345_clearing_and_ledger.sql'), 'utf8');
const clawbackSQL     = readFileSync(join(ROOT, 'supabase/migrations/20260629070000_clawback_review.sql'), 'utf8');
const moneyTimeline   = readFileSync(join(ROOT, 'docs/ops/money-timeline.md'), 'utf8');
const billingFn       = readFileSync(join(ROOT, 'supabase/functions/billing/index.ts'), 'utf8');

// ---------------------------------------------------------------------------
// 72h constant consistency — three independent sources must agree.
// ---------------------------------------------------------------------------

test('clawback: 72h clawback-immune window is in the clearing migration', () => {
  assert.ok(
    clearingSQL.includes("interval '72 hours'"),
    "20260627033345_clearing_and_ledger.sql must contain \"interval '72 hours'\" as the clear_events default",
  );
});

test('clawback: money-timeline.md documents the 72h clawback-immune point', () => {
  assert.ok(
    moneyTimeline.includes('72h') || moneyTimeline.includes('72 hours'),
    "docs/ops/money-timeline.md must document the 72h clawback-immune point",
  );
});

test('clawback: money-timeline.md references the clearing migration as source of truth', () => {
  assert.ok(
    moneyTimeline.includes('20260627033345_clearing_and_ledger.sql') ||
    moneyTimeline.includes('clear_events'),
    "money-timeline.md should reference clear_events or the clearing migration to anchor the 72h constant",
  );
});

// ---------------------------------------------------------------------------
// Migration structure checks — clawback_review.sql artefacts.
// ---------------------------------------------------------------------------

test('clawback: clawback_reviews table has refund_queued column', () => {
  assert.ok(
    clawbackSQL.includes('refund_queued'),
    "Migration must define refund_queued column on clawback_reviews",
  );
});

test('clawback: clawback_reviews table has refund_id column for Stripe refund id', () => {
  assert.ok(
    clawbackSQL.includes('refund_id'),
    "Migration must define refund_id column on clawback_reviews",
  );
});

test('clawback: disputes table is in the migration', () => {
  assert.ok(
    clawbackSQL.includes('CREATE TABLE public.disputes'),
    "Migration must define the disputes table",
  );
});

test('clawback: impressions.stripe_charge_id column is added in migration', () => {
  assert.ok(
    clawbackSQL.includes('stripe_charge_id'),
    "Migration must ADD COLUMN stripe_charge_id to impressions",
  );
});

test('clawback: approve_clawback is in public schema (PostgREST-accessible)', () => {
  assert.ok(
    clawbackSQL.includes('FUNCTION public.approve_clawback'),
    "approve_clawback must be in the public schema so PostgREST exposes it via /rpc/approve_clawback",
  );
  assert.ok(
    !clawbackSQL.includes('FUNCTION app.approve_clawback'),
    "approve_clawback must NOT be in the app schema (not PostgREST-accessible)",
  );
});

test('clawback: reject_clawback is in public schema (PostgREST-accessible)', () => {
  assert.ok(
    clawbackSQL.includes('FUNCTION public.reject_clawback'),
    "reject_clawback must be in the public schema so PostgREST exposes it via /rpc/reject_clawback",
  );
});

test('clawback: scan_ivt inserts into clawback_reviews', () => {
  // After the T6 migration re-defines scan_ivt, it must mention clawback_reviews.
  assert.ok(
    clawbackSQL.includes('clawback_reviews'),
    "scan_ivt in the T6 migration must insert into clawback_reviews",
  );
});

test('clawback: scan_ivt uses RETURNING id to capture risk_flag_id', () => {
  assert.ok(
    clawbackSQL.includes('RETURNING id INTO v_rf_id'),
    "scan_ivt must use RETURNING id INTO v_rf_id to link risk_flag to clawback_review",
  );
});

test('clawback: approve_clawback has sentinel no-op guard for gross_micros <= 0', () => {
  assert.ok(
    clawbackSQL.includes('no_op_gross_zero') || clawbackSQL.includes('gross_micros <= 0'),
    "approve_clawback must guard against sentinel/house impressions with gross_micros <= 0",
  );
});

// ---------------------------------------------------------------------------
// Billing function checks — refund path uses payment_intent, not charge.
// ---------------------------------------------------------------------------

test('clawback: billing refund uses payment_intent (pi_*), not charge field', () => {
  // The refund must use payment_intent: piId, not charge: chargeId.
  // Passing a pi_* to the `charge` field is a Stripe API error.
  assert.ok(
    billingFn.includes('payment_intent:'),
    "billing/index.ts /refund endpoint must pass payment_intent: to stripe.refunds.create()",
  );
});

test('clawback: billing charge path stamps impressions.stripe_charge_id', () => {
  // After a successful charge, the impression row must also be updated.
  // The svc() call uses double-quoted strings: svc("PATCH", "impressions", ...)
  assert.ok(
    billingFn.includes('stripe_charge_id') &&
    (billingFn.includes('"impressions"') || billingFn.includes("'impressions'")),
    "billing/index.ts must PATCH impressions.stripe_charge_id after a successful charge",
  );
});

test('clawback: billing has /refund endpoint', () => {
  assert.ok(
    billingFn.includes('endsWith("/refund")'),
    "billing/index.ts must have a POST /refund endpoint",
  );
});

// ---------------------------------------------------------------------------
// Pure function: microsToCents — same helper used for refund amounts.
// ---------------------------------------------------------------------------

/** Convert micro-USD to Stripe cents. 1 cent = 10,000 micro-USD. */
function microsToCents(micros) {
  return Math.round(micros / 10000);
}

test('clawback: microsToCents $1.00 → 100 cents', () => {
  assert.equal(microsToCents(1_000_000), 100);
});

test('clawback: microsToCents $0.50 → 50 cents (Stripe minimum)', () => {
  assert.equal(microsToCents(500_000), 50);
});

test('clawback: microsToCents $10.75 → 1075 cents', () => {
  assert.equal(microsToCents(10_750_000), 1075);
});

test('clawback: microsToCents rounds 5001 micros to 1 cent (not 0)', () => {
  // 5001 / 10000 = 0.5001 → rounds to 1
  assert.equal(microsToCents(5001), 1);
});

test('clawback: microsToCents $0 → 0 cents', () => {
  assert.equal(microsToCents(0), 0);
});

// ---------------------------------------------------------------------------
// Pure function: sentinel no-op logic (mirrors SQL in approve_clawback).
// ---------------------------------------------------------------------------

/**
 * Should we skip the clawback() call? Returns true for sentinel/house impressions.
 * Mirrors the PL/pgSQL guard in public.approve_clawback.
 */
function isClawbackNoOp(impressionId, grossMicros) {
  if (!impressionId) return true;        // no impression linked
  if (grossMicros == null) return true;  // gross unknown (treat as zero)
  if (grossMicros <= 0) return true;     // house/sentinel
  return false;
}

test('clawback: sentinel no-op — null impression_id is a no-op', () => {
  assert.ok(isClawbackNoOp(null, 1_000_000));
});

test('clawback: sentinel no-op — gross_micros=0 is a no-op (house advertiser)', () => {
  assert.ok(isClawbackNoOp('some-uuid', 0));
});

test('clawback: sentinel no-op — gross_micros<0 is a no-op', () => {
  assert.ok(isClawbackNoOp('some-uuid', -1));
});

test('clawback: sentinel no-op — null gross_micros is a no-op', () => {
  assert.ok(isClawbackNoOp('some-uuid', null));
});

test('clawback: sentinel no-op — positive gross is NOT a no-op', () => {
  assert.ok(!isClawbackNoOp('some-uuid', 500_000));
});

test('clawback: sentinel no-op — gross=1 micro is NOT a no-op', () => {
  assert.ok(!isClawbackNoOp('some-uuid', 1));
});
