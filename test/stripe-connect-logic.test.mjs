// test/stripe-connect-logic.test.mjs — hermetic unit tests for the payout money-decision
// helpers (no stack, no Stripe). These guard the CRITICAL rules from the adversarial review:
// the double-pay-safe error classification, reversal-net reconciliation, and amount-aware
// reversal math.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyTransferError,
  sumLumalineTransfersMicros,
  reversedMicrosFromTransfer,
} from '../supabase/functions/_shared/payout-logic.mjs';

// --- classifyTransferError: only a pure param rejection is "definitive" ----------------

test('a StripeInvalidRequestError is definitive (no transfer was created)', () => {
  assert.equal(classifyTransferError({ type: 'StripeInvalidRequestError', code: 'parameter_invalid' }), 'definitive');
});

test('an invalid_request_error rawType (Deno SDK shape) is definitive — e.g. insufficient_capabilities', () => {
  // The Deno esm.sh build surfaces err.rawType (snake) rather than the SDK class name.
  assert.equal(classifyTransferError({ rawType: 'invalid_request_error', code: 'insufficient_capabilities_for_transfer' }), 'definitive');
});

test('a connection error is ambiguous (a transfer may exist -> never auto-fail)', () => {
  assert.equal(classifyTransferError({ type: 'StripeConnectionError' }), 'ambiguous');
});

test('an idempotency-in-progress error is ambiguous (the transfer may be landing)', () => {
  assert.equal(classifyTransferError({ type: 'StripeIdempotencyError' }), 'ambiguous');
  assert.equal(classifyTransferError({ type: 'StripeInvalidRequestError', code: 'idempotency_error' }), 'ambiguous');
});

test('a 5xx / API error is ambiguous', () => {
  assert.equal(classifyTransferError({ type: 'StripeAPIError', statusCode: 500 }), 'ambiguous');
});

test('an unknown / null error defaults to ambiguous (safe: bias against double-pay)', () => {
  assert.equal(classifyTransferError(null), 'ambiguous');
  assert.equal(classifyTransferError(undefined), 'ambiguous');
  assert.equal(classifyTransferError('boom'), 'ambiguous');
  assert.equal(classifyTransferError({}), 'ambiguous');
});

// --- sumLumalineTransfersMicros: NET of reversals, lumaline-tagged only -----------------

test('sums only lumaline-tagged transfers, in micros', () => {
  const xfers = [
    { amount: 2500, metadata: { source: 'lumaline' } },     // $25.00
    { amount: 9999, metadata: { source: 'other' } },        // ignored
    { amount: 1000, metadata: {} },                         // ignored
    { amount: 500 },                                        // ignored (no metadata)
  ];
  assert.equal(sumLumalineTransfersMicros(xfers), 2500 * 10000);
});

test('subtracts amount_reversed so a fully-reversed transfer contributes 0', () => {
  const xfers = [
    { amount: 3000, amount_reversed: 3000, metadata: { source: 'lumaline' } }, // fully reversed -> 0
    { amount: 2500, amount_reversed: 500, metadata: { source: 'lumaline' } },  // net 2000
  ];
  assert.equal(sumLumalineTransfersMicros(xfers), 2000 * 10000);
});

test('handles empty / null input', () => {
  assert.equal(sumLumalineTransfersMicros([]), 0);
  assert.equal(sumLumalineTransfersMicros(null), 0);
});

// --- reversedMicrosFromTransfer: cumulative reversed -> micros --------------------------

test('uses cumulative amount_reversed when present', () => {
  assert.equal(reversedMicrosFromTransfer({ amount: 3000, amount_reversed: 1000 }), 1000 * 10000);
});

test('falls back to full amount when amount_reversed is absent', () => {
  assert.equal(reversedMicrosFromTransfer({ amount: 3000 }), 3000 * 10000);
  assert.equal(reversedMicrosFromTransfer({}), 0);
});

// ---- resolveOnboardCountry (fix: NULL country must ask, never default to US) ------------
test('resolveOnboardCountry: precedence is body > stored > header', async () => {
  const { resolveOnboardCountry } = await import('../supabase/functions/_shared/payout-logic.mjs');
  assert.equal(resolveOnboardCountry('NL', 'RO', 'DE'), 'NL');
  assert.equal(resolveOnboardCountry(undefined, 'RO', 'DE'), 'RO');
  assert.equal(resolveOnboardCountry(undefined, null, 'DE'), 'DE');
});

test('resolveOnboardCountry: normalizes case and whitespace', async () => {
  const { resolveOnboardCountry } = await import('../supabase/functions/_shared/payout-logic.mjs');
  assert.equal(resolveOnboardCountry(' nl ', null, null), 'NL');
  assert.equal(resolveOnboardCountry(null, 'ro', null), 'RO');
});

test('resolveOnboardCountry: invalid entries are skipped, not fatal', async () => {
  const { resolveOnboardCountry } = await import('../supabase/functions/_shared/payout-logic.mjs');
  assert.equal(resolveOnboardCountry('USA', 'R1', 'FR'), 'FR');   // 3 letters / digit → skip
  assert.equal(resolveOnboardCountry('', 42, 'be'), 'BE');        // empty / non-string → skip
  assert.equal(resolveOnboardCountry({}, [], null), null);
});

test('resolveOnboardCountry: all unknown → null (ask the user; NEVER a default)', async () => {
  const { resolveOnboardCountry } = await import('../supabase/functions/_shared/payout-logic.mjs');
  assert.equal(resolveOnboardCountry(undefined, null, undefined), null);
  assert.equal(resolveOnboardCountry(null, null, ''), null);
});
