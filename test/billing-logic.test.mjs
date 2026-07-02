// test/billing-logic.test.mjs — live-mode payment-method resolution (M5 go-live prep).
//
// Hermetic unit tests for supabase/functions/_shared/billing-logic.mjs, the pure module
// the billing edge function uses to pick the payment method for a charge. Imports the
// REAL shared module (same precedent as test/webhook-multi-secret.test.mjs) — no network,
// no Stripe, no Deno.
//
// THE CRITICAL INVARIANT: live mode must NEVER resolve to the Stripe test token
// pm_card_visa. A live PaymentIntent against a test token would be a broken charge at
// best and dishonest billing at worst — live with no saved PM must SKIP.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isLiveKey,
  choosePaymentMethod,
  TEST_FALLBACK_PM,
} from '../supabase/functions/_shared/billing-logic.mjs';

// ---------------------------------------------------------------------------
// isLiveKey — key-prefix classification
// ---------------------------------------------------------------------------

test('billing-logic: isLiveKey true for sk_live_ keys', () => {
  assert.equal(isLiveKey('sk_live_abc123'), true);
});

test('billing-logic: isLiveKey true for rk_live_ restricted keys', () => {
  assert.equal(isLiveKey('rk_live_abc123'), true);
});

test('billing-logic: isLiveKey false for sk_test_ and rk_test_ keys', () => {
  assert.equal(isLiveKey('sk_test_abc123'), false);
  assert.equal(isLiveKey('rk_test_abc123'), false);
});

test('billing-logic: isLiveKey false for empty / garbage / non-string input', () => {
  assert.equal(isLiveKey(''), false);
  assert.equal(isLiveKey('whsec_notakey'), false);
  assert.equal(isLiveKey(undefined), false);
  assert.equal(isLiveKey(null), false);
  assert.equal(isLiveKey(12345), false);
});

test('billing-logic: isLiveKey false when live marker is not a prefix', () => {
  assert.equal(isLiveKey('xsk_live_abc'), false);
});

// ---------------------------------------------------------------------------
// THE CRITICAL ONE — live mode never returns pm_card_visa
// ---------------------------------------------------------------------------

test('billing-logic: LIVE with no PMs at all skips — never pm_card_visa', () => {
  const r = choosePaymentMethod({
    liveMode: true,
    defaultPaymentMethodId: null,
    attachedPaymentMethodIds: [],
  });
  assert.deepEqual(r, { skip: 'no_payment_method' });
});

test('billing-logic: LIVE never returns pm_card_visa under any input shape', () => {
  const inputs = [
    { defaultPaymentMethodId: null, attachedPaymentMethodIds: [] },
    { defaultPaymentMethodId: undefined, attachedPaymentMethodIds: undefined },
    { defaultPaymentMethodId: '', attachedPaymentMethodIds: ['', '  '] },
    {}, // missing fields entirely
    // Even a poisoned input where the test token appears as "saved"/"attached":
    { defaultPaymentMethodId: TEST_FALLBACK_PM, attachedPaymentMethodIds: [] },
    { defaultPaymentMethodId: null, attachedPaymentMethodIds: [TEST_FALLBACK_PM] },
  ];
  for (const input of inputs) {
    const r = choosePaymentMethod({ liveMode: true, ...input });
    assert.ok(
      !('pm' in r) || r.pm !== TEST_FALLBACK_PM,
      `live mode leaked ${TEST_FALLBACK_PM} for input ${JSON.stringify(input)}`,
    );
  }
});

test('billing-logic: LIVE guard converts a poisoned pm_card_visa default into a skip', () => {
  const r = choosePaymentMethod({
    liveMode: true,
    defaultPaymentMethodId: TEST_FALLBACK_PM,
    attachedPaymentMethodIds: [],
  });
  assert.deepEqual(r, { skip: 'no_payment_method' });
});

// ---------------------------------------------------------------------------
// Precedence: saved default PM wins over attached
// ---------------------------------------------------------------------------

test('billing-logic: saved default PM wins over attached PMs (live)', () => {
  const r = choosePaymentMethod({
    liveMode: true,
    defaultPaymentMethodId: 'pm_default_111',
    attachedPaymentMethodIds: ['pm_attached_222', 'pm_attached_333'],
  });
  assert.deepEqual(r, { pm: 'pm_default_111' });
});

test('billing-logic: saved default PM wins over attached PMs (test mode too)', () => {
  const r = choosePaymentMethod({
    liveMode: false,
    defaultPaymentMethodId: 'pm_default_111',
    attachedPaymentMethodIds: ['pm_attached_222'],
  });
  assert.deepEqual(r, { pm: 'pm_default_111' });
});

// ---------------------------------------------------------------------------
// Fallback: first attached PM when no default
// ---------------------------------------------------------------------------

test('billing-logic: no default → first attached PM is used (live)', () => {
  const r = choosePaymentMethod({
    liveMode: true,
    defaultPaymentMethodId: null,
    attachedPaymentMethodIds: ['pm_attached_222', 'pm_attached_333'],
  });
  assert.deepEqual(r, { pm: 'pm_attached_222' });
});

test('billing-logic: blank/garbage attached entries are ignored when picking first', () => {
  const r = choosePaymentMethod({
    liveMode: true,
    defaultPaymentMethodId: '',
    attachedPaymentMethodIds: ['', '   ', 'pm_real_444'],
  });
  assert.deepEqual(r, { pm: 'pm_real_444' });
});

// ---------------------------------------------------------------------------
// Test-mode fallback: pm_card_visa only when NOT live and nothing saved
// (preserves every existing test + the test-mode e2e)
// ---------------------------------------------------------------------------

test('billing-logic: test mode with no PMs falls back to pm_card_visa', () => {
  const r = choosePaymentMethod({
    liveMode: false,
    defaultPaymentMethodId: null,
    attachedPaymentMethodIds: [],
  });
  assert.deepEqual(r, { pm: 'pm_card_visa' });
});

test('billing-logic: test mode prefers a real attached PM over the fallback', () => {
  const r = choosePaymentMethod({
    liveMode: false,
    defaultPaymentMethodId: null,
    attachedPaymentMethodIds: ['pm_attached_555'],
  });
  assert.deepEqual(r, { pm: 'pm_attached_555' });
});

test('billing-logic: liveMode must be exactly true to be live — non-boolean is test-safe', () => {
  // Fail-safe direction: only an explicit `true` disables the test fallback; but the
  // fallback token is still harmless in test mode, so truthy-garbage stays test mode.
  const r = choosePaymentMethod({
    liveMode: undefined,
    defaultPaymentMethodId: null,
    attachedPaymentMethodIds: [],
  });
  assert.deepEqual(r, { pm: 'pm_card_visa' });
});

// ---------------------------------------------------------------------------
// Skip path shape
// ---------------------------------------------------------------------------

test('billing-logic: skip result has exact reason string no_payment_method', () => {
  const r = choosePaymentMethod({ liveMode: true });
  assert.ok('skip' in r);
  assert.equal(r.skip, 'no_payment_method');
  assert.ok(!('pm' in r), 'skip result must not carry a pm');
});

test('billing-logic: pm result never carries a skip field', () => {
  const r = choosePaymentMethod({
    liveMode: true,
    defaultPaymentMethodId: 'pm_default_111',
  });
  assert.ok('pm' in r);
  assert.ok(!('skip' in r));
});
