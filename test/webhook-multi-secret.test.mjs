// test/webhook-multi-secret.test.mjs — parseWebhookSecrets (Task 6, M4).
//
// Hermetic unit test for the comma-split/trim/drop-empties helper that lets
// stripe-connect/index.ts verify a webhook signature against MULTIPLE configured
// secrets (a connected-account endpoint + a platform-scoped endpoint), while a single
// configured secret must keep working unchanged (backward compat).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseWebhookSecrets } from '../supabase/functions/_shared/webhook-secrets.mjs';

test('splits, trims, drops empties', () => {
  assert.deepEqual(parseWebhookSecrets('whsec_a, whsec_b ,, whsec_c '), ['whsec_a', 'whsec_b', 'whsec_c']);
});
test('single secret → one element', () => {
  assert.deepEqual(parseWebhookSecrets('whsec_only'), ['whsec_only']);
});
test('empty → empty array', () => {
  assert.deepEqual(parseWebhookSecrets(''), []);
  assert.deepEqual(parseWebhookSecrets('   '), []);
});
