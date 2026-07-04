import test from 'node:test';
import assert from 'node:assert/strict';
import { constantTimeEqual, payoutMinMicros } from '../supabase/functions/_shared/payout-logic.mjs';

test('constantTimeEqual: equal strings true, any diff false, length-mismatch false', () => {
  assert.equal(constantTimeEqual('abc123', 'abc123'), true);
  assert.equal(constantTimeEqual('abc123', 'abc124'), false);
  assert.equal(constantTimeEqual('abc', 'abcd'), false);
  assert.equal(constantTimeEqual('', ''), false);   // empty never authorizes
});

test('payoutMinMicros: default €1 on absent/garbage/negative, honors valid', () => {
  assert.equal(payoutMinMicros(undefined), 1000000);
  assert.equal(payoutMinMicros(''), 1000000);
  assert.equal(payoutMinMicros('nope'), 1000000);
  assert.equal(payoutMinMicros('-5'), 1000000);
  assert.equal(payoutMinMicros('0'), 1000000);      // 0 would pay dust → clamp to default
  assert.equal(payoutMinMicros('5000000'), 5000000);
  assert.equal(payoutMinMicros(2500000), 2500000);
});
