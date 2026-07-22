// test/sec-ratelimit.test.mjs — SECURITY-AUDIT HARDENING (A-farming). Pure in-memory fixed-window
// rate limiter (supabase/functions/_shared/ratelimit.mjs), the per-isolate cost/abuse floor used
// when the durable salted-IP DB limiter (rl_hit) is unconfigured/unavailable.
//
// Hermetic + deterministic: caller supplies `now`, no timers. Module is NEW -> pre-fix imports
// fail (whole suite fails); post-fix they pass.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryLimiter } from '../supabase/functions/_shared/ratelimit.mjs';

test('sec RL: allows up to max within a window, rejects the overflow', () => {
  const rl = createMemoryLimiter({ max: 3, windowMs: 1000 });
  assert.equal(rl.hit('ip', 0), true);
  assert.equal(rl.hit('ip', 100), true);
  assert.equal(rl.hit('ip', 200), true);
  assert.equal(rl.hit('ip', 300), false); // 4th in-window -> over budget
  assert.equal(rl.hit('ip', 999), false); // still over for the rest of the window
});

test('sec RL: refills after the window elapses', () => {
  const rl = createMemoryLimiter({ max: 1, windowMs: 1000 });
  assert.equal(rl.hit('ip', 0), true);
  assert.equal(rl.hit('ip', 500), false);
  assert.equal(rl.hit('ip', 1000), true); // new window at exactly windowMs
  assert.equal(rl.hit('ip', 1500), false);
});

test('sec RL: separate keys have separate budgets', () => {
  const rl = createMemoryLimiter({ max: 1, windowMs: 1000 });
  assert.equal(rl.hit('a', 0), true);
  assert.equal(rl.hit('b', 0), true);
  assert.equal(rl.hit('a', 0), false);
  assert.equal(rl.hit('b', 0), false);
});

test('sec RL: empty/falsy key is always allowed (no signal -> caller decides)', () => {
  const rl = createMemoryLimiter({ max: 1, windowMs: 1000 });
  assert.equal(rl.hit('', 0), true);
  assert.equal(rl.hit('', 0), true);
  assert.equal(rl.hit(null, 0), true);
  assert.equal(rl.hit(undefined, 0), true);
});

test('sec RL: prune drops expired buckets so the Map cannot grow unbounded', () => {
  const rl = createMemoryLimiter({ max: 5, windowMs: 1000 });
  rl.hit('a', 0);
  rl.hit('b', 0);
  assert.equal(rl.size(), 2);
  rl.prune(2000); // both windows expired
  assert.equal(rl.size(), 0);
});
