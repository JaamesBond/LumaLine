// test/clicks.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createClickTracker } from '../src/server/clicks.mjs';

const setup = (known = true) => createClickTracker({
  secret: 's3cr3t',
  isWindowKnown: () => known,
  now: () => 1000,
});

test('mint -> resolve returns destination once', () => {
  const ct = setup();
  const token = ct.mint({ windowId: 'w1', adId: 'a1', dest: 'https://example.com/x' });
  const r1 = ct.resolve(token);
  assert.deepEqual(r1, { ok: true, dest: 'https://example.com/x' });
  const r2 = ct.resolve(token);                 // dedupe
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /dup/);
});

test('rejects tampered token', () => {
  const ct = setup();
  const token = ct.mint({ windowId: 'w1', adId: 'a1', dest: 'https://example.com/x' });
  assert.equal(ct.resolve(token.slice(0, -2) + 'zz').ok, false);
});

test('rejects click for unknown window', () => {
  const ct = setup(false);
  const token = ct.mint({ windowId: 'w9', adId: 'a1', dest: 'https://example.com/x' });
  const r = ct.resolve(token);
  assert.equal(r.ok, false);
  assert.match(r.reason, /window/);
});

// --- regression: trust-gate findings ---

test('dedupe cannot be bypassed by appending junk to the token', () => {
  const ct = setup();
  const token = ct.mint({ windowId: 'w1', adId: 'a1', dest: 'https://example.com/x' });
  assert.equal(ct.resolve(token).ok, true);            // one legitimate click
  for (const suffix of ['.x', '.y', '.', '.0', '.replay']) {
    const r = ct.resolve(token + suffix);
    assert.equal(r.ok, false, `suffix ${suffix} must not re-bill`);
    assert.match(r.reason, /malformed/);               // strict 2-part shape
  }
});

test('refuses to mint a non-http(s) destination (no open redirect / js: / data:)', () => {
  const ct = setup();
  for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', 'not a url']) {
    assert.throws(() => ct.mint({ windowId: 'w1', adId: 'a1', dest: bad }), /unsafe dest/);
  }
});

test('requires a secret', () => {
  assert.throws(() => createClickTracker({ secret: '', isWindowKnown: () => true }), /secret/);
});
