// test/windows.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hmacHex } from '../src/lib/crypto.mjs';
import { createWindowStore } from '../src/server/windows.mjs';

function beatsFor(store, win, { count, activity = 'up', clock, spacing }) {
  let prev = win.windowId;
  for (let seq = 1; seq <= count; seq++) {
    clock.t += spacing ?? win.hbIntervalMs;        // advance between beats (default ~1s)
    const hmac = hmacHex(win.challenge, `${seq}|${prev}|${activity}`);
    store.beat({ windowId: win.windowId, seq, hmac, activityDelta: activity });
    prev = hmac;
  }
}

test('credits a well-formed, activity-backed window', () => {
  const clock = { t: 1000 };
  const store = createWindowStore({ now: () => clock.t });
  const win = store.open({ sessionId: 's1', activitySnapshot: 'a0' });
  beatsFor(store, win, { count: 5, activity: 'up', clock });
  const res = store.close({ windowId: win.windowId });
  assert.equal(res.credited, true);
  assert.equal(res.attentionSeconds, 5);
});

test('rejects batched beats (no real wall-clock spacing)', () => {
  const clock = { t: 1000 };
  const store = createWindowStore({ now: () => clock.t });
  const win = store.open({ sessionId: 's1', activitySnapshot: 'a0' });
  // all beats at the same instant -> anti-batch violation
  let prev = win.windowId;
  for (let seq = 1; seq <= 5; seq++) {
    const hmac = hmacHex(win.challenge, `${seq}|${prev}|up`);
    assert.throws(() => store.beat({ windowId: win.windowId, seq, hmac, activityDelta: 'up' }));
    prev = hmac;
  }
});

test('does not credit without activity progress', () => {
  const clock = { t: 1000 };
  const store = createWindowStore({ now: () => clock.t });
  const win = store.open({ sessionId: 's1', activitySnapshot: 'a0' });
  beatsFor(store, win, { count: 5, activity: 'none', clock });
  const res = store.close({ windowId: win.windowId });
  assert.equal(res.credited, false);
  assert.match(res.reason, /activity/);
});

test('rejects a forged hmac chain', () => {
  const clock = { t: 1000 };
  const store = createWindowStore({ now: () => clock.t });
  const win = store.open({ sessionId: 's1', activitySnapshot: 'a0' });
  clock.t += win.hbIntervalMs;
  assert.throws(() => store.beat({ windowId: win.windowId, seq: 1, hmac: 'deadbeef', activityDelta: 'up' }));
});

test('does not credit below minBeats', () => {
  const clock = { t: 1000 };
  const store = createWindowStore({ now: () => clock.t });
  const win = store.open({ sessionId: 's1', activitySnapshot: 'a0' });
  beatsFor(store, win, { count: 2, activity: 'up', clock });
  const res = store.close({ windowId: win.windowId });
  assert.equal(res.credited, false);
  assert.match(res.reason, /beats/);
});

// --- regression: trust-gate findings ---

test('close is idempotent — a window credits at most once (no double-bill)', () => {
  const clock = { t: 1000 };
  const store = createWindowStore({ now: () => clock.t });
  const win = store.open({ sessionId: 's1', activitySnapshot: 'a0' });
  beatsFor(store, win, { count: 5, activity: 'up', clock });
  const first = store.close({ windowId: win.windowId });
  const second = store.close({ windowId: win.windowId });
  const third = store.close({ windowId: win.windowId });
  assert.equal(first.credited, true);
  assert.equal(second.credited, false);
  assert.match(second.reason, /already closed/);
  assert.equal(third.credited, false);
});

test('does not credit before the full dwell elapses (anti-batch floor != full dwell)', () => {
  const clock = { t: 1000 };
  const store = createWindowStore({ now: () => clock.t, minBeats: 3, minSpacingMs: 500, dwellMs: 5000 });
  const win = store.open({ sessionId: 's1', activitySnapshot: 'a0' });
  // 3 valid, anti-batch-respecting beats over only ~1.5s, then close well before dwell.
  beatsFor(store, win, { count: 3, activity: 'up', clock, spacing: 500 });
  const res = store.close({ windowId: win.windowId });   // elapsed ~1500ms < 5000ms
  assert.equal(res.credited, false);
  assert.match(res.reason, /dwell too short/);
});
