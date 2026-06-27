// test/client-window.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { step } from '../src/client/window.mjs';

function fakePost() {
  const calls = [];
  const adData = JSON.stringify({ windowId: 'w1', line: 'Matei is the best', label: 'sponsored', clickUrl: 'http://x/c/t' });
  const post = async (path, body) => {
    calls.push({ path, body });
    if (path === '/window/open') return { windowId: 'w1', challenge: 'ch', nonce: 'n', dwellMs: 5000, hbIntervalMs: 1000, adData, sig: 'sig' };
    return { ok: true };
  };
  return { post, calls };
}

const cfgOK = { cooldownMs: 15000, verifyAd: () => true };

test('first tick opens a window and shows the (verified) ad', async () => {
  const { post, calls } = fakePost();
  const r = await step({ state: null, now: 1000, activity: 1, post, cfg: cfgOK });
  assert.equal(calls[0].path, '/window/open');
  assert.equal(r.state.windowId, 'w1');
  assert.match(r.status, /Matei is the best/);
  assert.equal(r.clickUrl, 'http://x/c/t');
});

test('refuses to render when the ad signature does not verify', async () => {
  const { post } = fakePost();
  const r = await step({ state: null, now: 1000, activity: 1, post, cfg: { cooldownMs: 15000, verifyAd: () => false } });
  assert.equal(r.verifyFail, true);
  assert.equal(r.status, null);
  assert.equal(r.state, null);
});

test('does not send raw activity values to the server (open uses an opaque snapshot)', async () => {
  const { post, calls } = fakePost();
  await step({ state: null, now: 1000, activity: 12345.678, post, cfg: cfgOK });
  assert.equal(calls[0].body.activitySnapshot, 'session');   // not the raw cost/token value
});

test('mid-window tick posts a beat with only a coarse activity bucket', async () => {
  const { post, calls } = fakePost();
  const first = await step({ state: null, now: 1000, activity: 1, post, cfg: cfgOK });
  const second = await step({ state: first.state, now: 2000, activity: 200, post, cfg: cfgOK });
  const beat = calls.at(-1);
  assert.equal(beat.path, '/window/beat');
  assert.equal(beat.body.seq, 1);
  assert.ok(['low', 'med', 'high'].includes(beat.body.activityDelta));
  assert.equal(second.state.seq, 1);
});

test('idle (unchanged activity) reports a none bucket', async () => {
  const { post, calls } = fakePost();
  const first = await step({ state: null, now: 1000, activity: 7, post, cfg: cfgOK });
  await step({ state: first.state, now: 2000, activity: 7, post, cfg: cfgOK });
  assert.equal(calls.at(-1).body.activityDelta, 'none');
});

test('after dwell, posts close once and reverts to base', async () => {
  const { post, calls } = fakePost();
  let s = (await step({ state: null, now: 1000, activity: 1, post, cfg: cfgOK })).state;
  for (let i = 1; i <= 5; i++) s = (await step({ state: s, now: 1000 + i * 1000, activity: 1 + i, post, cfg: cfgOK })).state;
  const done = await step({ state: s, now: 7000, activity: 99, post, cfg: cfgOK });
  assert.ok(calls.some((c) => c.path === '/window/close'));
  assert.equal(done.status, null);
});
