// test/sec-client-window.test.mjs — SECURITY-AUDIT HARDENING (A-farming, client trust loop).
// Regression locks on src/client/window.mjs trust-relevant behavior.
//
// NOTE: the hardening diff to window.mjs is COMMENT-ONLY (it documents that the heartbeat chain
// SEQUENCES beats + gives third-party tamper-evidence, but is NOT an attention proof vs the
// publisher — the real anti-farm gate is server-side). So these are behavior LOCKS, not
// fail-before-fix tests: they nail down the two invariants the audit relied on staying true —
//   (1) the click URL (and line/label) come ONLY from the SIGNED adData, never an unsigned
//       envelope field, and the ad must be BOUND to this window (adData.windowId === windowId);
//   (2) the beat HMAC chain is correctly SEQUENCED (seq increments, prevHash chains).
//
// Hermetic: `node --test`, node: builtins only. post + verifyAd are injected.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { step } from '../src/client/window.mjs';

const cfgOK = { cooldownMs: 15000, verifyAd: () => true };

// Envelope whose SIGNED adData carries the real clickUrl, plus a DECOY unsigned top-level clickUrl
// that must be ignored. Also lets us corrupt the adData.windowId to test binding.
function fakePost({ signedClickUrl = 'http://x/c/SIGNED', decoyClickUrl = 'http://evil/c/DECOY', adWindowId = 'w1' } = {}) {
  const calls = [];
  const adData = JSON.stringify({
    windowId: adWindowId,
    line: 'Matei is the best',
    label: 'sponsored',
    clickUrl: signedClickUrl,
  });
  const post = async (path, body) => {
    calls.push({ path, body });
    if (path === '/window/open') {
      return {
        windowId: 'w1',
        challenge: 'ch',
        nonce: 'n',
        dwellMs: 5000,
        hbIntervalMs: 1000,
        adData,
        sig: 'sig',
        clickUrl: decoyClickUrl,   // UNSIGNED decoy at the envelope top level — must be ignored
        line: 'HACKED LINE',       // UNSIGNED decoy — must be ignored
      };
    }
    return { ok: true };
  };
  return { post, calls };
}

test('sec client: clickUrl + line come from SIGNED adData, not the unsigned envelope decoys', () => {
  return (async () => {
    const { post } = fakePost();
    const r = await step({ state: null, now: 1000, activity: 1, post, cfg: cfgOK });
    assert.equal(r.clickUrl, 'http://x/c/SIGNED');
    assert.equal(r.state.clickUrl, 'http://x/c/SIGNED');
    assert.notEqual(r.clickUrl, 'http://evil/c/DECOY');
    assert.match(r.status, /Matei is the best/);
    assert.doesNotMatch(r.status, /HACKED LINE/);
  })();
});

test('sec client: signature failure refuses to render — no state, no status', async () => {
  const { post } = fakePost();
  const r = await step({ state: null, now: 1000, activity: 1, post, cfg: { cooldownMs: 15000, verifyAd: () => false } });
  assert.equal(r.verifyFail, true);
  assert.equal(r.status, null);
  assert.equal(r.state, null);
});

test('sec client: ad NOT bound to this window (adData.windowId mismatch) is refused', async () => {
  const { post } = fakePost({ adWindowId: 'w_OTHER' });
  const r = await step({ state: null, now: 1000, activity: 1, post, cfg: cfgOK });
  assert.equal(r.verifyFail, true);
  assert.equal(r.status, null);
  assert.equal(r.state, null);
});

test('sec client: verifyAd receives the signed adData + sig + keyid (envelope decoys not substituted)', async () => {
  const seen = [];
  const cfg = { cooldownMs: 15000, verifyAd: (adData, sig, keyid) => { seen.push({ adData, sig, keyid }); return true; } };
  const { post } = fakePost();
  await step({ state: null, now: 1000, activity: 1, post, cfg });
  assert.equal(seen.length, 1);
  assert.match(seen[0].adData, /SIGNED/);          // the signed blob, not the decoy
  assert.equal(seen[0].sig, 'sig');
});

test('sec client: beat chain SEQUENCES — seq increments and prevHash chains per beat', async () => {
  const { post, calls } = fakePost();
  let r = await step({ state: null, now: 1000, activity: 1, post, cfg: cfgOK });
  const hashes = [r.state.prevHash]; // window open seeds prevHash = windowId
  for (let i = 1; i <= 3; i++) {
    r = await step({ state: r.state, now: 1000 + i * 1000, activity: 1 + i, post, cfg: cfgOK });
    assert.equal(r.state.seq, i, `seq must be ${i} after beat ${i}`);
    hashes.push(r.state.prevHash);
  }
  const beats = calls.filter((c) => c.path === '/window/beat');
  assert.deepEqual(beats.map((b) => b.body.seq), [1, 2, 3]); // strictly sequenced
  // prevHash advances each beat (chain), and the wire never carries raw activity — only a bucket.
  assert.equal(new Set(hashes).size, hashes.length, 'each beat must produce a distinct chained hash');
  for (const b of beats) {
    assert.ok(['none', 'low', 'med', 'high'].includes(b.body.activityDelta));
    assert.equal(Object.prototype.hasOwnProperty.call(b.body, 'activity'), false); // no raw activity leaks
  }
});
