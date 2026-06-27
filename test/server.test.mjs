// test/server.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { hmacHex, verifyData } from '../src/lib/crypto.mjs';
import { createWindowStore } from '../src/server/windows.mjs';
import { startServer } from '../src/server/server.mjs';

let ctx, base, pubPem;
before(async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  ctx = await startServer({
    port: 0,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    clickSecret: 'test-secret',
    // Inject a short dwell so the test credits in ~2.6s while still honoring the
    // anti-batch (>=500ms) and full-dwell gates.
    store: createWindowStore({ dwellMs: 2000 }),
    ad: { adId: 'a1', line: 'Matei is the best', label: 'sponsored', dest: 'https://example.com/x', durationMs: 2000 },
    log: () => {},
  });
  base = `http://127.0.0.1:${ctx.port}`;
});
after(() => ctx.server.close());

const postJson = (path, body) =>
  fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('full window credits one impression; click 302s; re-close does not re-bill', async () => {
  const open = await (await postJson('/window/open', { sessionId: 's1', activitySnapshot: 'session' })).json();
  assert.ok(open.windowId && open.adData && open.sig);
  // The ad payload is ed25519-signed and bound to this window.
  assert.equal(verifyData(open.adData, open.sig, pubPem), true);
  const ad = JSON.parse(open.adData);
  assert.equal(ad.windowId, open.windowId);
  assert.match(ad.line, /Matei is the best/);

  let prev = open.windowId;
  for (let seq = 1; seq <= 5; seq++) {
    await new Promise((r) => setTimeout(r, 520));   // respect anti-batch spacing
    const hmac = hmacHex(open.challenge, `${seq}|${prev}|med`);
    const res = await postJson('/window/beat', { windowId: open.windowId, seq, hmac, activityDelta: 'med' });
    assert.equal(res.status, 200);
    prev = hmac;
  }
  const close = await (await postJson('/window/close', { windowId: open.windowId })).json();
  assert.equal(close.credited, true);

  // Re-close the same window: must NOT credit again (idempotent billing).
  const reclose = await (await postJson('/window/close', { windowId: open.windowId })).json();
  assert.equal(reclose.credited, false);

  const token = ad.clickUrl.split('/c/')[1];
  const click = await fetch(`${base}/c/${token}`, { redirect: 'manual' });
  assert.equal(click.status, 302);
  assert.equal(click.headers.get('location'), 'https://example.com/x');
  // Replaying the same click does not 302 again (dedupe).
  const reclick = await fetch(`${base}/c/${token}`, { redirect: 'manual' });
  assert.equal(reclick.status, 404);
});

test('GET /feed returns a signature-verifiable ad', async () => {
  const r = await (await fetch(`${base}/feed`)).json();
  assert.ok(r.data && r.sig);
  assert.equal(verifyData(r.data, r.sig, pubPem), true);
  assert.equal(JSON.parse(r.data).adId, 'a1');
});

test('a malformed click URL returns 4xx and does NOT crash the server', async () => {
  const bad = await fetch(`${base}/c/%`, { redirect: 'manual' });   // invalid percent-encoding
  assert.equal(bad.status, 400);
  // server still serving afterwards:
  const ok = await fetch(`${base}/feed`);
  assert.equal(ok.status, 200);
});

test('a forged/garbage heartbeat is rejected with a generic 400 (no oracle)', async () => {
  const open = await (await postJson('/window/open', { sessionId: 's2' })).json();
  await new Promise((r) => setTimeout(r, 520));
  const res = await postJson('/window/beat', { windowId: open.windowId, seq: 1, hmac: 'deadbeef', activityDelta: 'up' });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, 'rejected');         // generic; no internal reason leaked
});
