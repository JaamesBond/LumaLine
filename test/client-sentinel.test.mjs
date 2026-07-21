// test/client-sentinel.test.mjs — hermetic unit tests for the anonymous (logged-out) display path
// (src/client/sentinel.mjs). The logged-out client shows a static, signed self-promo line WITHOUT
// opening a server window (the sentinel is gross=0 and can never earn). fetch, clock, verifier, and
// cache are all injected — no network, no filesystem.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sentinelStep } from '../src/client/sentinel.mjs';

const AD = JSON.stringify({ line: 'LumaLine — honest, signed ads for Claude Code', label: 'sponsored', clickUrl: 'https://lumaline.dev' });
const FRESH = { adData: AD, sig: 'sig', keyid: 'k1' };
const okVerify = () => true;
const noVerify = () => false;

test('fresh cache within TTL renders from cache with NO network', async () => {
  let fetched = 0;
  const r = await sentinelStep({
    now: 1000, ttlMs: 10_000, verifyAd: okVerify, showUrl: true,
    cache: { ...FRESH, fetchedAt: 500 },
    fetchLine: async () => { fetched += 1; return FRESH; },
  });
  assert.equal(fetched, 0, 'no fetch when the cache is fresh — this is what kills the per-tick storm');
  assert.match(r.status, /★ LumaLine/);
  assert.match(r.status, /lumaline\.dev/);
  assert.match(r.status, /sponsored/);
  assert.equal(r.clickUrl, 'https://lumaline.dev');
});

test('stale cache triggers exactly ONE fetch, restamps the cache, renders fresh', async () => {
  let fetched = 0;
  const r = await sentinelStep({
    now: 100_000, ttlMs: 10_000, verifyAd: okVerify, showUrl: true,
    cache: { ...FRESH, fetchedAt: 500 },   // ~99.5s old > 10s TTL
    fetchLine: async () => { fetched += 1; return FRESH; },
  });
  assert.equal(fetched, 1);
  assert.equal(r.cache.fetchedAt, 100_000, 'cache is restamped with now');
  assert.match(r.status, /★ LumaLine/);
});

test('missing cache fetches once + renders + populates the cache', async () => {
  const r = await sentinelStep({ now: 1, ttlMs: 10_000, verifyAd: okVerify, showUrl: true, cache: null, fetchLine: async () => FRESH });
  assert.match(r.status, /★ LumaLine/);
  assert.equal(r.cache.adData, AD);
});

test('fetch throws but a usable cache remains → renders the stale cached line (a stale honest line beats a blank)', async () => {
  const r = await sentinelStep({
    now: 100_000, ttlMs: 10_000, verifyAd: okVerify, showUrl: true,
    cache: { ...FRESH, fetchedAt: 500 },
    fetchLine: async () => { throw new Error('network down'); },
  });
  assert.match(r.status, /★ LumaLine/);
  assert.equal(r.cache.fetchedAt, 500, 'the stale cache is kept as-is on a failed refresh');
});

test('fetch fails with NO cache → status null (caller shows its plain base status)', async () => {
  const r = await sentinelStep({ now: 1, ttlMs: 10_000, verifyAd: okVerify, showUrl: true, cache: null, fetchLine: async () => { throw new Error('x'); } });
  assert.equal(r.status, null);
  assert.equal(r.clickUrl, null);
  assert.equal(r.cache, null);
});

test('signed-content-only: an UNVERIFIABLE fetched line is never shown', async () => {
  const r = await sentinelStep({ now: 1, ttlMs: 10_000, verifyAd: noVerify, showUrl: true, cache: null, fetchLine: async () => FRESH });
  assert.equal(r.status, null, 'a line that fails Ed25519 verify is refused (signed-content-only)');
});

test('signed-content-only: a TAMPERED cache is re-verified every tick, not served on freshness alone', async () => {
  let fetched = 0;
  const r = await sentinelStep({
    now: 1000, ttlMs: 10_000, verifyAd: noVerify, showUrl: true,   // verify fails → nothing is trusted
    cache: { ...FRESH, fetchedAt: 999 },                           // "fresh" by clock, but unverifiable
    fetchLine: async () => { fetched += 1; return FRESH; },
  });
  assert.equal(fetched, 1, 'a tampered cache is NOT served from its timestamp — it forces a refetch');
  assert.equal(r.status, null, 'and the equally-unverifiable refetch is refused too');
});

test('showUrl:false drops the inline URL but still shows the line', async () => {
  const r = await sentinelStep({ now: 1, ttlMs: 10_000, verifyAd: okVerify, showUrl: false, cache: null, fetchLine: async () => FRESH });
  assert.match(r.status, /★ LumaLine/);
  assert.doesNotMatch(r.status, /lumaline\.dev/);
});

test('malformed adData renders no line (no crash, no fabricated content)', async () => {
  const r = await sentinelStep({ now: 1, ttlMs: 10_000, verifyAd: okVerify, showUrl: true, cache: null, fetchLine: async () => ({ adData: 'not json', sig: 's', keyid: 'k' }) });
  assert.equal(r.status, null);
});
