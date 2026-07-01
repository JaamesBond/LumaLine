// Unit: client base-URL config — branded defaults + env overrides + AUTH_BASE derivation.
// config.mjs reads process.env at module-eval time, so each case imports with a unique query
// string (a distinct ESM specifier → fresh evaluation) after setting/clearing the env.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const CLICK_ENVS = ['LUMALINE_FEED', 'LUMALINE_AUTH', 'LUMALINE_CLICK'];
function clearEnv() { for (const k of CLICK_ENVS) delete process.env[k]; }

test('branded defaults: FEED_BASE / AUTH_BASE / CLICK_BASE point at lumaline.dev', async () => {
  clearEnv();
  const cfg = await import('../src/config.mjs?case=branded-defaults');
  assert.equal(cfg.FEED_BASE, 'https://feed.lumaline.dev/lumaline-feed');
  assert.equal(cfg.AUTH_BASE, 'https://feed.lumaline.dev/auth-device'); // derived from FEED_BASE
  assert.equal(cfg.CLICK_BASE, 'https://c.lumaline.dev');
});

test('LUMALINE_FEED override moves FEED_BASE and derives AUTH_BASE on the same host', async () => {
  clearEnv();
  process.env.LUMALINE_FEED = 'http://127.0.0.1:8787/lumaline-feed';
  const cfg = await import('../src/config.mjs?case=feed-override');
  assert.equal(cfg.FEED_BASE, 'http://127.0.0.1:8787/lumaline-feed');
  assert.equal(cfg.AUTH_BASE, 'http://127.0.0.1:8787/auth-device');
  clearEnv();
});

test('LUMALINE_AUTH and LUMALINE_CLICK overrides win independently', async () => {
  clearEnv();
  process.env.LUMALINE_AUTH = 'http://127.0.0.1:9000/auth-device';
  process.env.LUMALINE_CLICK = 'http://127.0.0.1:9000/click';
  const cfg = await import('../src/config.mjs?case=auth-click-override');
  assert.equal(cfg.AUTH_BASE, 'http://127.0.0.1:9000/auth-device');
  assert.equal(cfg.CLICK_BASE, 'http://127.0.0.1:9000/click');
  clearEnv();
});
