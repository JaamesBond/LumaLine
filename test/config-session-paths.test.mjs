import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statePath, AUDIT, LUMALINE_HOME } from '../src/config.mjs';

test('state path is per-session and distinct per key; audit is a single shared log', () => {
  assert.ok(statePath('s1').startsWith(LUMALINE_HOME));
  assert.notEqual(statePath('s1'), statePath('s2'));
  assert.match(statePath('s1'), /impression-state-s1\.json$/);
  // Audit stays ONE shared file at the path the privacy policy + README promise.
  assert.ok(AUDIT.startsWith(LUMALINE_HOME));
  assert.match(AUDIT, /audit\.log$/);
});
