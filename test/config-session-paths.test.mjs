import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statePath, auditPath, LUMALINE_HOME } from '../src/config.mjs';

test('per-session paths live under LUMALINE_HOME and are distinct per key', () => {
  assert.ok(statePath('s1').startsWith(LUMALINE_HOME));
  assert.ok(auditPath('s1').startsWith(LUMALINE_HOME));
  assert.notEqual(statePath('s1'), statePath('s2'));
  assert.match(statePath('s1'), /impression-state-s1\.json$/);
  assert.match(auditPath('s1'), /audit-s1\.log$/);
});
