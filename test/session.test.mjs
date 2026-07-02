import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionKey } from '../src/client/session.mjs';

test('uses session_id when present', () => {
  assert.equal(sessionKey({ session_id: 'a1b2c3d4-0000-4000-8000-000000000001' }),
    'a1b2c3d4-0000-4000-8000-000000000001');
});

test('sanitizes unsafe characters out of session_id (no path traversal)', () => {
  assert.equal(sessionKey({ session_id: '../../etc/passwd' }), 'etcpasswd');
});

test('falls back to a stable dir hash when only current_dir is present', () => {
  const a = sessionKey({ workspace: { current_dir: '/home/u/proj' } });
  assert.match(a, /^dir-[0-9a-f]{16}$/);
  assert.equal(a, sessionKey({ workspace: { current_dir: '/home/u/proj' } })); // stable
});

test('different dirs produce different keys', () => {
  assert.notEqual(
    sessionKey({ workspace: { current_dir: '/a' } }),
    sessionKey({ workspace: { current_dir: '/b' } }),
  );
});

test('returns default when neither session_id nor current_dir is present', () => {
  assert.equal(sessionKey({}), 'default');
});
