// Cross-module invariant guard (offline — gates CI without a stack).
//
// The refresh-token grace window (SQL: device_refresh c_grace) and the client refresh lock stale
// window (src/client/auth.mjs LOCK_STALE_MS) live in two independently-editable files. If a future
// edit inverts their margin — c_grace shrunk below, or LOCK_STALE_MS raised above — a crashed holder's
// lock would be reclaimed and its recovery retry would land AFTER the grace expired, silently
// reintroducing the crash-mid-rotation lockout the migration exists to fix. Pin the relationship here.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MIGRATION = 'supabase/migrations/20260704120000_refresh_token_grace_window.sql';
const CLIENT = 'src/client/auth.mjs';

test('grace window comfortably exceeds the client stale-lock reclaim window (c_grace >= 2 * LOCK_STALE_MS)', () => {
  const sql = readFileSync(path.join(root, MIGRATION), 'utf8');
  const client = readFileSync(path.join(root, CLIENT), 'utf8');

  const graceMatch = sql.match(/c_grace\s+constant\s+interval\s*:=\s*interval\s*'(\d+)\s*seconds?'/i);
  assert.ok(graceMatch, `could not find c_grace interval in ${MIGRATION}`);
  const graceMs = Number(graceMatch[1]) * 1000;

  const lockMatch = client.match(/LOCK_STALE_MS\s*=\s*([\d_]+)/);
  assert.ok(lockMatch, `could not find LOCK_STALE_MS in ${CLIENT}`);
  const lockStaleMs = Number(lockMatch[1].replace(/_/g, ''));

  assert.ok(
    graceMs >= lockStaleMs * 2,
    `c_grace (${graceMs}ms) must be >= 2 * LOCK_STALE_MS (${lockStaleMs}ms) so a reclaimed-lock retry still lands inside the grace; got margin ${graceMs / lockStaleMs}x`,
  );
});
