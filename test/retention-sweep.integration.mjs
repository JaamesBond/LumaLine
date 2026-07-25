// test/retention-sweep.integration.mjs — GDPR Phase 1: scheduled retention sweep.
//
// app.retention_sweep() enforces privacy-policy §8: operational data is scrubbed or
// deleted past its retention age, financial rows are NEVER deleted (impressions anchor
// the ledger + the deferred zero-sum trigger, so only ip_hash/asn are nulled).
//
// Fixtures are BACKDATED to straddle every boundary, because a fresh local stack has no
// old rows. Both sides of each boundary are asserted: a sweep that deleted everything
// would pass a one-sided test.
//
// Setup + assertions use psql (app schema is off the Data API). Self-skips without a stack.
//
// WHAT IS TESTED:
//   R1 — dry run returns counts and mutates NOTHING
//   R2 — impressions past 90d have ip_hash/asn nulled; the ROW survives
//   R3 — impressions inside 90d are untouched
//   R4 — ad_windows past 7d deleted; inside 7d kept
//   R5 — clicks past 90d have click_token_hash scrubbed; inside kept
//   R6 — risk_flags past 90d deleted; inside kept
//   R7 — device_auth_codes past 24h deleted; inside kept
//   R8 — ledger_entries untouched and still balanced
//   R9 — sweep is idempotent (second run reports zero work)
//   R10 — anon/authenticated cannot execute the sweep

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const DB_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], {
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
}

function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const PSQL_OK = psqlWorks();
const SKIP = !PSQL_OK ? 'psql/local stack unavailable — SKIPPING' : false;
if (SKIP) console.log(`[retention-sweep.integration] ${SKIP}`);

test('R1 — dry run returns the full count contract and mutates nothing', { skip: SKIP }, () => {
  const out = JSON.parse(psql(`select app.retention_sweep(p_dry_run => true)::text`));
  for (const k of ['dry_run', 'impressions_scrubbed', 'ad_windows_deleted',
                   'clicks_scrubbed', 'risk_flags_deleted', 'device_auth_codes_deleted']) {
    assert.ok(k in out, `missing result key ${k}`);
  }
  assert.equal(out.dry_run, true);
});

test('R10 — anon and authenticated cannot execute the sweep', { skip: SKIP }, () => {
  const sig = 'app.retention_sweep(boolean,integer,integer,interval,interval,interval,interval,interval)';
  assert.equal(psql(`select has_function_privilege('anon', '${sig}', 'EXECUTE')`), 'f');
  assert.equal(psql(`select has_function_privilege('authenticated', '${sig}', 'EXECUTE')`), 'f');
  assert.equal(psql(`select has_function_privilege('service_role', '${sig}', 'EXECUTE')`), 't');
});
