// test/grant-drift.test.mjs — 20260728100000_revoke_grant_drift.sql
//
// Production carried `anon=arwdDxtm` / `authenticated=arwdDxtm` on 25 tables in `public`, where
// the migrations grant `authenticated` at most SELECT and `anon` no DML at all. RLS was the only
// containment left, and `publishers_update_own` PERMITS updating your own row — with no
// protect-columns trigger — so a publisher could set `payout_status='verified'` and
// `stripe_account_id` to any account. Those are two of the four predicates `payout_batch_reserve`
// selects on. That is a payout-redirect vector.
//
// WHY THIS TEST IS SHAPED THE WAY IT IS: a stack built from these migrations is ALREADY correct,
// so the corrective migration is very nearly a no-op locally and a naive "assert the ACLs are
// right" test passes whether or not the migration does anything. Every case below therefore
// SIMULATES the drift first (`grant all ... to anon, authenticated`), ASSERTS the drift is live,
// and only then applies the migration's statements. A precondition that is not proven live makes
// the whole assertion vacuous — this project has been bitten by that three times.
//
// Everything runs inside `begin; ... rollback;` — GRANT/REVOKE are transactional in PostgreSQL —
// so the suite leaves the stack byte-identical to how it found it.
//
// WHAT IS TESTED:
//   D1 — the drift is reproducible, and the migration removes it (anon + authenticated DML)
//   D2 — publishers: payout_status / stripe_account_id NOT writable; handle / country ARE
//   D3 — the column re-grant is load-bearing (a bare table REVOKE cascades into column ACLs)
//   D4 — the two intended DML exceptions survive: clawback_reviews, disputes
//   D5 — service_role keeps full DML (it is never named in the REVOKE)
//   D6 — TRUNCATE is stripped from both public roles (it bypasses RLS entirely)

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const DB_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
const MIGRATION = 'supabase/migrations/20260728100000_revoke_grant_drift.sql';

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-v', 'ON_ERROR_STOP=1', '-tAqc', sql], {
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
}

function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const PSQL_OK = psqlWorks();
const SKIP = !PSQL_OK ? 'psql/local stack unavailable — SKIPPING' : false;
if (SKIP) console.log(`[grant-drift] ${SKIP}`);

// The migration's executable statements, read from the file itself so the test can never drift
// from what actually ships. Comments are stripped; the remaining statements are what run on prod.
function migrationSql() {
  return readFileSync(MIGRATION, 'utf8')
    .split('\n').filter((l) => !l.trimStart().startsWith('--')).join('\n').trim();
}

// simulate drift -> assert it took -> apply the migration -> return the probe result, all inside
// one transaction that is rolled back.
function underDriftThenFix(probeSql) {
  return psql(`
    begin;
    grant all on all tables in schema public to anon, authenticated;
    ${probeSql.replaceAll('/*STAGE*/', "'drifted'")}
    ${migrationSql()}
    ${probeSql.replaceAll('/*STAGE*/', "'fixed'")}
    rollback;
  `);
}

const priv = (role, tbl, p, stage) =>
  `select ${stage} || ' ${role} ${p} ${tbl}: ' || has_table_privilege('${role}','public.${tbl}','${p}')::text;`;

test('D1 — the drift is reproducible and the migration removes it', { skip: SKIP }, () => {
  const out = underDriftThenFix(
    priv('authenticated', 'publishers', 'UPDATE', '/*STAGE*/') +
    priv('anon', 'publishers', 'INSERT', '/*STAGE*/') +
    priv('anon', 'ledger_entries', 'DELETE', '/*STAGE*/'));

  // Precondition: the drift really is present. Without this the rest proves nothing.
  assert.match(out, /drifted authenticated UPDATE publishers: true/);
  assert.match(out, /drifted anon INSERT publishers: true/);
  assert.match(out, /drifted anon DELETE ledger_entries: true/);

  // And the migration removes it.
  assert.match(out, /fixed authenticated UPDATE publishers: false/);
  assert.match(out, /fixed anon INSERT publishers: false/);
  assert.match(out, /fixed anon DELETE ledger_entries: false/);
});

test('D2 — publishers: trust-sensitive columns locked, profile columns still editable', { skip: SKIP }, () => {
  const probe = `select /*STAGE*/ || ' payout_status=' ||
      has_column_privilege('authenticated','public.publishers','payout_status','UPDATE')::text
    || ' stripe_account_id=' ||
      has_column_privilege('authenticated','public.publishers','stripe_account_id','UPDATE')::text
    || ' handle=' ||
      has_column_privilege('authenticated','public.publishers','handle','UPDATE')::text
    || ' country=' ||
      has_column_privilege('authenticated','public.publishers','country','UPDATE')::text;`;
  const out = underDriftThenFix(probe);

  // Under drift every column is writable — including the two that redirect money.
  assert.match(out, /drifted payout_status=true stripe_account_id=true handle=true country=true/);

  // After the fix: the money columns are service_role-only again, the profile pair survives.
  assert.match(out, /fixed payout_status=false stripe_account_id=false handle=true country=true/);
});

test('D3 — the column re-grant is load-bearing, not belt-and-braces', { skip: SKIP }, () => {
  // A bare table-level REVOKE UPDATE cascades into the column ACL (PostgreSQL revokes column
  // privileges alongside table ones). Without the migration's explicit re-grant, the publisher
  // dashboard's profile edit would silently break. Prove that by running ONLY the revoke.
  const out = psql(`
    begin;
    select 'before=' || has_column_privilege('authenticated','public.publishers','handle','UPDATE')::text;
    revoke insert, update, delete, truncate on all tables in schema public from anon, authenticated;
    select 'after_bare_revoke=' || has_column_privilege('authenticated','public.publishers','handle','UPDATE')::text;
    grant update (handle, country) on public.publishers to authenticated;
    select 'after_regrant=' || has_column_privilege('authenticated','public.publishers','handle','UPDATE')::text;
    rollback;
  `);
  assert.match(out, /before=true/);
  assert.match(out, /after_bare_revoke=false/, 'the table REVOKE must cascade into the column ACL');
  assert.match(out, /after_regrant=true/);
});

test('D4 — the two intended DML exceptions survive the revoke', { skip: SKIP }, () => {
  const probe =
    priv('authenticated', 'clawback_reviews', 'INSERT', '/*STAGE*/') +
    priv('authenticated', 'clawback_reviews', 'UPDATE', '/*STAGE*/') +
    priv('authenticated', 'disputes', 'INSERT', '/*STAGE*/') +
    priv('authenticated', 'disputes', 'UPDATE', '/*STAGE*/');
  const out = underDriftThenFix(probe);

  assert.match(out, /fixed authenticated INSERT clawback_reviews: true/);
  assert.match(out, /fixed authenticated UPDATE clawback_reviews: true/);
  assert.match(out, /fixed authenticated INSERT disputes: true/);
  // disputes is file-once: publishers may not edit after submitting.
  assert.match(out, /fixed authenticated UPDATE disputes: false/);
});

test('D5 — service_role is untouched and keeps full DML', { skip: SKIP }, () => {
  const probe =
    priv('service_role', 'publishers', 'UPDATE', '/*STAGE*/') +
    priv('service_role', 'publishers', 'DELETE', '/*STAGE*/') +
    priv('service_role', 'ledger_entries', 'INSERT', '/*STAGE*/');
  const out = underDriftThenFix(probe);

  assert.match(out, /fixed service_role UPDATE publishers: true/);
  assert.match(out, /fixed service_role DELETE publishers: true/);
  assert.match(out, /fixed service_role INSERT ledger_entries: true/);
});

test('D6 — TRUNCATE is stripped from both public roles (it bypasses RLS)', { skip: SKIP }, () => {
  const probe =
    priv('anon', 'publishers', 'TRUNCATE', '/*STAGE*/') +
    priv('authenticated', 'publishers', 'TRUNCATE', '/*STAGE*/');
  const out = underDriftThenFix(probe);

  assert.match(out, /drifted anon TRUNCATE publishers: true/);
  assert.match(out, /fixed anon TRUNCATE publishers: false/);
  assert.match(out, /fixed authenticated TRUNCATE publishers: false/);
});
