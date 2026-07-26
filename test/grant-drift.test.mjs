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
  assert.match(out, /drifted authenticated TRUNCATE publishers: true/);
  assert.match(out, /fixed anon TRUNCATE publishers: false/);
  assert.match(out, /fixed authenticated TRUNCATE publishers: false/);
});

test('D7 — anon holds SELECT on nothing in public', { skip: SKIP }, () => {
  // The drift is arwdDxtm: the `r` is SELECT, and stripping DML alone leaves the read surface
  // wide open. main grants anon SELECT on zero relations.
  const probe = `select /*STAGE*/ || ' anon_readable=' || count(*)::text
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r','v')
      and has_table_privilege('anon', c.oid, 'SELECT');`;
  const out = underDriftThenFix(probe);

  assert.doesNotMatch(out, /drifted anon_readable=0/, 'precondition: the drift must grant anon reads');
  assert.match(out, /fixed anon_readable=0/);
});

test('D8 — the RLS-bypassing definer view is not readable by a client role', { skip: SKIP }, () => {
  // public.uncharged_advertiser_billings is service_role-only in main and lost its
  // security_invoker, so a surviving SELECT bypasses base-table RLS and leaks
  // stripe_customer_id / advertiser_name / per-publisher billing to the public anon key.
  const probe = `select /*STAGE*/ || ' anon=' ||
      has_table_privilege('anon','public.uncharged_advertiser_billings','SELECT')::text
    || ' authenticated=' ||
      has_table_privilege('authenticated','public.uncharged_advertiser_billings','SELECT')::text
    || ' service_role=' ||
      has_table_privilege('service_role','public.uncharged_advertiser_billings','SELECT')::text;`;
  const out = underDriftThenFix(probe);

  assert.match(out, /drifted anon=true authenticated=true/, 'precondition: drift exposes the view');
  assert.match(out, /fixed anon=false authenticated=false service_role=true/);
});

test('D10 — whole-schema invariant: the client roles end exactly where main puts them', { skip: SKIP }, () => {
  // The strongest statement available: simulate the full production drift, apply the migration,
  // and count the security-relevant surface across every relation in `public`.
  const cnt = (role, privs) => `(select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
      where n.nspname='public' and c.relkind in ('r','v')
        and (${privs.map((p) => `has_table_privilege('${role}',c.oid,'${p}')`).join(' or ')}))::text`;
  const probe = `select /*STAGE*/ || ' anonR=' || ${cnt('anon', ['SELECT'])}
    || ' anonW=' || ${cnt('anon', ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'])}
    || ' authR=' || ${cnt('authenticated', ['SELECT'])}
    || ' authW=' || ${cnt('authenticated', ['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'])};`;
  const out = underDriftThenFix(probe);

  // Under the drift every client role can read and write everything.
  assert.match(out, /drifted anonR=35 anonW=35 authR=35 authW=35/);

  // After: anon reaches nothing at all; authenticated reads the 26 relations main grants it and
  // writes only clawback_reviews and disputes. Residual REFERENCES/TRIGGER/MAINTAIN may linger
  // where the drift created an ACL entry — neither is a read or a write.
  assert.match(out, /fixed anonR=0 anonW=0 authR=26 authW=2/);
});

test('D11 — the fix is durable: a NEW table is not stamped with the hole', { skip: SKIP }, () => {
  // Sections 1-3 correct today's 35 relations. Without §4's ALTER DEFAULT PRIVILEGES, every table
  // added later is stamped from pg_default_acl and silently re-acquires the drift — the fix would
  // decay from the day it lands. Prove it by creating a table and reading its ACL.
  //
  // Precondition first: restore the production-shaped default, create a table under it, and show
  // the new table really does come out wide open. Otherwise the "after" assertion proves nothing.
  const out = psql(`
    begin;
    alter default privileges in schema public
      grant insert, update, delete, truncate, select on tables to anon, authenticated;
    create table public._drift_probe_before (id int);
    select 'before: anonW=' ||
      (has_table_privilege('anon','public._drift_probe_before','INSERT')
       or has_table_privilege('anon','public._drift_probe_before','UPDATE'))::text
      || ' anonR=' || has_table_privilege('anon','public._drift_probe_before','SELECT')::text;

    alter default privileges in schema public
      revoke insert, update, delete, truncate, select on tables from anon, authenticated;
    create table public._drift_probe_after (id int);
    select 'after: anonW=' ||
      (has_table_privilege('anon','public._drift_probe_after','INSERT')
       or has_table_privilege('anon','public._drift_probe_after','UPDATE'))::text
      || ' anonR=' || has_table_privilege('anon','public._drift_probe_after','SELECT')::text
      || ' authW=' ||
      (has_table_privilege('authenticated','public._drift_probe_after','INSERT')
       or has_table_privilege('authenticated','public._drift_probe_after','UPDATE'))::text
      || ' authR=' || has_table_privilege('authenticated','public._drift_probe_after','SELECT')::text;
    rollback;
  `);

  assert.match(out, /before: anonW=true anonR=true/, 'precondition: the drifted default must stamp new tables');
  assert.match(out, /after: anonW=false anonR=false authW=false authR=false/);
});

test('D9 — advertisers: table read revoked, column-scoped read survives', { skip: SKIP }, () => {
  // 20260716150000 deliberately revoked whole-table SELECT and column-scoped it so
  // stripe_customer_id / is_house never reach a client. The table-level REVOKE cascades into
  // those column ACLs, so the re-grant is load-bearing — without it the advertiser portal
  // cannot read its own org at all.
  const probe = `select /*STAGE*/ || ' table=' ||
      has_table_privilege('authenticated','public.advertisers','SELECT')::text
    || ' name_col=' ||
      has_column_privilege('authenticated','public.advertisers','name','SELECT')::text
    || ' stripe_customer_id_col=' ||
      has_column_privilege('authenticated','public.advertisers','stripe_customer_id','SELECT')::text;`;
  const out = underDriftThenFix(probe);

  assert.match(out, /drifted table=true name_col=true stripe_customer_id_col=true/);
  // After: no whole-table read, the five safe columns survive, the sensitive one does not.
  assert.match(out, /fixed table=false name_col=true stripe_customer_id_col=false/);
});
