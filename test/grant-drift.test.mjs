// test/grant-drift.test.mjs — 20260728100000_revoke_grant_drift.sql, the corrective for the
// production grant drift (anon/authenticated held `arwdDxtm` on 25 public tables; the migrations
// grant at most SELECT to `authenticated` and nothing at all to `anon`).
//
// WHY THIS TEST IS SHAPED THE WAY IT IS
// The naive version of this test is worthless. The local stack is built purely from the migrations,
// so it is ALREADY correct — the corrective migration is a near-no-op there and every "is it
// locked down?" assertion passes trivially, whether or not the migration exists. So this suite
// SIMULATES THE PRODUCTION DRIFT FIRST (`grant all on all tables in schema public to anon,
// authenticated`), PROVES the drift is live (D2/D3 exercise the actual payout-redirect vector),
// and only then applies the migration and demands the ACLs come back.
//
// It executes the REAL migration file's SQL — read off disk and spliced in — not a copy. Editing
// the migration without editing this test cannot silently pass.
//
// WHAT IS TESTED
//   B1 — BASELINE: `anon` holds no SELECT/INSERT/UPDATE/DELETE anywhere in `public`
//   B2 — BASELINE: `authenticated` holds DML on exactly two tables (clawback_reviews, disputes)
//   D1 — DRIFT IS LIVE: after `grant all`, anon+authenticated hold full DML on every relation
//   D2 — DRIFT IS LIVE: `authenticated` can UPDATE publishers.payout_status / .stripe_account_id
//        — the payout-redirect vector, stated as a privilege fact
//   D3 — DRIFT IS LIVE: whole-table SELECT on `advertisers` is back (column-scoping defeated)
//   F1 — FIXED: table ACLs equal the captured baseline, minus TRUNCATE for anon/authenticated
//        (the one deliberate tightening) — no other difference, in either direction
//   F2 — FIXED: column-level ACLs are byte-identical to baseline (the REVOKE-cascade trap)
//   F3 — FIXED: `authenticated` can no longer UPDATE payout_status / stripe_account_id / status,
//        but CAN still UPDATE handle / country
//   F4 — FIXED: clawback_reviews INSERT+UPDATE and disputes INSERT still work for `authenticated`;
//        disputes UPDATE is still refused
//   F5 — FIXED: `service_role` ACLs are byte-identical to baseline across all of `public`
//   F6 — FIXED: anon holds nothing again
//   F7 — FIXED: a table created AFTER the migration is born with no anon/authenticated grant —
//        the pg_default_acl source is closed, so the drift cannot recur one new table at a time
//   P1 — POSTGREST PROOF: a real authenticated publisher PATCHing its own row over the Data API —
//        stripe_account_id/payout_status refused, handle/country accepted. Run against the drifted
//        stack first (the PATCH must SUCCEED, reproducing the finding end-to-end), then against the
//        corrected stack. This is the only part that cannot run inside a rolled-back transaction,
//        because PostgREST holds its own connection; it restores the ACLs in a finally.
//
// Self-skips without a local Supabase stack / psql / the migration.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL    = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

const MIGRATION = join(
  dirname(fileURLToPath(import.meta.url)), '..',
  'supabase', 'migrations', '20260728100000_revoke_grant_drift.sql',
);

function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-v', 'ON_ERROR_STOP=1', '-tAqc', sql],
    { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

// Runs a multi-statement script through psql's stdin. Used for the transactional experiment (which
// must be ONE session so BEGIN/ROLLBACK actually wrap it) and for the drift/restore steps of P1.
function psqlScript(script) {
  return execFileSync('psql', [DB_URL, '-v', 'ON_ERROR_STOP=1', '-tAq', '-f', '-'],
    { encoding: 'utf8', input: script, stdio: ['pipe', 'pipe', 'pipe'] });
}

async function isStackUp() {
  try {
    const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) });
    return r.status >= 200 && r.status < 500;
  } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

let MIGRATION_SQL = null;
try { MIGRATION_SQL = readFileSync(MIGRATION, 'utf8'); } catch { /* absent */ }

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const SKIP     = !STACK_UP || !PSQL_OK || !MIGRATION_SQL
  ? 'needs a local Supabase stack + psql + 20260728100000_revoke_grant_drift.sql'
  : false;

// ---------------------------------------------------------------------------
// Snapshot helpers. Emitted as JSON from inside a single psql session so that every stage of the
// experiment is observed by the same transaction.
// ---------------------------------------------------------------------------

// relname|role -> comma-joined sorted privilege list, for every relation in `public`.
const TABLE_ACL_SQL = `
  select coalesce(jsonb_object_agg(k, v), '{}'::jsonb)::text from (
    select c.relname || '|' || g.rolname as k,
           coalesce((select string_agg(x.privilege_type, ',' order by x.privilege_type)
                     from aclexplode(c.relacl) x where x.grantee = g.oid), '') as v
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    cross join (select oid, rolname from pg_roles
                where rolname in ('anon','authenticated','service_role')) g
    where n.nspname = 'public' and c.relkind in ('r','v','m','p','f')
      and c.relname not in ('_drift_probe_before', '_drift_probe_after')
  ) t`;

// The ACL a NEWLY CREATED table is born with — i.e. what pg_default_acl stamps on it.
const newTableAcl = (name) => `
  select jsonb_build_object(
    'anon', coalesce((select string_agg(x.privilege_type, ',' order by x.privilege_type)
                      from aclexplode(c.relacl) x where x.grantee = 'anon'::regrole), ''),
    'authenticated', coalesce((select string_agg(x.privilege_type, ',' order by x.privilege_type)
                      from aclexplode(c.relacl) x where x.grantee = 'authenticated'::regrole), '')
  )::text from pg_class c where c.oid = 'public.${name}'::regclass`;

// relname.attname|role -> privileges, for every column carrying an explicit column-level ACL.
const COLUMN_ACL_SQL = `
  select coalesce(jsonb_object_agg(k, v), '{}'::jsonb)::text from (
    select c.relname || '.' || a.attname || '|' || g.rolname as k,
           coalesce((select string_agg(x.privilege_type, ',' order by x.privilege_type)
                     from aclexplode(a.attacl) x where x.grantee = g.oid), '') as v
    from pg_attribute a
    join pg_class c on c.oid = a.attrelid
    join pg_namespace n on n.oid = c.relnamespace
    cross join (select oid, rolname from pg_roles
                where rolname in ('anon','authenticated','service_role')) g
    where n.nspname = 'public' and a.attacl is not null
  ) t`;

// The named privilege questions this migration exists to answer.
const PROBE_SQL = `
  select jsonb_build_object(
    'auth_pub_handle_upd', has_column_privilege('authenticated','public.publishers','handle','UPDATE'),
    'auth_pub_country_upd',has_column_privilege('authenticated','public.publishers','country','UPDATE'),
    'auth_pub_payout_upd', has_column_privilege('authenticated','public.publishers','payout_status','UPDATE'),
    'auth_pub_stripe_upd', has_column_privilege('authenticated','public.publishers','stripe_account_id','UPDATE'),
    'auth_pub_status_upd', has_column_privilege('authenticated','public.publishers','status','UPDATE'),
    'auth_pub_tbl_upd',    has_table_privilege('authenticated','public.publishers','UPDATE'),
    'auth_pub_sel',        has_table_privilege('authenticated','public.publishers','SELECT'),
    'auth_cr_ins',         has_table_privilege('authenticated','public.clawback_reviews','INSERT'),
    'auth_cr_upd',         has_table_privilege('authenticated','public.clawback_reviews','UPDATE'),
    'auth_disp_ins',       has_table_privilege('authenticated','public.disputes','INSERT'),
    'auth_disp_upd',       has_table_privilege('authenticated','public.disputes','UPDATE'),
    'auth_adv_tbl_sel',    has_table_privilege('authenticated','public.advertisers','SELECT'),
    'auth_adv_name_sel',   has_column_privilege('authenticated','public.advertisers','name','SELECT'),
    'auth_adv_stripe_sel', has_column_privilege('authenticated','public.advertisers','stripe_customer_id','SELECT'),
    'auth_dac_sel',        has_table_privilege('authenticated','public.device_auth_codes','SELECT'),
    'anon_pub_sel',        has_table_privilege('anon','public.publishers','SELECT'),
    'anon_pub_upd',        has_table_privilege('anon','public.publishers','UPDATE'),
    'anon_pub_ins',        has_table_privilege('anon','public.publishers','INSERT'),
    'anon_pub_del',        has_table_privilege('anon','public.publishers','DELETE'),
    'anon_led_trunc',      has_table_privilege('anon','public.ledger_entries','TRUNCATE'),
    'sr_pub_sel',          has_table_privilege('service_role','public.publishers','SELECT'),
    'sr_pub_ins',          has_table_privilege('service_role','public.publishers','INSERT'),
    'sr_pub_upd',          has_table_privilege('service_role','public.publishers','UPDATE'),
    'sr_pub_del',          has_table_privilege('service_role','public.publishers','DELETE'),
    'sr_led_ins',          has_table_privilege('service_role','public.ledger_entries','INSERT'),
    'sr_adv_sel',          has_table_privilege('service_role','public.advertisers','SELECT')
  )::text`;

const DML = ['INSERT', 'UPDATE', 'DELETE'];

// The relations the migration hands `authenticated` nothing at all on (steps 4-5). `advertisers` is
// here because its whole-table grant is revoked and replaced by a five-column SELECT.
const NO_TOUCH = new Set([
  'ad_windows', 'advertisers', 'billing_run_lock', 'device_auth_codes',
  'device_code_approve_attempts', 'rl_buckets', 'signup_throttle_buckets',
  'stripe_webhook_events', 'uncharged_advertiser_billings',
]);
const stage = (out, tag) => JSON.parse(out.split('\n').find((l) => l.startsWith(`${tag} `)).slice(tag.length + 1));
const privs  = (snap, key) => (snap[key] ?? '').split(',').filter(Boolean);
const forRole = (snap, role) =>
  Object.fromEntries(Object.entries(snap).filter(([k]) => k.endsWith(`|${role}`)));

// ---------------------------------------------------------------------------
// The experiment: baseline -> simulated production drift -> real migration -> re-observe.
// Wrapped in BEGIN/ROLLBACK inside ONE psql session, so the stack is left exactly as found even if
// an assertion below fails.
// ---------------------------------------------------------------------------
const EXPERIMENT = `
begin;
select 'BASE_TBL '  || (${TABLE_ACL_SQL});
select 'BASE_COL '  || (${COLUMN_ACL_SQL});
select 'BASE_PRB '  || (${PROBE_SQL});

-- Simulate production, at BOTH levels: the 35 relations that exist, and the pg_default_acl entry
-- that stamps the ones that do not exist yet. The local image ships the postgres entry as Dxtm;
-- prod has it as arwdDxtm, so the default must be widened here or step 5 is untestable.
grant all on all tables in schema public to anon, authenticated;
alter default privileges in schema public grant all on tables to anon, authenticated;
create table public._drift_probe_before (id int);
select 'DRIFT_TBL '    || (${TABLE_ACL_SQL});
select 'DRIFT_PRB '    || (${PROBE_SQL});
select 'DRIFT_NEWTBL ' || (${newTableAcl('_drift_probe_before')});

-- The migration under test, verbatim from disk.
${MIGRATION_SQL ?? ''}

create table public._drift_probe_after (id int);
select 'FIX_TBL '    || (${TABLE_ACL_SQL});
select 'FIX_COL '    || (${COLUMN_ACL_SQL});
select 'FIX_PRB '    || (${PROBE_SQL});
select 'FIX_NEWTBL ' || (${newTableAcl('_drift_probe_after')});
rollback;
`;

let BASE_TBL, BASE_COL, BASE_PRB, DRIFT_TBL, DRIFT_PRB, FIX_TBL, FIX_COL, FIX_PRB;
let DRIFT_NEWTBL, FIX_NEWTBL;
if (!SKIP) {
  const out = psqlScript(EXPERIMENT);
  BASE_TBL  = stage(out, 'BASE_TBL');   BASE_COL  = stage(out, 'BASE_COL');
  BASE_PRB  = stage(out, 'BASE_PRB');   DRIFT_TBL = stage(out, 'DRIFT_TBL');
  DRIFT_PRB = stage(out, 'DRIFT_PRB');  FIX_TBL   = stage(out, 'FIX_TBL');
  FIX_COL   = stage(out, 'FIX_COL');    FIX_PRB   = stage(out, 'FIX_PRB');
  DRIFT_NEWTBL = stage(out, 'DRIFT_NEWTBL');
  FIX_NEWTBL   = stage(out, 'FIX_NEWTBL');
}

// ---------------------------------------------------------------------------
// B — the captured baseline really is the narrow, intended state.
// ---------------------------------------------------------------------------
test('B1 — baseline: anon holds no SELECT/INSERT/UPDATE/DELETE anywhere in public', { skip: SKIP }, () => {
  const offenders = Object.entries(forRole(BASE_TBL, 'anon'))
    .filter(([, v]) => ['SELECT', ...DML].some((p) => v.split(',').includes(p)));
  assert.deepEqual(offenders, [], `anon must hold no read/write grants; got ${JSON.stringify(offenders)}`);
});

test('B2 — baseline: authenticated holds DML on exactly clawback_reviews + disputes', { skip: SKIP }, () => {
  const withDml = Object.entries(forRole(BASE_TBL, 'authenticated'))
    .filter(([, v]) => DML.some((p) => v.split(',').includes(p)))
    .map(([k]) => k.split('|')[0])
    .sort();
  assert.deepEqual(withDml, ['clawback_reviews', 'disputes']);
  assert.deepEqual(privs(BASE_TBL, 'clawback_reviews|authenticated').filter((p) => DML.includes(p)).sort(),
    ['INSERT', 'UPDATE']);
  assert.deepEqual(privs(BASE_TBL, 'disputes|authenticated').filter((p) => DML.includes(p)).sort(),
    ['INSERT']);
});

// ---------------------------------------------------------------------------
// D — the precondition. Without these passing, everything after them proves nothing.
// ---------------------------------------------------------------------------
test('D1 — drift is live: anon + authenticated hold full DML on every relation', { skip: SKIP }, () => {
  for (const role of ['anon', 'authenticated']) {
    const missing = Object.entries(forRole(DRIFT_TBL, role))
      .filter(([, v]) => !['SELECT', ...DML, 'TRUNCATE'].every((p) => v.split(',').includes(p)))
      .map(([k]) => k);
    assert.deepEqual(missing, [], `simulated drift must give ${role} full DML everywhere`);
  }
  assert.ok(Object.keys(forRole(DRIFT_TBL, 'anon')).length >= 25, 'drift must span at least the 25 tables found on prod');
});

test('D2 — drift is live: authenticated can UPDATE publishers.payout_status + .stripe_account_id', { skip: SKIP }, () => {
  assert.equal(BASE_PRB.auth_pub_payout_upd, false, 'baseline must NOT allow it (else the test is vacuous)');
  assert.equal(BASE_PRB.auth_pub_stripe_upd, false, 'baseline must NOT allow it (else the test is vacuous)');
  assert.equal(DRIFT_PRB.auth_pub_payout_upd, true, 'the self-verify vector');
  assert.equal(DRIFT_PRB.auth_pub_stripe_upd, true, 'the payout-redirect vector');
  assert.equal(DRIFT_PRB.auth_pub_status_upd, true, 'the self-unsuspend vector');
  assert.equal(DRIFT_PRB.anon_pub_upd, true, 'anon writes too');
});

test('D3 — drift is live: whole-table SELECT on advertisers defeats the column-scoping', { skip: SKIP }, () => {
  assert.equal(BASE_PRB.auth_adv_tbl_sel, false);
  assert.equal(BASE_PRB.auth_adv_stripe_sel, false, 'stripe_customer_id is outside the column grant');
  assert.equal(DRIFT_PRB.auth_adv_tbl_sel, true);
  assert.equal(DRIFT_PRB.auth_adv_stripe_sel, true, 'drift re-exposes every column');
  assert.equal(DRIFT_PRB.auth_dac_sel, true, 'and the device-login codes');
});

// ---------------------------------------------------------------------------
// F — the migration puts it all back.
// ---------------------------------------------------------------------------
test('F1 — fixed: table ACLs equal baseline, modulo the migration\'s stated tightenings', { skip: SKIP }, () => {
  // The three tightenings beyond raw baseline, each mapping 1:1 onto a statement in the migration:
  //   anon                      -> holds nothing anywhere            (step 1, `revoke all`)
  //   authenticated on NO_TOUCH -> holds nothing                     (steps 4-5, `revoke all`)
  //   authenticated elsewhere   -> baseline minus TRUNCATE           (step 2)
  // Everything else must come back byte-identical.
  const expected = Object.fromEntries(Object.entries(BASE_TBL).map(([k, v]) => {
    const [rel, role] = k.split('|');
    if (role === 'service_role') return [k, v];
    if (role === 'anon') return [k, ''];
    if (NO_TOUCH.has(rel)) return [k, ''];
    return [k, v.split(',').filter((p) => p !== 'TRUNCATE').join(',')];
  }));
  assert.deepEqual(FIX_TBL, expected);

  // No relation may GAIN a privilege relative to baseline — in any direction, for any role.
  for (const k of Object.keys(BASE_TBL)) {
    const gained = privs(FIX_TBL, k).filter((p) => !privs(BASE_TBL, k).includes(p));
    assert.deepEqual(gained, [], `${k} must not gain privileges; gained ${gained}`);
  }
});

test('F2 — fixed: column-level ACLs are byte-identical to baseline', { skip: SKIP }, () => {
  assert.deepEqual(FIX_COL, BASE_COL);
  // And they are actually present — a baseline of {} would make the above vacuous.
  assert.equal(BASE_COL['publishers.handle|authenticated'], 'UPDATE');
  assert.equal(BASE_COL['publishers.country|authenticated'], 'UPDATE');
  assert.equal(BASE_COL['advertisers.name|authenticated'], 'SELECT');
});

test('F3 — fixed: publishers is writable on handle/country only', { skip: SKIP }, () => {
  assert.equal(FIX_PRB.auth_pub_handle_upd, true,  'profile edit must survive the table-level revoke');
  assert.equal(FIX_PRB.auth_pub_country_upd, true, 'profile edit must survive the table-level revoke');
  assert.equal(FIX_PRB.auth_pub_payout_upd, false, 'self-verify closed');
  assert.equal(FIX_PRB.auth_pub_stripe_upd, false, 'payout redirect closed');
  assert.equal(FIX_PRB.auth_pub_status_upd, false, 'self-unsuspend closed');
  assert.equal(FIX_PRB.auth_pub_tbl_upd, false,    'no table-wide UPDATE');
  assert.equal(FIX_PRB.auth_pub_sel, true,         'publishers still readable under RLS');
});

test('F4 — fixed: clawback_reviews + disputes writes still work', { skip: SKIP }, () => {
  assert.equal(FIX_PRB.auth_cr_ins, true);
  assert.equal(FIX_PRB.auth_cr_upd, true);
  assert.equal(FIX_PRB.auth_disp_ins, true);
  assert.equal(FIX_PRB.auth_disp_upd, false, 'disputes are append-only for publishers');
});

test('F5 — fixed: service_role ACLs are byte-identical to baseline', { skip: SKIP }, () => {
  assert.deepEqual(forRole(FIX_TBL, 'service_role'), forRole(BASE_TBL, 'service_role'));
  for (const k of ['sr_pub_sel', 'sr_pub_ins', 'sr_pub_upd', 'sr_pub_del', 'sr_led_ins', 'sr_adv_sel']) {
    assert.equal(FIX_PRB[k], true, `service_role must retain ${k}`);
  }
});

test('F6 — fixed: anon holds nothing, and advertisers is column-scoped again', { skip: SKIP }, () => {
  for (const k of ['anon_pub_sel', 'anon_pub_upd', 'anon_pub_ins', 'anon_pub_del', 'anon_led_trunc']) {
    assert.equal(FIX_PRB[k], false, `anon must not hold ${k}`);
  }
  // Not just the probed privileges — anon must hold NO privilege on ANY relation in public.
  const held = Object.entries(forRole(FIX_TBL, 'anon')).filter(([, v]) => v !== '');
  assert.deepEqual(held, [], `anon must hold nothing in public; still holds ${JSON.stringify(held)}`);
  assert.equal(FIX_PRB.auth_adv_tbl_sel, false);
  assert.equal(FIX_PRB.auth_adv_name_sel, true,   'the five-column grant is back');
  assert.equal(FIX_PRB.auth_adv_stripe_sel, false, 'and it still hides stripe_customer_id');
  assert.equal(FIX_PRB.auth_dac_sel, false,        'device-login codes unreadable again');
});

test('F7 — fixed: a NEWLY CREATED table no longer inherits the hole', { skip: SKIP }, () => {
  // Precondition: under the drifted pg_default_acl, a brand-new table is born wide open. Without
  // this, step 5 of the migration is unfalsifiable on a local stack (whose default is already Dxtm).
  for (const role of ['anon', 'authenticated']) {
    for (const p of ['SELECT', ...DML]) {
      assert.ok(DRIFT_NEWTBL[role].split(',').includes(p),
        `drifted default must stamp ${p} for ${role} on a new table`);
    }
  }
  // After the fix, pg_default_acl gives the two public roles nothing at all.
  assert.equal(FIX_NEWTBL.anon, '', 'a new table must grant anon nothing');
  assert.equal(FIX_NEWTBL.authenticated, '', 'a new table must grant authenticated nothing');
});

// ---------------------------------------------------------------------------
// P1 — the end-to-end proof, over the real Data API, exactly how the finding was made.
//
// PostgREST holds its own pooled connection, so this cannot live inside the rolled-back
// transaction above: the drift and the fix must really be committed. Everything is restored in a
// finally, and the ACLs are re-asserted against the baseline afterwards.
// ---------------------------------------------------------------------------
const P = { authId: randomUUID(), pubId: randomUUID() };
P.email  = `grantdrift-${P.authId}@example.com`;
P.handle = `grantdrift-${P.pubId.slice(0, 8)}`;
const P_JWT = mintJwt(P.authId);

async function patchOwnRow(body) {
  const resp = await fetch(`${REST_BASE}/publishers?id=eq.${P.pubId}`, {
    method: 'PATCH',
    headers: {
      apikey: ANON,
      Authorization: `Bearer ${P_JWT}`,
      'content-type': 'application/json',
      Prefer: 'return=representation',
    },
    body: JSON.stringify(body),
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { status: resp.status, ok: resp.ok, data };
}

test('P1 — PostgREST: a publisher cannot redirect its own payout after the fix', { skip: SKIP }, async (t) => {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${P.authId}', 'authenticated', 'authenticated',
      '${P.email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, status)
    values ('${P.pubId}', '${P.authId}', '${P.handle}', 'FR', 'active');`);

  try {
    // --- with the production drift in place, the vector is real ---
    psql('grant all on all tables in schema public to anon, authenticated;');
    const evil = await patchOwnRow({ stripe_account_id: `acct_attacker_${P.pubId.slice(0, 8)}` });
    assert.equal(evil.status, 200, 'precondition: the drifted stack MUST accept the payout redirect');
    assert.equal(psql(`select stripe_account_id from public.publishers where id='${P.pubId}';`),
      `acct_attacker_${P.pubId.slice(0, 8)}`, 'and it must really have landed in the table');

    const selfVerify = await patchOwnRow({ payout_status: 'verified' });
    assert.equal(selfVerify.status, 200, 'precondition: the drifted stack MUST accept self-verification');

    // --- apply the real migration ---
    psql(`update public.publishers set stripe_account_id = null, payout_status = 'none' where id='${P.pubId}';`);
    psqlScript(MIGRATION_SQL);

    // PostgREST caches the schema; nudge it and give it a moment to reload the new privileges.
    psql("notify pgrst, 'reload schema';");
    await new Promise((r) => setTimeout(r, 750));

    // --- the vector is closed ---
    const blocked = await patchOwnRow({ stripe_account_id: `acct_attacker2_${P.pubId.slice(0, 8)}` });
    assert.notEqual(blocked.status, 200, `payout redirect must be refused, got ${blocked.status} ${JSON.stringify(blocked.data)}`);
    assert.equal(psql(`select coalesce(stripe_account_id,'<null>') from public.publishers where id='${P.pubId}';`),
      '<null>', 'and nothing may have landed in the table');

    const blockedVerify = await patchOwnRow({ payout_status: 'verified' });
    assert.notEqual(blockedVerify.status, 200, 'self-verification must be refused');
    assert.equal(psql(`select payout_status from public.publishers where id='${P.pubId}';`), 'none');

    // --- but the legitimate profile edit still works (the column-grant survival proof) ---
    const ok = await patchOwnRow({ handle: `${P.handle}-edited`, country: 'DE' });
    assert.equal(ok.status, 200, `profile edit must still work, got ${ok.status} ${JSON.stringify(ok.data)}`);
    assert.equal(psql(`select handle || '/' || country from public.publishers where id='${P.pubId}';`),
      `${P.handle}-edited/DE`);
  } finally {
    // Restore the stack no matter what: re-apply the migration over any leftover drift, drop fixtures.
    try { psqlScript(MIGRATION_SQL); } catch { /* best-effort */ }
    try { psql("notify pgrst, 'reload schema';"); } catch { /* best-effort */ }
    try { psql(`delete from public.publishers where id='${P.pubId}';`); } catch { /* best-effort */ }
    try { psql(`delete from auth.users where id='${P.authId}';`); } catch { /* best-effort */ }
  }

  // The stack must be exactly where the transactional experiment left it.
  const after = JSON.parse(psql(TABLE_ACL_SQL.trim()));
  assert.deepEqual(after, FIX_TBL, 'P1 must leave the ACLs corrected, not drifted');
  t.diagnostic('P1: payout redirect reproduced under drift, refused after the migration');
});
