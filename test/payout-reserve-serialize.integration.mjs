// test/payout-reserve-serialize.integration.mjs — M8-T7 (Phase 2): reserve/clawback serialization.
//
// 20260716130000_payout_reserve_serialize.sql makes TWO additive edits to payout_batch_reserve:
//   (1) its default p_hold is sourced from app.payout_hold_interval() (the single source also
//       read by admin_open_clawback's negative-payable post-condition — 20260716140000), so the
//       reserve maturity boundary and the clawback money-safety boundary can NEVER diverge; and
//   (2) FOR UPDATE OF p on the publisher SELECT, so a reserve serializes on the same publisher
//       row that admin_open_clawback takes SELECT ... FOR UPDATE on.
//
// The transfer/confirm core (payout_confirm/payout_fail/payout_reverse) is UNTOUCHED. This suite
// proves: the single-source hold couples both call sites; the row lock is present and actually
// blocks a concurrent FOR UPDATE on the same publisher row; and BOTH serialized interleavings of
// (reserve, admin_open_clawback) leave publisher_payable >= 0 (never a negative-payable window).
//
// Fixtures + assertions go through psql (verified publishers, back-dated cleared earnings, the
// app-schema money-admin membership). Self-skips without the local stack, psql, or the migrations.
//
// WHAT IS TESTED:
//   S1 — single source + lock present: both function defs reference app.payout_hold_interval();
//        reserve's def contains FOR UPDATE OF p; app.payout_hold_interval() = interval '7 days'
//   S2 — reserve-THEN-clawback: reserve (DEFAULT hold matures an 8-day earning) creates a pending
//        payout; admin_open_clawback then refuses with payout_active; payable stays >= 0
//   S3 — clawback-THEN-reserve: admin_open_clawback reverses an earning first; reserve then sees
//        the reduced payable and skips below_min; payable stays >= 0
//   S4 — genuine row-lock contention: while one txn holds SELECT ... FOR UPDATE on the publisher
//        row, a second connection's FOR UPDATE on the same row blocks and hits lock_timeout

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL    = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
// Run a multi-statement psql script from stdin (used for the transaction that holds a row lock and
// shells out to a second connection via \! ). Returns combined stdout (best-effort on failure).
function psqlScript(script) {
  try { return execFileSync('psql', [DB_URL], { input: script, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch (e) { return String(e.stdout || '') + String(e.stderr || ''); }
}

async function rpc(fnName, body, token) {
  const headers = { apikey: token ?? ANON, 'content-type': 'application/json', accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }
function migrationPresent() {
  try {
    return psql("select (to_regprocedure('public.admin_open_clawback(uuid,text)') is not null and to_regprocedure('public.payout_batch_reserve(interval,bigint,bigint,int)') is not null and to_regprocedure('app.payout_hold_interval()') is not null);") === 't';
  } catch { return false; }
}

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const PRESENT  = PSQL_OK ? migrationPresent() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !PRESENT ? 'payout_reserve_serialize / admin_open_clawback not applied — SKIPPING'
  : false;
if (SKIP) console.log(`[payout-reserve-serialize.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Money-admin persona (member of app.admins + app.money_admins, aal2) for admin_open_clawback.
// ---------------------------------------------------------------------------
const MADMIN = { authId: randomUUID() };
const MADMIN_JWT = mintJwt(MADMIN.authId, { aal: 'aal2' });
const REASON = 'M8 race-serialization test';

const GROSS = 10_000_000, PUB = 6_000_000;     // 60/40 split: each impression earns 6M
const MIN = 25_000_000, VEL = 100_000_000_000, LIM = 500;
const created = [];   // { authId, pubId }

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

// A payout-eligible publisher: verified Connect account, active, not deleted.
function newVerifiedPublisher() {
  const authId = randomUUID(), pubId = randomUUID();
  seedUser(authId, `prs-${authId}@example.com`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, payout_status, status)
    values ('${pubId}','${authId}','prs-${pubId.slice(0,8)}','FR','acct_test_${pubId.slice(0,8)}','verified','active');`);
  created.push({ authId, pubId });
  return { authId, pubId };
}

// One cleared cpva impression (its own window) earning PUB, aged `ageDays`. Returns the impression id.
function addEarning(pubId, ageDays) {
  const impId = randomUUID(), winId = randomUUID(), grp = randomUUID();
  const plat = GROSS - PUB;
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, created_at)
    values ('${impId}','${winId}','${pubId}',5,${GROSS},'cleared', now() - interval '${ageDays} days');`);
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','cpva_accrual','advertiser_billing',${GROSS},'cleared','impression','${impId}',null),
    ('${grp}','cpva_accrual','publisher_earnings',${-PUB},'cleared','impression','${impId}','${pubId}'),
    ('${grp}','cpva_accrual','platform_revenue',${-plat},'cleared','impression','${impId}',null);`);
  return impId;
}

function payable(pubId) {
  return Number(psql(`select app.publisher_payable_micros('${pubId}'::uuid, app.payout_hold_interval());`));
}

function seedFixture() {
  seedUser(MADMIN.authId, `prs-madmin-${MADMIN.authId}@example.com`);
  psql(`insert into app.admins (auth_user_id) values ('${MADMIN.authId}');`);
  psql(`insert into app.money_admins (auth_user_id) values ('${MADMIN.authId}');`);
}

function teardownFixture() {
  try {
    for (const { authId, pubId } of created) {
      try {
        psql(`delete from public.clawback_reviews where impression_id in (select id from public.impressions where publisher_id='${pubId}');`);
        psql(`delete from public.risk_flags where impression_id in (select id from public.impressions where publisher_id='${pubId}')
             or window_id in (select window_id from public.impressions where publisher_id='${pubId}');`);
        psql(`delete from public.ledger_entries where entry_group_id in (
             select entry_group_id from public.ledger_entries
              where publisher_id='${pubId}'
                 or source_id in (select id from public.impressions where publisher_id='${pubId}')
                 or source_id in (select id from public.payouts where publisher_id='${pubId}'));`);
        psql(`delete from public.payouts where publisher_id='${pubId}';`);
        psql(`delete from public.impressions where publisher_id='${pubId}';`);
        psql(`delete from public.devices where publisher_id='${pubId}';`);
        psql(`delete from public.publishers where id='${pubId}';`);
        psql(`delete from auth.users where id='${authId}';`);
      } catch { /* best-effort per publisher */ }
    }
    psql(`delete from app.admin_action_log where actor='${MADMIN.authId}';`);
    psql(`delete from app.money_admins where auth_user_id='${MADMIN.authId}';`);
    psql(`delete from app.admins where auth_user_id='${MADMIN.authId}';`);
    psql(`delete from auth.users where id='${MADMIN.authId}';`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

// ---------------------------------------------------------------------------
// S1 — single-source hold + lock present (the "changing the constant changes both call sites" probe).
// ---------------------------------------------------------------------------
test('S1: both call sites source app.payout_hold_interval() and reserve locks the publisher row', { skip: SKIP }, async () => {
  const reserveDef = psql(`select pg_get_functiondef('public.payout_batch_reserve(interval,bigint,bigint,int)'::regprocedure);`);
  assert.match(reserveDef, /app\.payout_hold_interval\(\)/, 'reserve default p_hold must source app.payout_hold_interval()');
  assert.match(reserveDef, /FOR UPDATE OF p/i, 'reserve must take FOR UPDATE OF p on the publisher SELECT');
  assert.doesNotMatch(reserveDef, /default '7 days'|interval '7 days'/i, 'reserve must not hardcode a divergent 7-day literal');

  const clawbackDef = psql(`select pg_get_functiondef('public.admin_open_clawback(uuid,text)'::regprocedure);`);
  assert.match(clawbackDef, /app\.payout_hold_interval\(\)/, "admin_open_clawback's guard must source the SAME app.payout_hold_interval()");
  assert.doesNotMatch(clawbackDef, /interval '7 days'/i, "admin_open_clawback must not hardcode a divergent 7-day literal");

  // The shared constant is 7 days, so both boundaries resolve identically.
  assert.equal(psql(`select app.payout_hold_interval();`), '7 days', 'the single-source hold is 7 days');
});

// ---------------------------------------------------------------------------
// S2 — reserve THEN clawback: the clawback refuses on the active payout; payable stays >= 0.
//      Reserve is called with DEFAULTS, so it also proves the default hold (7d) matures an 8-day earning.
// ---------------------------------------------------------------------------
test('S2: reserve-then-clawback → payout_active refusal; payable never negative', { skip: SKIP }, async () => {
  const { pubId } = newVerifiedPublisher();
  const imps = [];
  for (let i = 0; i < 5; i++) imps.push(addEarning(pubId, 8)); // 5 * 6M = 30M matured past the 7d default hold

  // Reserve with DEFAULTS (no p_hold) — proves the default resolves to a 7-day maturity.
  const rres = await rpc('payout_batch_reserve', {}, SERVICE);
  assert.ok(rres.ok, `reserve must succeed: ${JSON.stringify(rres.data)}`);
  const poRow = psql(`select status||'|'||amount_micros from public.payouts where publisher_id='${pubId}';`);
  const [poStatus, poAmt] = poRow.split('|');
  assert.equal(poStatus, 'pending', 'reserve created a pending payout (default hold matured the 8-day earning)');
  assert.equal(poAmt, String(5 * PUB), 'reserved the full matured 30M');

  // Now the clawback must refuse: an active (pending) payout exists for this publisher.
  const cres = await rpc('admin_open_clawback', { p_impression_id: imps[0], p_reason: REASON }, MADMIN_JWT);
  assert.ok(cres.ok, `refusal returns 200 with ok:false, got ${cres.status}: ${JSON.stringify(cres.data)}`);
  assert.equal(cres.data?.ok, false);
  assert.equal(cres.data?.reason, 'payout_active', 'clawback refuses while a payout is in flight');

  // Nothing reversed; the pending payout books no ledger, so payable is unchanged and >= 0.
  assert.equal(psql(`select state from public.impressions where id='${imps[0]}';`), 'cleared', 'impression untouched by the refused clawback');
  assert.ok(payable(pubId) >= 0, 'payable must remain >= 0 after the serialized reserve-then-clawback');
});

// ---------------------------------------------------------------------------
// S3 — clawback THEN reserve: reserve observes the reduced (post-reversal) payable and skips
//      below_min; payable stays >= 0. Proves the reserve can never over-reserve a reversed earning.
// ---------------------------------------------------------------------------
test('S3: clawback-then-reserve → reserve sees the reduced payable and skips; payable never negative', { skip: SKIP }, async () => {
  const { pubId } = newVerifiedPublisher();
  const imps = [];
  for (let i = 0; i < 5; i++) imps.push(addEarning(pubId, 8)); // 30M matured, unpaid, no payout yet

  assert.equal(payable(pubId), 5 * PUB, 'payable is 30M before the clawback');

  // Clawback one impression's window first → payable drops to 24M (< 25M MIN).
  const cres = await rpc('admin_open_clawback', { p_impression_id: imps[0], p_reason: REASON }, MADMIN_JWT);
  assert.equal(cres.data?.ok, true, `clawback must succeed (unpaid, aged): ${JSON.stringify(cres.data)}`);
  assert.equal(payable(pubId), 4 * PUB, 'payable dropped by exactly the reversed earning (24M)');

  // Reserve with DEFAULTS now sees 24M < 25M MIN → must NOT reserve this publisher.
  const rres = await rpc('payout_batch_reserve', {}, SERVICE);
  assert.ok(rres.ok, `reserve must succeed: ${JSON.stringify(rres.data)}`);
  assert.equal(psql(`select count(*) from public.payouts where publisher_id='${pubId}';`), '0',
    'reserve must skip the below-min publisher after the reversal (no over-reserve of a reversed earning)');
  assert.ok(payable(pubId) >= 0, 'payable must remain >= 0 after the serialized clawback-then-reserve');
});

// ---------------------------------------------------------------------------
// S4 — genuine row-lock contention: while txn A holds SELECT ... FOR UPDATE on the publisher row,
//      a second connection's FOR UPDATE on the same row blocks and hits lock_timeout. This is the
//      exact mechanism that serializes payout_batch_reserve (FOR UPDATE OF p) against
//      admin_open_clawback (SELECT ... FOR UPDATE on public.publishers).
// ---------------------------------------------------------------------------
test('S4: a held publisher-row FOR UPDATE blocks a concurrent FOR UPDATE on the same row', { skip: SKIP }, async () => {
  const { pubId } = newVerifiedPublisher();

  // Outer txn holds the row lock, then shells out (still inside the txn) to a SECOND connection that
  // tries to lock the same row with a short lock_timeout; that inner connection must be blocked and
  // time out — proving the two operations serialize on the publisher row rather than interleave.
  const script = [
    'BEGIN;',
    `SELECT 1 FROM public.publishers WHERE id='${pubId}' FOR UPDATE;`,
    `\\! psql '${DB_URL}' -tAqc "SET lock_timeout='800ms'; SELECT 1 FROM public.publishers WHERE id='${pubId}' FOR UPDATE;" 2>&1`,
    'COMMIT;',
    '',
  ].join('\n');

  const out = psqlScript(script);
  assert.match(out, /lock timeout|lock_timeout|canceling statement due to lock timeout/i,
    `the concurrent FOR UPDATE on the locked publisher row must block and hit lock_timeout, got:\n${out}`);
});
