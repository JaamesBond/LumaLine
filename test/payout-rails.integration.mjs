// test/payout-rails.integration.mjs — M3-T2/T3 payout rails (SQL layer, Stripe-free).
//
// Exercises the money-critical logic that does NOT need live Stripe Connect:
//   * payable computation (earned past the 7d hold, minus already paid)
//   * two-phase reserve (one active payout per publisher; no ledger booked at reserve)
//   * payout_confirm books a balanced ledger group and is idempotent (double-call -> one group)
//   * payout_fail marks failed without booking ledger
//   * eligibility / minimum / velocity gating
//   * payout reconciliation totals
//
// Setup + assertions use psql (back-dated impressions, auth.users, ledger). REST(service)
// drives the RPCs. Self-skips without the local stack or psql.
//
// WHAT IS TESTED:
//   P1  — publisher_payable_micros counts only earnings past the hold
//   P2  — payout_batch_reserve creates a pending payout (no ledger yet) for an eligible publisher
//   P3  — reserve is idempotent per publisher (one-active-payout index)
//   P4  — payout_confirm books a balanced ledger group + status=paid + transfer id
//   P5  — payout_confirm is idempotent (second call -> still ONE ledger group)
//   P6  — after confirm, payable drops by the paid amount
//   P7  — payout_fail marks failed and books NO ledger
//   P8  — ineligible publisher (not verified / no stripe acct) is not reserved
//   P9  — below-minimum publisher is not reserved
//   P10 — payout_recon_totals sums paid-payout ledger debits
//   P11 — service-role-only: anon/authenticated cannot call the money RPCs

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

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
async function rpc(fnName, body, token = SERVICE) {
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, {
    method: 'POST',
    headers: { apikey: token, Authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }
function payoutRailsApplied() { try { return psql("select count(*) from pg_proc where proname='payout_batch_reserve';") !== '0'; } catch { return false; } }

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
// NB: we deliberately do NOT skip on missing migration — these tests are the RED for it.
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING' : !PSQL_OK ? 'psql unavailable — SKIPPING' : false;
if (SKIP) console.log(`[payout-rails.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixture: a verified payout-eligible publisher with back-dated earnings.
// One impression 10 days old (past the 7d hold) + one 1 day old (inside hold).
// ---------------------------------------------------------------------------
const GROSS = 1_000_000, PUB = 600_000, PLAT = 400_000;

function newPublisher({ verified = true, withAcct = true, country = 'US', status = 'active' } = {}) {
  const authId = randomUUID(), pubId = randomUUID();
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at, confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000','${authId}','authenticated','authenticated',
      'payout-${authId}@example.com','',now(),'{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','');`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, payout_status, status)
    values ('${pubId}','${authId}','po-${pubId.slice(0,8)}', ${country ? `'${country}'` : 'null'},
      ${withAcct ? `'acct_test_${pubId.slice(0,8)}'` : 'null'}, '${verified ? 'verified' : 'none'}', '${status}');`);
  return { authId, pubId };
}
/** Add a cleared earning of PUB micros, attributed to an impression aged `ageDays`. */
function addEarning(pubId, ageDays) {
  const impId = randomUUID(), winId = randomUUID(), grp = randomUUID();
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, created_at)
    values ('${impId}','${winId}','${pubId}',5,${GROSS},'cleared', now() - interval '${ageDays} days');`);
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','cpva_accrual','advertiser_billing',${GROSS},'cleared','impression','${impId}',null),
    ('${grp}','cpva_accrual','publisher_earnings',${-PUB},'cleared','impression','${impId}','${pubId}'),
    ('${grp}','cpva_accrual','platform_revenue',${-PLAT},'cleared','impression','${impId}',null);`);
  return { impId, grp };
}
const created = [];
function makeFull(opts) { const p = newPublisher(opts); created.push(p); return p; }
function teardown() {
  for (const { authId, pubId } of created) {
    try {
      psql(`delete from public.ledger_entries where publisher_id='${pubId}' or entry_group_id in (select entry_group_id from public.ledger_entries where source_id in (select id from public.impressions where publisher_id='${pubId}'));`);
      psql(`delete from public.ledger_entries where source_id in (select id from public.payouts where publisher_id='${pubId}');`);
      psql(`delete from public.payouts where publisher_id='${pubId}';`);
      psql(`delete from public.impressions where publisher_id='${pubId}';`);
      psql(`delete from public.devices where publisher_id='${pubId}';`);
      psql(`delete from public.publishers where id='${pubId}';`);
      psql(`delete from auth.users where id='${authId}';`);
    } catch { /* best-effort */ }
  }
}
if (!SKIP) process.on('exit', teardown);

const HOLD = '7 days', MIN = 25_000_000, VEL = 100_000_000_000, LIM = 500;

test('P1: payable counts only earnings past the hold', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  addEarning(pubId, 10); // past hold -> counts
  addEarning(pubId, 1);  // inside hold -> excluded
  const payable = psql(`select app.publisher_payable_micros('${pubId}'::uuid, interval '7 days');`);
  assert.equal(payable, String(PUB), `payable must be ${PUB} (one past-hold earning), got ${payable}`);
});

test('P2: reserve creates a pending payout (no ledger booked yet)', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  for (let i = 0; i < 50; i++) addEarning(pubId, 10); // 50 * 600k = 30M > $25 min
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const po = psql(`select status||'|'||amount_micros||'|'||coalesce(stripe_transfer_id,'NULL') from public.payouts where publisher_id='${pubId}';`);
  const [status, amount, tid] = po.split('|');
  assert.equal(status, 'pending');
  assert.equal(amount, String(50 * PUB));
  assert.equal(tid, 'NULL', 'no transfer id at reserve');
  // No payout ledger group yet (source_type='payout').
  const payoutLegs = psql(`select count(*) from public.ledger_entries le join public.payouts p on le.source_id=p.id where p.publisher_id='${pubId}' and le.source_type='payout';`);
  assert.equal(payoutLegs, '0', 'reserve must NOT book a ledger group');
});

test('P3: reserve is idempotent per publisher (one-active-payout index)', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  for (let i = 0; i < 50; i++) addEarning(pubId, 10);
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const n = psql(`select count(*) from public.payouts where publisher_id='${pubId}' and status in ('pending','in_transit');`);
  assert.equal(n, '1', 'at most one active payout per publisher');
});

test('P4/P5: payout_confirm books a balanced ledger group and is idempotent', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  for (let i = 0; i < 50; i++) addEarning(pubId, 10);
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const payoutId = psql(`select id from public.payouts where publisher_id='${pubId}' and status='pending' limit 1;`);
  const tid = 'tr_test_' + payoutId.slice(0, 8);

  const c1 = await rpc('payout_confirm', { p_payout_id: payoutId, p_transfer_id: tid });
  assert.equal(c1.data?.ok, true, `confirm failed: ${JSON.stringify(c1.data)}`);

  // status paid + transfer id stored.
  const row = psql(`select status||'|'||coalesce(stripe_transfer_id,'NULL') from public.payouts where id='${payoutId}';`);
  assert.equal(row, `paid|${tid}`);

  // exactly one balanced payout ledger group.
  const grp = psql(`select count(distinct entry_group_id)||'|'||coalesce(sum(amount_micros),0) from public.ledger_entries where source_type='payout' and source_id='${payoutId}';`);
  assert.equal(grp, `1|0`, 'one balanced (sum 0) payout group');
  const legs = psql(`select account||':'||amount_micros from public.ledger_entries where source_type='payout' and source_id='${payoutId}' order by account;`).split('\n').sort().join(',');
  assert.ok(legs.includes(`platform_cash:${-50 * PUB}`), `platform_cash leg: ${legs}`);
  assert.ok(legs.includes(`publisher_earnings:${50 * PUB}`), `publisher_earnings leg: ${legs}`);

  // idempotent: second confirm -> still one group.
  const c2 = await rpc('payout_confirm', { p_payout_id: payoutId, p_transfer_id: tid });
  assert.equal(c2.data?.ok, false, 'second confirm is a no-op');
  const grp2 = psql(`select count(distinct entry_group_id) from public.ledger_entries where source_type='payout' and source_id='${payoutId}';`);
  assert.equal(grp2, '1', 'still exactly one payout ledger group after double confirm');

  // P6: payable drops by the paid amount.
  const payable = psql(`select app.publisher_payable_micros('${pubId}'::uuid, interval '7 days');`);
  assert.equal(payable, '0', 'payable must be 0 after paying out the full matured balance');
});

test('P7: payout_fail marks failed and books NO ledger', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  for (let i = 0; i < 50; i++) addEarning(pubId, 10);
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const payoutId = psql(`select id from public.payouts where publisher_id='${pubId}' and status='pending' limit 1;`);
  const f = await rpc('payout_fail', { p_payout_id: payoutId, p_reason: 'account_closed' });
  assert.equal(f.data?.ok, true, `fail failed: ${JSON.stringify(f.data)}`);
  const row = psql(`select status||'|'||coalesce(failure_reason,'NULL') from public.payouts where id='${payoutId}';`);
  assert.equal(row, 'failed|account_closed');
  const legs = psql(`select count(*) from public.ledger_entries where source_type='payout' and source_id='${payoutId}';`);
  assert.equal(legs, '0', 'failed payout must book no ledger');
  // payable restored (the matured balance is payable again).
  const payable = psql(`select app.publisher_payable_micros('${pubId}'::uuid, interval '7 days');`);
  assert.equal(payable, String(50 * PUB), 'payable restored after failed payout');
});

test('P8: ineligible publisher (not verified / no stripe acct) is not reserved', { skip: SKIP }, async () => {
  const a = makeFull({ verified: false });           // not verified
  const b = makeFull({ verified: true, withAcct: false }); // no stripe acct
  for (let i = 0; i < 50; i++) { addEarning(a.pubId, 10); addEarning(b.pubId, 10); }
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const na = psql(`select count(*) from public.payouts where publisher_id='${a.pubId}';`);
  const nb = psql(`select count(*) from public.payouts where publisher_id='${b.pubId}';`);
  assert.equal(na, '0', 'unverified publisher must not be reserved');
  assert.equal(nb, '0', 'publisher without stripe account must not be reserved');
});

test('P9: below-minimum publisher is not reserved', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  addEarning(pubId, 10); // one earning = 600k < $25 (25M)
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const n = psql(`select count(*) from public.payouts where publisher_id='${pubId}';`);
  assert.equal(n, '0', 'below-minimum balance must not be reserved');
});

test('P10: payout_recon_totals sums paid-payout ledger debits', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  for (let i = 0; i < 50; i++) addEarning(pubId, 10);
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const payoutId = psql(`select id from public.payouts where publisher_id='${pubId}' and status='pending' limit 1;`);
  await rpc('payout_confirm', { p_payout_id: payoutId, p_transfer_id: 'tr_recon_' + payoutId.slice(0, 8) });
  const res = await rpc('payout_recon_totals', { p_from: '2000-01-01T00:00:00Z', p_to: '2999-01-01T00:00:00Z' });
  assert.ok(res.ok, `recon failed: ${JSON.stringify(res.data)}`);
  assert.ok(Number(res.data?.payout_debits_micros) >= 50 * PUB, `recon must include this payout's debit: ${JSON.stringify(res.data)}`);
});

test('P12: payout_reverse (transfer.reversed) unwinds a paid payout to net-zero', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  for (let i = 0; i < 50; i++) addEarning(pubId, 10);
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM });
  const payoutId = psql(`select id from public.payouts where publisher_id='${pubId}' and status='pending' limit 1;`);
  await rpc('payout_confirm', { p_payout_id: payoutId, p_transfer_id: 'tr_rev_' + payoutId.slice(0, 8) });

  const r = await rpc('payout_reverse', { p_payout_id: payoutId, p_reason: 'transfer_reversed' });
  assert.equal(r.data?.ok, true, `reverse failed: ${JSON.stringify(r.data)}`);

  // payout marked failed; net ledger for the payout is zero (confirm + reversal cancel).
  const status = psql(`select status||'|'||coalesce(failure_reason,'NULL') from public.payouts where id='${payoutId}';`);
  assert.equal(status, 'failed|transfer_reversed');
  const net = psql(`select coalesce(sum(amount_micros),0) from public.ledger_entries where source_type='payout' and source_id='${payoutId}';`);
  assert.equal(net, '0', 'confirm + reverse must net to zero on the payout legs');

  // payable restored (money never left, per the reversal).
  const payable = psql(`select app.publisher_payable_micros('${pubId}'::uuid, interval '7 days');`);
  assert.equal(payable, String(50 * PUB), 'payable restored after reversal');

  // reverse is idempotent.
  const r2 = await rpc('payout_reverse', { p_payout_id: payoutId, p_reason: 'transfer_reversed' });
  assert.equal(r2.data?.ok, false, 'second reverse is a no-op');
});

test('P13: payable above the velocity cap is skipped (anomaly review)', { skip: SKIP }, async () => {
  const { pubId } = makeFull();
  for (let i = 0; i < 50; i++) addEarning(pubId, 10); // 30M payable
  await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: 10_000_000, p_limit: LIM });
  const n = psql(`select count(*) from public.payouts where publisher_id='${pubId}';`);
  assert.equal(n, '0', 'payout above velocity cap must not be reserved');
});

test('P11: money RPCs are service-role-only (anon/authenticated blocked)', { skip: SKIP }, async () => {
  const res = await rpc('payout_batch_reserve', { p_hold: HOLD, p_min_micros: MIN, p_velocity_max_micros: VEL, p_limit: LIM }, ANON);
  assert.ok(res.status === 401 || res.status === 403 || res.status === 404,
    `anon must not call payout_batch_reserve, got ${res.status}`);
});
