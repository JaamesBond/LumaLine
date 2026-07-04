// test/auto-payout-nudge.integration.mjs — M5-T4 auto-payout nudge candidates + dedup (Stripe-free).
//
// Exercises public.payout_nudge_candidates + public.mark_connect_nudged (20260704150000_auto_payout.sql)
// directly against the local Supabase DB via psql — the connecting role (postgres) is a superuser
// and bypasses the service_role-only grants, same trick test/auto-payout-sql.integration.mjs relies
// on for `select app.run_payout()`. Setup mirrors test/payout-rails.integration.mjs's
// auth.users -> publishers -> matured cleared earnings fixture (addEarningMicros). No Stripe / REST
// involved — this is pure SQL-layer proof.
//
// N1 — un-onboarded (stripe_account_id null), over-minimum publisher is a nudge candidate, with the
//      right email/handle/payable_micros.
// N2 — mark_connect_nudged(ARRAY[id]) sets connect_nudge_at.
// N3 — a second candidates call excludes the just-nudged publisher (deduped within 6 days).
// N4 — negative control: an onboarded (stripe_account_id set) over-minimum publisher is never a
//      candidate.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const DB_URL = process.env.SUPABASE_DB_URL || 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const SKIP = psqlWorks() ? false : 'local DB unreachable — SKIPPING';
if (SKIP) console.log(`[auto-payout-nudge] ${SKIP}`);

const MIN = 1_000_000;       // €1 minimum, per the task spec
const HOLD_SQL = "interval '7 days'";

function newPublisher({ withAcct = false, country = 'US' } = {}) {
  const authId = randomUUID(), pubId = randomUUID();
  const email = `nudge-${authId}@example.com`;
  const handle = `po-${pubId.slice(0, 8)}`;
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at, confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000','${authId}','authenticated','authenticated',
      '${email}','',now(),'{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','');`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, payout_status, status)
    values ('${pubId}','${authId}','${handle}','${country}',
      ${withAcct ? `'acct_test_${pubId.slice(0, 8)}'` : 'null'}, 'verified', 'active');`);
  return { authId, pubId, email, handle };
}

/** Add a cleared cpva_accrual earning of `pubMicros`, backed by an impression aged `ageDays`. */
function addEarningMicros(pubId, pubMicros, ageDays = 10) {
  const impId = randomUUID(), winId = randomUUID(), grp = randomUUID();
  const gross = Math.round(pubMicros / 0.6); // doesn't have to balance 60/40 exactly; explicit legs below
  const plat = gross - pubMicros;
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, created_at)
    values ('${impId}','${winId}','${pubId}',5,${gross},'cleared', now() - interval '${ageDays} days');`);
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','cpva_accrual','advertiser_billing',${gross},'cleared','impression','${impId}',null),
    ('${grp}','cpva_accrual','publisher_earnings',${-pubMicros},'cleared','impression','${impId}','${pubId}'),
    ('${grp}','cpva_accrual','platform_revenue',${-plat},'cleared','impression','${impId}',null);`);
  return { impId, grp };
}

const created = [];
function makeFull(opts) { const p = newPublisher(opts); created.push(p); return p; }
function teardown() {
  for (const { authId, pubId } of created) {
    try {
      psql(`delete from public.ledger_entries where publisher_id='${pubId}'
        or entry_group_id in (select entry_group_id from public.ledger_entries where source_id in (select id from public.impressions where publisher_id='${pubId}'));`);
      psql(`delete from public.impressions where publisher_id='${pubId}';`);
      psql(`delete from public.devices where publisher_id='${pubId}';`);
      psql(`delete from public.publishers where id='${pubId}';`);
      psql(`delete from auth.users where id='${authId}';`);
    } catch { /* best-effort */ }
  }
}
if (!SKIP) process.on('exit', teardown);

/** Row (as `id|email|handle|payable`) for `pubId` in the current nudge-candidates result, or '' if absent. */
function candidateRow(pubId) {
  return psql(`select coalesce(t.publisher_id::text,'') ||'|'|| coalesce(t.email,'') ||'|'|| coalesce(t.handle,'') ||'|'|| coalesce(t.payable_micros::text,'')
    from public.payout_nudge_candidates(${MIN}, ${HOLD_SQL}) t where t.publisher_id = '${pubId}'::uuid;`);
}

test('N1/N2/N3: un-onboarded over-min publisher is a nudge candidate; mark_connect_nudged dedupes it', { skip: SKIP }, () => {
  const pub = makeFull({ withAcct: false });
  addEarningMicros(pub.pubId, 1_500_000, 10); // matured (past 7d hold), > MIN

  // N1: appears as a candidate with the right contact + payable.
  const row = candidateRow(pub.pubId);
  assert.notEqual(row, '', 'un-onboarded, over-minimum publisher must appear as a nudge candidate');
  const [id, email, handle, payable] = row.split('|');
  assert.equal(id, pub.pubId, 'candidate publisher_id must match');
  assert.equal(email, pub.email, 'candidate email must match auth.users.email');
  assert.equal(handle, pub.handle, 'candidate handle must match publishers.handle');
  assert.ok(Number(payable) >= MIN, `payable_micros ${payable} must be >= ${MIN}`);

  // N2: mark_connect_nudged sets connect_nudge_at.
  const before = psql(`select coalesce(connect_nudge_at::text,'') from public.publishers where id='${pub.pubId}';`);
  assert.equal(before, '', 'connect_nudge_at must start unset');
  psql(`select public.mark_connect_nudged(array['${pub.pubId}']::uuid[]);`);
  const after = psql(`select coalesce(connect_nudge_at::text,'') from public.publishers where id='${pub.pubId}';`);
  assert.notEqual(after, '', 'connect_nudge_at must be set after mark_connect_nudged');

  // N3: a second candidates call excludes the just-nudged publisher (deduped within 6 days).
  const row2 = candidateRow(pub.pubId);
  assert.equal(row2, '', 'just-nudged publisher must be excluded from a second candidates call');
});

test('N4: onboarded (stripe_account_id set) over-minimum publisher is never a nudge candidate', { skip: SKIP }, () => {
  const pub = makeFull({ withAcct: true });
  addEarningMicros(pub.pubId, 1_500_000, 10); // matured, > MIN, but onboarded
  const row = candidateRow(pub.pubId);
  assert.equal(row, '', 'onboarded publisher must not be a nudge candidate regardless of payable balance');
});
