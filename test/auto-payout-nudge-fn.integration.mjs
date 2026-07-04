// test/auto-payout-nudge-fn.integration.mjs — proves the FIX for review finding 1 through the
// REAL served function (not psql): app.payout_nudge_candidates is SET-returning (a JSON array),
// and the fix routes it through `serviceRpcRows` (which does NOT unwrap arrays) instead of
// `serviceRpc` (which collapses any array to its first element, so `cands` was always `[]`).
//
// This test hits the live `/payout/batch` endpoint (non-dry-run) and asserts the JSON response
// carries `nudge_candidates >= 1` — that number can ONLY be > 0 if the edge function actually
// read the candidate rows back as an array, which is exactly what `serviceRpc`'s old unwrap
// prevented. `nudged` may legitimately be 0 (no RESEND_API_KEY configured locally) — that's not
// what this test is proving.
//
// SAFETY (money core untouched, but this DOES hit non-dry-run /payout/batch): before seeding
// anything, we run a `dry_run=true` pass first and require `would_transfer` to be EMPTY. That
// dry-run reuses the exact same reserve + "every db-pending payout" logic as the live path
// (traps #2), so an empty `would_transfer` guarantees the live call moves zero Stripe money.
// If it's non-empty (a reservable onboarded publisher, or a leftover pending payout, already
// exists in the local DB) we SKIP rather than risk a real transfer. Our own seeded publisher is
// deliberately UN-ONBOARDED (stripe_account_id NULL), so payout_batch_reserve can never select
// it either way — see 20260629100000_payout_rails.sql's reserve WHERE clause.
//
// Requires: `supabase functions serve stripe-connect --no-verify-jwt --env-file
// supabase/functions/.env` (or equivalent) running locally with LUMALINE_CRON_SECRET set to the
// SAME value this test sends in `x-lumaline-cron-secret`. Self-skips if either is missing.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const FN = process.env.STRIPE_CONNECT_URL || 'http://127.0.0.1:54321/functions/v1/stripe-connect';
const CRON_SECRET = process.env.LUMALINE_CRON_SECRET || '';
const DB_URL = process.env.SUPABASE_DB_URL || 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

async function up() {
  try {
    const r = await fetch(`${FN}/payout/batch`, { method: 'OPTIONS', signal: AbortSignal.timeout(2000) });
    return r.status === 200;
  } catch {
    return false;
  }
}
const FN_UP = await up();

let SKIP = false;
if (!FN_UP) SKIP = 'stripe-connect fn not served — SKIPPING';
else if (!CRON_SECRET) SKIP = 'LUMALINE_CRON_SECRET not set in this shell — SKIPPING (must match the served fn\'s env)';
if (SKIP) console.log(`[auto-payout-nudge-fn] ${SKIP}`);

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

function newPublisher({ withAcct = false, country = 'US' } = {}) {
  const authId = randomUUID(), pubId = randomUUID();
  const email = `nudgefn-${authId}@example.com`;
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
  const gross = Math.round(pubMicros / 0.6);
  const plat = gross - pubMicros;
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, created_at)
    values ('${impId}','${winId}','${pubId}',5,${gross},'cleared', now() - interval '${ageDays} days');`);
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','cpva_accrual','advertiser_billing',${gross},'cleared','impression','${impId}',null),
    ('${grp}','cpva_accrual','publisher_earnings',${-pubMicros},'cleared','impression','${impId}','${pubId}'),
    ('${grp}','cpva_accrual','platform_revenue',${-plat},'cleared','impression','${impId}',null);`);
}

const created = [];
function teardown() {
  for (const { authId, pubId } of created) {
    try {
      psql(`delete from public.ledger_entries where publisher_id='${pubId}'
        or entry_group_id in (select entry_group_id from public.ledger_entries where source_id in (select id from public.impressions where publisher_id='${pubId}'));`);
      psql(`delete from public.impressions where publisher_id='${pubId}';`);
      psql(`delete from public.devices where publisher_id='${pubId}';`);
      psql(`delete from public.payouts where publisher_id='${pubId}';`);
      psql(`delete from public.publishers where id='${pubId}';`);
      psql(`delete from auth.users where id='${authId}';`);
    } catch { /* best-effort */ }
  }
}
if (!SKIP) process.on('exit', teardown);

async function postBatch(dryRun) {
  const r = await fetch(`${FN}/payout/batch${dryRun ? '?dry_run=true' : ''}`, {
    method: 'POST',
    headers: { 'x-lumaline-cron-secret': CRON_SECRET, 'content-type': 'application/json' },
    body: '{}',
  });
  return { status: r.status, body: await r.json() };
}

test('nudge_candidates in /payout/batch response proves serviceRpcRows reads the array (not serviceRpc\'s collapse)', { skip: SKIP }, async () => {
  // SAFETY: refuse to risk a live transfer if the DB already has a reservable onboarded
  // publisher (or a leftover db-pending payout) sitting around.
  const pre = await postBatch(true);
  assert.equal(pre.status, 200, `dry-run pre-check must succeed: ${JSON.stringify(pre.body)}`);
  assert.equal(pre.body.ok, true, 'dry-run pre-check must report ok:true');
  const wouldTransfer = Array.isArray(pre.body.would_transfer) ? pre.body.would_transfer : [];
  if (wouldTransfer.length > 0) {
    console.log(`[auto-payout-nudge-fn] SKIPPING: ${wouldTransfer.length} payout(s) would already transfer — refusing to risk a live Stripe transfer in this test`);
    return; // bail out of the test body without asserting further (safety over coverage)
  }

  // Seed ONLY an un-onboarded publisher (stripe_account_id NULL) with matured, over-min
  // earnings. payout_batch_reserve can never select it (requires stripe_account_id IS NOT
  // NULL), so this seed cannot itself trigger a transfer — it can only make it a nudge
  // candidate.
  const pub = newPublisher({ withAcct: false });
  created.push(pub);
  addEarningMicros(pub.pubId, 1_500_000, 10); // > €1 min, past the 7-day hold

  const live = await postBatch(false);
  assert.equal(live.status, 200, `live /payout/batch must succeed: ${JSON.stringify(live.body)}`);
  assert.equal(live.body.ok, true, 'live response must report ok:true');
  assert.equal(live.body.paid, 0, 'no onboarded publisher exists (guarded by the dry-run pre-check) -> paid must be 0');
  assert.equal(typeof live.body.nudge_candidates, 'number', 'response must carry a numeric nudge_candidates counter');
  assert.ok(
    live.body.nudge_candidates >= 1,
    `nudge_candidates must be >= 1 (got ${live.body.nudge_candidates}) — proves payout_nudge_candidates' array was read via serviceRpcRows, not collapsed by serviceRpc`,
  );
  assert.equal(typeof live.body.nudged, 'number', 'response must carry a numeric nudged counter (0 is fine — no RESEND key locally)');
});
