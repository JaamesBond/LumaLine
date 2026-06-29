// test/stripe-connect-webhook.integration.mjs — M3-T1 Stripe Connect webhook.
//
// The webhook is the trust boundary: it is the ONLY unauthenticated route, and its
// authentication IS the Stripe signature. These tests prove the money-critical
// guarantees locally, WITHOUT live Stripe Connect, by signing synthetic events with the
// local test secret (STRIPE_WEBHOOK_SECRET=whsec_test_lumaline_local in functions/.env):
//
//   W1 — a correctly-signed account.updated flips publisher payout_status -> verified
//   W2 — a tampered body (signature over the original) is REJECTED (400)
//   W3 — a replayed event id is a deduped no-op (one stripe_webhook_events row)
//   W4 — transfer.reversed unwinds a PAID payout (status failed, ledger nets to zero)
//   W5 — a missing Stripe-Signature header is REJECTED (400)
//   W6 — account.updated from an unsupported country -> ineligible_country
//
// Requires `supabase functions serve` running with the test secret + STRIPE_SECRET_KEY
// (constructEventAsync needs the SDK). Self-skips if the function or psql is unavailable.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const FN_BASE = 'http://127.0.0.1:54321/functions/v1/stripe-connect';
const DB_URL  = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const WEBHOOK_SECRET = 'whsec_test_lumaline_local';

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function stripeSig(payload, secret = WEBHOOK_SECRET, ts = Math.floor(Date.now() / 1000)) {
  const v1 = createHmac('sha256', secret).update(`${ts}.${payload}`).digest('hex');
  return `t=${ts},v1=${v1}`;
}
async function postWebhook(payload, sigHeader) {
  const headers = { apikey: ANON, 'content-type': 'application/json' };
  if (sigHeader !== null) headers['Stripe-Signature'] = sigHeader;
  const resp = await fetch(`${FN_BASE}/webhook`, { method: 'POST', headers, body: payload });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { status: resp.status, data };
}
function evt(type, object) {
  return JSON.stringify({ id: `evt_${randomUUID().replace(/-/g, '')}`, object: 'event', api_version: '2024-04-10', type, data: { object } });
}

async function fnUp() {
  try {
    // No signature -> the handler returns 400 (missing sig) if it is reachable.
    const r = await fetch(`${FN_BASE}/webhook`, { method: 'POST', headers: { apikey: ANON }, body: '{}', signal: AbortSignal.timeout(3000) });
    return r.status === 400 || r.status === 503; // reachable (503 if secret missing)
  } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const FN_OK   = await fnUp();
const PSQL_OK = psqlWorks();
const SKIP = !FN_OK ? 'stripe-connect fn unreachable (run `supabase functions serve`) — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING' : false;
if (SKIP) console.log(`[stripe-connect-webhook.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixtures (psql; auth.users + publisher + an optional paid payout).
// ---------------------------------------------------------------------------
const created = [];
function newPublisher({ acct, country = 'US', payout_status = 'pending' }) {
  const authId = randomUUID(), pubId = randomUUID();
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at, confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000','${authId}','authenticated','authenticated',
      'wh-${authId}@example.com','',now(),'{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','');`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, payout_status, status)
    values ('${pubId}','${authId}','wh-${pubId.slice(0,8)}','${country}','${acct}','${payout_status}','active');`);
  created.push({ authId, pubId });
  return pubId;
}
function newPaidPayout(pubId, transferId, amount) {
  const payoutId = randomUUID(), grp = randomUUID();
  psql(`insert into public.payouts (id, publisher_id, amount_micros, status, stripe_transfer_id, paid_at)
    values ('${payoutId}','${pubId}',${amount},'paid','${transferId}',now());`);
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','payout','publisher_earnings',${amount},'cleared','payout','${payoutId}','${pubId}'),
    ('${grp}','payout','platform_cash',${-amount},'cleared','payout','${payoutId}',null);`);
  return payoutId;
}
function teardown() {
  for (const { authId, pubId } of created) {
    try {
      psql(`delete from public.ledger_entries where source_id in (select id from public.payouts where publisher_id='${pubId}');`);
      psql(`delete from public.payouts where publisher_id='${pubId}';`);
      psql(`delete from public.publishers where id='${pubId}';`);
      psql(`delete from auth.users where id='${authId}';`);
    } catch { /* best-effort */ }
  }
  try { psql(`delete from public.stripe_webhook_events where type like 'account.%' or type like 'transfer.%';`); } catch { /* ignore */ }
}
if (!SKIP) process.on('exit', teardown);

test('W1: signed account.updated -> publisher payout_status verified', { skip: SKIP }, async () => {
  const acct = `acct_test_${randomUUID().slice(0, 8)}`;
  const pubId = newPublisher({ acct, country: 'US', payout_status: 'pending' });
  const payload = evt('account.updated', { id: acct, object: 'account', charges_enabled: true, payouts_enabled: true, details_submitted: true, country: 'US' });
  const res = await postWebhook(payload, stripeSig(payload));
  assert.equal(res.status, 200, `expected 200: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.eligibility, 'verified');
  const status = psql(`select payout_status from public.publishers where id='${pubId}';`);
  assert.equal(status, 'verified', 'publisher must be verified after account.updated');
});

test('W2: tampered body is rejected (400)', { skip: SKIP }, async () => {
  const acct = `acct_test_${randomUUID().slice(0, 8)}`;
  const pubId = newPublisher({ acct, country: 'US', payout_status: 'pending' });
  const original = evt('account.updated', { id: acct, object: 'account', charges_enabled: true, payouts_enabled: true, details_submitted: true, country: 'US' });
  const sig = stripeSig(original);                  // signature over the ORIGINAL
  const tampered = original.replace(acct, `acct_evil_${randomUUID().slice(0, 8)}`);
  const res = await postWebhook(tampered, sig);     // ...but send a DIFFERENT body
  assert.equal(res.status, 400, `tampered body must be rejected: ${JSON.stringify(res.data)}`);
  const status = psql(`select payout_status from public.publishers where id='${pubId}';`);
  assert.equal(status, 'pending', 'tampered webhook must not change state');
});

test('W3: replayed event id is a deduped no-op', { skip: SKIP }, async () => {
  const acct = `acct_test_${randomUUID().slice(0, 8)}`;
  newPublisher({ acct, country: 'US', payout_status: 'pending' });
  const payload = evt('account.updated', { id: acct, object: 'account', charges_enabled: true, payouts_enabled: true, details_submitted: true, country: 'US' });
  const sig = stripeSig(payload);
  const eventId = JSON.parse(payload).id;
  const r1 = await postWebhook(payload, sig);
  const r2 = await postWebhook(payload, sig);       // exact same event id
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200);
  assert.equal(r2.data?.duplicate, true, 'second delivery must be a deduped no-op');
  const n = psql(`select count(*) from public.stripe_webhook_events where event_id='${eventId}';`);
  assert.equal(n, '1', 'exactly one dedup row for the replayed event');
});

test('W4: transfer.reversed unwinds a paid payout (failed + ledger net zero)', { skip: SKIP }, async () => {
  const acct = `acct_test_${randomUUID().slice(0, 8)}`;
  const pubId = newPublisher({ acct, country: 'US', payout_status: 'verified' });
  const transferId = `tr_test_${randomUUID().slice(0, 8)}`;
  const payoutId = newPaidPayout(pubId, transferId, 30_000_000);
  const payload = evt('transfer.reversed', { id: transferId, object: 'transfer', amount: 3_000_00, currency: 'usd', metadata: { source: 'lumaline', payout_id: payoutId } });
  const res = await postWebhook(payload, stripeSig(payload));
  assert.equal(res.status, 200, `expected 200: ${JSON.stringify(res.data)}`);
  const status = psql(`select status||'|'||coalesce(failure_reason,'NULL') from public.payouts where id='${payoutId}';`);
  assert.equal(status, 'failed|transfer_reversed');
  const net = psql(`select coalesce(sum(amount_micros),0) from public.ledger_entries where source_type='payout' and source_id='${payoutId}';`);
  assert.equal(net, '0', 'confirm + reversal must net to zero');
});

test('W5: missing Stripe-Signature header is rejected (400)', { skip: SKIP }, async () => {
  const payload = evt('account.updated', { id: 'acct_test_nohdr', object: 'account', charges_enabled: true, payouts_enabled: true, details_submitted: true, country: 'US' });
  const res = await postWebhook(payload, null);
  assert.equal(res.status, 400, `missing signature must be rejected: ${JSON.stringify(res.data)}`);
});

test('W6: account.updated from an unsupported country -> ineligible_country', { skip: SKIP }, async () => {
  const acct = `acct_test_${randomUUID().slice(0, 8)}`;
  const pubId = newPublisher({ acct, country: 'US', payout_status: 'pending' });
  const payload = evt('account.updated', { id: acct, object: 'account', charges_enabled: true, payouts_enabled: true, details_submitted: true, country: 'FR' });
  const res = await postWebhook(payload, stripeSig(payload));
  assert.equal(res.status, 200, `expected 200: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.eligibility, 'ineligible_country');
  const status = psql(`select payout_status from public.publishers where id='${pubId}';`);
  assert.equal(status, 'ineligible_country');
});
