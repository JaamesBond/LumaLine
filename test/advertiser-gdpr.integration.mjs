// test/advertiser-gdpr.integration.mjs — M9-T5: advertiser GDPR erasure + export (self + admin).
//
// public.advertiser_gdpr_self_delete() / advertiser_gdpr_delete(uuid) (20260716200000) mirror
// gdpr_self_delete: a shared SECDEF body (app.advertiser_gdpr_erase) refuses while money is in flight,
// anonymizes name+stripe_customer_id + tombstones member auth emails, pauses the org's campaigns/
// line_items, and PRESERVES the balance ledger + action log. Self-delete takes no argument (derives the
// target from app.current_advertiser_id()), so it cannot target another org. advertiser_data_export()
// returns the caller's own campaigns/creatives/deposits. Self-skips without stack/psql/the migration.
//
// WHAT IS TESTED:
//   G1 — self-delete anonymizes the caller's OWN advertiser (name scrubbed, stripe_customer_id nulled,
//        deleted_at set), tombstones the member auth email, pauses the org, PRESERVES the balance ledger
//   G2 — a nonzero balance no longer blocks self-delete; a pending topup still does
//   G3 — idempotent (second call → already_deleted)
//   G4 — a bystander advertiser B is completely untouched (no cross-org erasure)
//   G5 — a session mapped to NO advertiser is rejected (unauthenticated)
//   G6 — admin advertiser_gdpr_delete(uuid) works; a non-admin session is refused
//   G7 — advertiser_data_export returns the caller's own campaigns/creatives/deposits; unmapped rejected
//   G8 — the house advertiser is refused (house_advertiser)
//   G9 — an advertiser holding unspent credit CAN be erased (Phase 2 deadlock regression)
//   G10 — in-flight transactions (a pending charge) still block erasure (guard not over-removed)
//   G11 — an advertiser writes off its OWN residual credit; ledger stays zero-sum
//   G12 — reserved credit cannot be written off (BACKED-reserve invariant)
//   G13 — writeoff is self-scoped: it cannot touch another org
//   G14 — deletion_disposition records why a balance was left behind; rejects spend_down
//   G15 — erasure is TERMINAL: an erased advertiser cannot resume serving — the self-serve status
//         RPCs refuse, and window_open refuses even when the rows are forced back to active
//   G16 — admin_ledger_health()'s cleared-accrual identity survives an opt-in credit write-off
//   G17 — the six self-serve CREATION/EDIT RPCs each succeed while live and refuse after erasure
//   G18 — the DEPOSIT path (advertiser_deposit_self_id) resolves while live and refuses after erasure
//   G19 — advertiser_data_export STILL WORKS after erasure (the Art. 15/20 over-gating guard)
//   G20 — advertiser_writeoff_credit STILL WORKS after erasure (opt-in abandonment stays reachable)
//   G21 — spend_down joins the disposition set; the pending watermark exists on BOTH roles
//   G22 — spend_down defers erasure and deliberately KEEPS campaigns serving
//   G23 — dormant with money in flight enters pending AND freezes serving
//   G24 — the cron completes a pending deletion once the blocker clears; idempotent
//   G25 — the cron holds a spend_down pending until the balance actually reaches zero
//   G26 — a pending row past 25 days raises the Art. 12(3) alert, and clears it on completion
//   G27 — cancel clears the watermark, unpauses, is self-scoped, and is refused after erasure

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL    = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

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

async function rpc(fnName, body, jwt) {
  const headers = { apikey: ANON, 'content-type': 'application/json', accept: 'application/json' };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }
// Presence of the FEATURE, not of one signature: Phase 3 (20260727100000) drops the no-argument
// advertiser_gdpr_self_delete() in favour of advertiser_gdpr_self_delete(p_disposition text
// default 'dormant'). Pinning this probe to one arity would silently SKIP the whole suite the
// moment the signature moved — the worst possible failure mode for a money/GDPR suite.
function migrationPresent() {
  try {
    return psql(`select (to_regprocedure('public.advertiser_gdpr_self_delete()') is not null
                      or to_regprocedure('public.advertiser_gdpr_self_delete(text)') is not null);`) === 't';
  } catch { return false; }
}

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const PRESENT  = PSQL_OK ? migrationPresent() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !PRESENT ? '20260716200000 not applied — SKIPPING'
  : false;
if (SKIP) console.log(`[advertiser-gdpr.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
const ADMIN = { authId: randomUUID() };
const ADMIN_JWT = mintJwt(ADMIN.authId);
const ORPHAN_JWT = mintJwt(randomUUID());   // a valid session mapped to no advertiser

const advIds = [];
const pubIds = [];
const authIds = [ADMIN.authId];

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')
    on conflict (id) do nothing;`);
}

// A prepay advertiser + a mapped owner session + a campaign(active)/line_item(active)/creative + a
// deposit sub-ledger row (must be preserved) + a zero balance row. Returns ids + the owner JWT.
function seedAdvertiser({ isHouse = false, balance = 0, reserved = 0, stripeCust = 'cus_seed' } = {}) {
  const advId = randomUUID(), campId = randomUUID(), liId = randomUUID(), crId = randomUUID();
  const ownerAuth = randomUUID();
  const email = `gdpr-owner-${ownerAuth}@example.com`;
  seedUser(ownerAuth, email);
  psql(`insert into public.advertisers (id, name, status, billing_mode, is_house, stripe_customer_id)
        values ('${advId}', 'Acme ${advId.slice(0, 8)}', 'active', 'prepay', ${isHouse}, '${stripeCust}');`);
  psql(`insert into public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
        values ('${advId}', ${balance}, ${reserved});`);
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role) values ('${ownerAuth}','${advId}','owner');`);
  psql(`insert into public.campaigns (id, advertiser_id, name, status) values ('${campId}','${advId}','camp','active');`);
  // House advertisers require zero bids (line_items_house_bids_zero, sentinel_never_bills); a non-house
  // advertiser bids normally. Both keep cpc=0 (CPVA-only).
  psql(`insert into public.line_items (id, campaign_id, cpva_bid_micros, cpc_bid_micros, status)
        values ('${liId}','${campId}',${isHouse ? 0 : 5000},0,'active');`);
  psql(`insert into public.creatives (id, line_item_id, line, dest_url, label, status)
        values ('${crId}','${liId}','Signed honest ads','https://example.test/x','sponsored','active');`);
  // A deposit sub-ledger row (financial record to be PRESERVED across erasure).
  psql(`insert into public.advertiser_balance_ledger (advertiser_id, kind, amount_micros, stripe_payment_intent_id)
        values ('${advId}','deposit',100000000,'pi_${advId.slice(0,8)}');`);
  advIds.push(advId);
  authIds.push(ownerAuth);
  return { advId, campId, liId, crId, ownerAuth, email, jwt: mintJwt(ownerAuth) };
}

// ---------------------------------------------------------------------------
// G15 serving helpers. window_open needs a DEVICE session (publisher_id + device_id claims), not
// the advertiser session the rest of this file uses. Mirrors advertiser-serving.integration.mjs.
// ---------------------------------------------------------------------------
function mintDeviceJwt({ sub, publisher_id, device_id }) {
  return mintJwt(sub, { publisher_id, device_id });
}

// A publisher + device + backing auth user, returning a device JWT. Deliberately a DIFFERENT auth
// user from any advertiser member, so window_open's self-deal exclusion never applies.
function seedPublisher() {
  const authId = randomUUID(), pubId = randomUUID(), deviceId = randomUUID();
  seedUser(authId, `gdpr-pub-${pubId.slice(0, 8)}@example.com`);
  psql(`insert into public.publishers (id, auth_user_id, handle, status) values ('${pubId}','${authId}','gdpr-${pubId.slice(0,8)}','active');`);
  psql(`insert into public.devices (id, publisher_id) values ('${deviceId}','${pubId}');`);
  pubIds.push(pubId);
  authIds.push(authId);
  return { authId, pubId, deviceId, jwt: mintDeviceJwt({ sub: authId, publisher_id: pubId, device_id: deviceId }) };
}

// Make a seeded line dominate the weighted rotation and carry a line text unique to this test.
function makeDominant(liId, crId) {
  const line = `gdpr-serve-${crId.slice(0, 12)}`;
  psql(`update public.line_items set weight = 1000000, targeting = '{}',
          start_at = now() - interval '1 hour', end_at = now() + interval '30 days' where id = '${liId}';`);
  psql(`update public.creatives set line = '${line}' where id = '${crId}';`);
  return line;
}

// Collect the lines window_open serves over n opens, spreading them across fresh devices so the
// in-DB velocity caps (6 concurrent open windows / device) are never the reason we stop seeing a
// line. Returns [] entries for a house/no-fill tick.
async function servedLines(n) {
  const out = [];
  for (let i = 0; i < n; i += 5) {
    const pub = seedPublisher();
    for (let k = 0; k < Math.min(5, n - i); k++) {
      const w = await rpc('window_open', { p_activity_snapshot: 'session' }, pub.jwt);
      if (!w.ok) throw new Error(`window_open failed: ${w.status} ${JSON.stringify(w.data)}`);
      out.push(w.data?.ad?.line ?? null);
    }
  }
  return out;
}

// Pull an advertiser's creatives/line_items out of the global rotation ASAP — a weight-1e6 line
// would otherwise starve every other suite running in parallel against this same database.
function stopServing(advId) {
  try {
    psql(`set session_replication_role = replica;
      delete from public.creatives where line_item_id in (select id from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id='${advId}'));
      delete from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id='${advId}');
      reset session_replication_role;`);
  } catch { /* best-effort */ }
}

function teardown() {
  try {
    const parts = [`set session_replication_role = replica;`];
    const pubs = pubIds.map((x) => `'${x}'`).join(',');
    if (pubs) {
      parts.push(`delete from public.impressions where publisher_id in (${pubs});`);
      parts.push(`delete from public.ad_windows where publisher_id in (${pubs});`);
      parts.push(`delete from public.serve_counters where publisher_id in (${pubs});`);
      parts.push(`delete from public.ledger_entries where publisher_id in (${pubs});`);
      parts.push(`delete from public.devices where publisher_id in (${pubs});`);
      parts.push(`delete from public.publishers where id in (${pubs});`);
    }
    const advs = advIds.map((x) => `'${x}'`).join(',');
    if (advs) {
      parts.push(`delete from public.line_item_daily_stats where line_item_id in (select li.id from public.line_items li join public.campaigns c on c.id=li.campaign_id where c.advertiser_id in (${advs}));`);
      parts.push(`delete from public.advertiser_balance_ledger where advertiser_id in (${advs});`);
      parts.push(`delete from public.ledger_entries where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_action_log where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_topup_intents where advertiser_id in (${advs});`);
      parts.push(`delete from public.creatives where line_item_id in (select li.id from public.line_items li join public.campaigns c on c.id=li.campaign_id where c.advertiser_id in (${advs}));`);
      parts.push(`delete from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id in (${advs}));`);
      parts.push(`delete from public.campaigns where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_balances where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_users where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertisers where id in (${advs});`);
    }
    if (advs) {
      parts.push(`delete from app.alert_events where check_name='gdpr_pending_overdue'
                    and dedup_key in (${advIds.map((x) => `'advertiser:${x}'`).join(',')});`);
    }
    parts.push(`delete from app.admins where auth_user_id='${ADMIN.authId}';`);
    parts.push(`delete from auth.users where id in (${authIds.map((a) => `'${a}'`).join(',')});`);
    parts.push(`reset session_replication_role;`);
    psql(parts.join('\n'));
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedUser(ADMIN.authId, `gdpr-admin-${ADMIN.authId}@example.com`);
  psql(`insert into app.admins (auth_user_id) values ('${ADMIN.authId}') on conflict do nothing;`);
  process.on('exit', teardown);
}

// ---------------------------------------------------------------------------
test('G1: self-delete anonymizes own org, tombstones email, pauses serving, preserves ledger', { skip: SKIP }, async () => {
  const A = seedAdvertiser();
  const res = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.ok(res.ok, `self-delete failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true);
  assert.equal(res.data.advertiser_id, A.advId, 'resolves the caller\'s OWN org');

  const row = psql(`select name||'|'||coalesce(stripe_customer_id,'NULL')||'|'||(deleted_at is not null) from public.advertisers where id='${A.advId}';`);
  const [name, stripe, deleted] = row.split('|');
  assert.notEqual(name, `Acme ${A.advId.slice(0, 8)}`, 'name scrubbed');
  assert.equal(stripe, 'NULL', 'stripe_customer_id nulled (protected-column erasure via the service_role claim swap)');
  assert.equal(deleted, 'true', 'deleted_at set');

  const email = psql(`select email from auth.users where id='${A.ownerAuth}';`);
  assert.notEqual(email, A.email, 'auth email tombstoned');
  assert.ok(/deleted/i.test(email), `tombstone email, got ${email}`);

  assert.equal(psql(`select status from public.line_items where id='${A.liId}';`), 'paused', 'line_item paused (serving stops)');
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}';`), 'paused', 'campaign paused');

  // Balance ledger PRESERVED (a financial record).
  assert.equal(psql(`select count(*) from public.advertiser_balance_ledger where advertiser_id='${A.advId}';`), '1', 'deposit ledger row preserved');
  assert.ok(Number(psql(`select count(*) from public.advertiser_action_log where advertiser_id='${A.advId}' and action='gdpr_erase';`)) >= 1, 'erasure audited');
});

test('G2: a nonzero balance no longer blocks self-delete, but a pending topup still does', { skip: SKIP }, async () => {
  // Phase 2 (20260726100000) removed the idle-balance gate — see G9 for the direct-function
  // regression test. This test covers the same change through the self-delete RPC wrapper, and
  // confirms the in-flight-transaction guard (topup_pending) is untouched.
  const A = seedAdvertiser({ balance: 5000000 });
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros, status)
        values ('sess_${A.advId.slice(0,8)}','${A.advId}',10000000,'pending');`);
  let res = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(res.data.reason, 'topup_pending', 'refused while a deposit is in flight (balance notwithstanding)');
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}';`), 't', 'NOT anonymized');

  // Resolve the topup → erasure now succeeds, despite the balance still being nonzero.
  psql(`update public.advertiser_topup_intents set status='credited' where advertiser_id='${A.advId}';`);
  res = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(res.data.ok, true, 'erasure succeeds once money settled');
  assert.equal(psql(`select balance_micros from public.advertiser_balances where advertiser_id='${A.advId}';`),
    '5000000', 'balance is untouched by erasure — still nonzero, as claimed');
});

test('G3: idempotent — a second self-delete returns already_deleted', { skip: SKIP }, async () => {
  const A = seedAdvertiser();
  const first = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(first.data.ok, true);
  const second = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(second.data.ok, false, 'second call is a no-op');
  assert.equal(second.data.reason, 'already_deleted');
});

test('G4: a bystander advertiser B is completely untouched', { skip: SKIP }, async () => {
  const A = seedAdvertiser();
  const B = seedAdvertiser();
  await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  const row = psql(`select name||'|'||coalesce(stripe_customer_id,'NULL')||'|'||(deleted_at is null) from public.advertisers where id='${B.advId}';`);
  const [name, stripe, notDeleted] = row.split('|');
  assert.equal(name, `Acme ${B.advId.slice(0, 8)}`, 'B name intact');
  assert.notEqual(stripe, 'NULL', 'B stripe_customer_id intact');
  assert.equal(notDeleted, 'true', 'B not deleted');
});

test('G5: a session mapped to no advertiser is rejected', { skip: SKIP }, async () => {
  const res = await rpc('advertiser_gdpr_self_delete', {}, ORPHAN_JWT);
  assert.ok(!res.ok && res.status >= 400, `unmapped session must be rejected, got ${res.status}`);
});

test('G6: admin advertiser_gdpr_delete(uuid) works; a non-admin is refused', { skip: SKIP }, async () => {
  const A = seedAdvertiser();
  // A non-admin advertiser session cannot call the admin path.
  const denied = await rpc('advertiser_gdpr_delete', { p_advertiser_id: A.advId }, A.jwt);
  assert.ok(!denied.ok && denied.status >= 400, 'non-admin refused on the admin path');
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}';`), 't', 'not erased by the denied call');

  const ok = await rpc('advertiser_gdpr_delete', { p_advertiser_id: A.advId }, ADMIN_JWT);
  assert.ok(ok.ok && ok.data.ok === true, `admin erase failed: ${JSON.stringify(ok.data)}`);
  assert.equal(psql(`select (deleted_at is not null) from public.advertisers where id='${A.advId}';`), 't', 'admin erased the org');
});

test('G7: advertiser_data_export returns own campaigns/creatives/deposits; unmapped rejected', { skip: SKIP }, async () => {
  const A = seedAdvertiser();
  const res = await rpc('advertiser_data_export', {}, A.jwt);
  assert.ok(res.ok, `export failed: ${JSON.stringify(res.data)}`);
  assert.equal(res.data.advertiser.id, A.advId, 'own advertiser');
  assert.ok(Array.isArray(res.data.campaigns) && res.data.campaigns.length >= 1, 'own campaigns present');
  assert.ok(res.data.creatives.length >= 1, 'own creatives present');
  assert.ok(res.data.deposits.length >= 1, 'own deposits present');
  assert.ok(res.data.spend && res.data.spend.totals, 'spend summary embedded');

  const orphan = await rpc('advertiser_data_export', {}, ORPHAN_JWT);
  assert.ok(!orphan.ok && orphan.status >= 400, 'unmapped session cannot export');
});

test('G8: the house advertiser is refused (house_advertiser)', { skip: SKIP }, async () => {
  const H = seedAdvertiser({ isHouse: true });
  const res = await rpc('advertiser_gdpr_delete', { p_advertiser_id: H.advId }, ADMIN_JWT);
  assert.equal(res.data.ok, false, 'house advertiser cannot be erased');
  assert.equal(res.data.reason, 'house_advertiser');
});

test('G9 — an advertiser holding unspent credit CAN be erased (deadlock regression)', { skip: SKIP }, () => {
  // Regression for the Art. 17 deadlock: deposits are non-refundable and there is no withdrawal
  // RPC, so gating erasure on balance_micros > 0 made erasure permanently unreachable for anyone
  // holding credit. Personal-data erasure must never depend on an org's money settling.
  const A = seedAdvertiser({ balance: 40000000 });

  const out = JSON.parse(psql(`select app.advertiser_gdpr_erase('${A.advId}')::text`));
  assert.equal(out.ok, true, `erase refused: ${JSON.stringify(out)}`);

  // Personal data gone...
  assert.match(psql(`select name from public.advertisers where id = '${A.advId}'`), /^deleted-/);
  assert.ok(psql(`select deleted_at from public.advertisers where id = '${A.advId}'`).length > 0);

  // ...and the money is untouched, left as an unrecognized liability. NOT silently taken.
  assert.equal(psql(
    `select balance_micros from public.advertiser_balances where advertiser_id = '${A.advId}'`), '40000000');
});

test('G10 — in-flight TRANSACTIONS still block erasure (guard not over-removed)', { skip: SKIP }, () => {
  // Only the idle-balance gate was removed. A pending charge is an in-flight transaction that
  // resolves on its own in days, and must still defer erasure.
  const A = seedAdvertiser({ balance: 0 });
  psql(`insert into public.advertiser_charges (entry_group_id, advertiser_id, amount_micros, amount_cents, status)
        values (gen_random_uuid(), '${A.advId}', 1000000, 100, 'pending')`);

  const out = JSON.parse(psql(`select app.advertiser_gdpr_erase('${A.advId}')::text`));
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'charge_pending');
});

test('G11 — an advertiser writes off its OWN residual credit, ledger stays zero-sum', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 40000000 });
  const before = psql(`select coalesce(sum(amount_micros), 0) from public.ledger_entries`);

  const res = await rpc('advertiser_writeoff_credit', {}, A.jwt);
  assert.equal(res.data.ok, true, JSON.stringify(res.data));
  assert.equal(String(res.data.written_off_micros), '40000000');
  assert.equal(psql(
    `select balance_micros from public.advertiser_balances where advertiser_id = '${A.advId}'`), '0');

  // Zero-sum preserved: the write-off books two legs that cancel.
  assert.equal(psql(`select coalesce(sum(amount_micros), 0) from public.ledger_entries`), before);
  assert.equal(psql(
    `select count(*) from public.ledger_entries where entry_group_id = '${res.data.entry_group_id}'`), '2');

  // No cash moves on a write-off: the account, not just the count, matters. The forfeited credit
  // stays in the platform's Stripe balance and is recognized as revenue, not booked as cash leaving.
  assert.equal(psql(
    `select account from public.ledger_entries
      where entry_group_id = '${res.data.entry_group_id}' and amount_micros = -40000000`), 'platform_revenue');
  assert.equal(psql(
    `select account from public.ledger_entries
      where entry_group_id = '${res.data.entry_group_id}' and amount_micros = 40000000`), 'advertiser_funds');
  assert.equal(psql(
    `select count(*) from public.ledger_entries
      where entry_group_id = '${res.data.entry_group_id}' and account = 'platform_cash'`), '0');
});

test('G12 — reserved credit cannot be written off', { skip: SKIP }, async () => {
  // reserved_micros is money already committed to serve windows. Writing it off would break the
  // BACKED-reserve invariant (advertiser_balances.reserved_micros == SUM(ad_windows.reserve_micros)).
  const A = seedAdvertiser({ balance: 40000000, reserved: 15000000 });

  const res = await rpc('advertiser_writeoff_credit', {}, A.jwt);
  assert.equal(res.data.ok, false);
  assert.equal(res.data.reason, 'reserved_outstanding');
  assert.equal(psql(
    `select balance_micros from public.advertiser_balances where advertiser_id = '${A.advId}'`), '40000000');
});

test('G13 — writeoff is self-scoped: it cannot touch another org', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 5000000 });
  const B = seedAdvertiser({ balance: 9000000 });

  await rpc('advertiser_writeoff_credit', {}, A.jwt);
  assert.equal(psql(
    `select balance_micros from public.advertiser_balances where advertiser_id = '${B.advId}'`), '9000000');
  assert.equal(psql(
    `select balance_micros from public.advertiser_balances where advertiser_id = '${A.advId}'`), '0');
});

test('G14 — disposition records why a balance was left behind', { skip: SKIP }, () => {
  const A = seedAdvertiser({ balance: 40000000 });

  psql(`update public.advertisers set deletion_disposition = 'dormant' where id = '${A.advId}'`);
  assert.equal(psql(
    `select deletion_disposition from public.advertisers where id = '${A.advId}'`), 'dormant');

  // Phase 3 (20260727100000) admits spend_down now that app.gdpr_complete_pending() honors it —
  // see G21 for the full accepted set. Junk is still rejected: psql() uses execFileSync, which
  // throws on a nonzero exit, so a CHECK violation surfaces as a throw.
  assert.throws(() => psql(
    `update public.advertisers set deletion_disposition = 'junk' where id = '${A.advId}'`));
});

test('G15 — erasure is TERMINAL: an erased advertiser can neither be re-activated nor served', { skip: SKIP }, async () => {
  // app.advertiser_gdpr_erase pauses campaigns/line_items but deliberately leaves
  // advertisers.status = 'active' (a protected column) and KEEPS the advertiser_users mappings, so
  // app.current_advertiser_id() still resolves for an erased org. Without a deleted_at check a
  // still-mapped member could flip everything back to active and spend the residual credit.
  // 20260726110000 closes it at BOTH layers; this test proves both, and proves the preconditions
  // are live rather than asserting on an inert fixture.
  const A = seedAdvertiser({ balance: 100000000 });
  const lineA = makeDominant(A.liId, A.crId);
  let B = null;
  try {
    // --- PRECONDITION 1: this advertiser really does serve today. ---
    const before = await servedLines(10);
    assert.ok(before.includes(lineA),
      `precondition failed: the fixture never served before erasure (saw ${JSON.stringify(before)})`);

    // --- PRECONDITION 2: the self-serve status RPCs really are reachable for this caller. ---
    let r = await rpc('advertiser_set_line_item_status', { p_id: A.liId, p_target: 'paused' }, A.jwt);
    assert.ok(r.ok, `precondition failed: pause refused pre-erasure: ${JSON.stringify(r.data)}`);
    r = await rpc('advertiser_set_line_item_status', { p_id: A.liId, p_target: 'active' }, A.jwt);
    assert.ok(r.ok, `precondition failed: resume refused pre-erasure: ${JSON.stringify(r.data)}`);

    // --- ERASE ---
    const erased = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
    assert.equal(erased.data.ok, true, `erase failed: ${JSON.stringify(erased.data)}`);
    assert.equal(psql(`select status from public.line_items where id='${A.liId}';`), 'paused');
    assert.equal(psql(`select status from public.campaigns where id='${A.campId}';`), 'paused');

    // (a) the self-serve RPCs refuse re-activation. Both raise (errcode 55000), the refusal shape
    // these functions already use for the A9 dispute hold, carrying account_deleted.
    for (const [fn, id] of [['advertiser_set_line_item_status', A.liId], ['advertiser_set_campaign_status', A.campId]]) {
      const res = await rpc(fn, { p_id: id, p_target: 'active' }, A.jwt);
      assert.ok(!res.ok && res.status >= 400, `${fn} must refuse an erased advertiser, got ${res.status}`);
      assert.match(JSON.stringify(res.data ?? {}), /account_deleted/, `${fn} must refuse with account_deleted`);
    }
    assert.equal(psql(`select status from public.line_items where id='${A.liId}';`), 'paused', 'still paused after the refused resume');
    assert.equal(psql(`select status from public.campaigns where id='${A.campId}';`), 'paused');

    // (b) the STRUCTURAL half: force the rows back to active behind the RPCs' back (exactly what a
    // compromised/creative path would do) and prove window_open still refuses. deleted_at must be
    // the ONLY thing excluding it — the advertiser row itself is still status='active'.
    psql(`update public.line_items set status='active' where id='${A.liId}';
          update public.campaigns  set status='active' where id='${A.campId}';`);
    assert.equal(psql(`select status||'|'||(deleted_at is not null) from public.advertisers where id='${A.advId}';`),
      'active|true', 'advertisers.status stays active after erasure — deleted_at is the only serve-gate');

    // Control: a NON-erased twin proves the serving machinery is alive during the same opens, so
    // "A never served" cannot be an artifact of an empty pool or a dead publisher fixture.
    B = seedAdvertiser({ balance: 100000000 });
    const lineB = makeDominant(B.liId, B.crId);

    // Windows already opened against A during the pre-erasure precondition are expected; what must
    // not move is the count AFTER erasure.
    const winsAgainstA = () => psql(`select count(*) from public.ad_windows w join public.line_items li on li.id=w.line_item_id
                                      where li.campaign_id='${A.campId}';`);
    const winsBefore = winsAgainstA();
    assert.ok(Number(winsBefore) > 0, 'precondition: A really did open windows while it was alive');

    const after = await servedLines(20);
    assert.ok(after.includes(lineB), `control failed: the non-erased twin never served (saw ${JSON.stringify(after)})`);
    assert.ok(!after.includes(lineA), 'an ERASED advertiser must never serve, even with campaign + line_item forced active');
    assert.equal(winsAgainstA(), winsBefore, 'not one further window was opened against the erased org');
  } finally {
    stopServing(A.advId);
    if (B) stopServing(B.advId);
  }
});

test('G16 — the cleared-accrual identity survives an opt-in credit write-off', { skip: SKIP }, async () => {
  // admin_ledger_health() checks advertiser_billing = publisher_earnings + platform_revenue over
  // CLEARED ACCRUALS. advertiser_writeoff_credit() books a cleared platform_revenue leg with
  // event_type='advertiser_adjustment'; the other two legs of the identity were already filtered
  // to the accrual event types, so an unfiltered third leg makes accrual_identity_ok permanently
  // false — ledger corruption, as far as the owner dashboard can tell. 20260726110000 filters it.
  const WRITEOFF = 7000000000;      // €7000 — orders of magnitude above any concurrent fixture,
                                    // so the delta assertion below cannot be masked by other suites
  const P = seedPublisher();
  const W = seedAdvertiser({ balance: WRITEOFF });

  // A REAL cleared accrual, so the identity is asserted over a NON-EMPTY fixture (a green
  // accrual_identity_ok on an empty ledger would prove nothing). One statement = one txn, so the
  // deferred zero-sum trigger sees the balanced group.
  const grp = randomUUID(), imp = randomUUID();
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id, advertiser_id) values
      ('${grp}','cpva_accrual','advertiser_billing', 1000000,'cleared','impression','${imp}', null,          '${W.advId}'),
      ('${grp}','cpva_accrual','publisher_earnings', -600000,'cleared','impression','${imp}','${P.pubId}',   '${W.advId}'),
      ('${grp}','cpva_accrual','platform_revenue',   -400000,'cleared','impression','${imp}', null,          '${W.advId}');`);

  const before = await rpc('admin_ledger_health', {}, ADMIN_JWT);
  assert.ok(before.ok, `health read failed: ${before.status} ${JSON.stringify(before.data)}`);
  assert.ok(Number(before.data.cleared_advertiser_billing_micros) >= 1000000,
    'precondition: the accrual identity must be over a non-empty cleared fixture');
  assert.equal(before.data.accrual_identity_ok, true, 'precondition: the identity holds before the write-off');
  const platBefore = Number(before.data.cleared_platform_revenue_micros);

  const wo = await rpc('advertiser_writeoff_credit', {}, W.jwt);
  assert.equal(wo.data.ok, true, `write-off failed: ${JSON.stringify(wo.data)}`);
  assert.equal(String(wo.data.written_off_micros), String(WRITEOFF));

  // Precondition for the FIX itself: the write-off really does book a CLEARED platform_revenue
  // leg. Without this the assertions below would pass on a no-op write-off.
  assert.equal(psql(`select count(*) from public.ledger_entries
      where entry_group_id='${wo.data.entry_group_id}' and account='platform_revenue' and state='cleared';`), '1',
    'precondition: the write-off books a cleared platform_revenue leg (the contaminating event)');

  const after = await rpc('admin_ledger_health', {}, ADMIN_JWT);
  assert.equal(after.data.accrual_identity_ok, true,
    'the cleared-accrual identity must survive a write-off (unfiltered platform_revenue breaks it)');
  assert.equal(after.data.zero_sum_ok, true, 'zero-sum is unaffected either way');
  assert.ok(Number(after.data.cleared_platform_revenue_micros) - platBefore < WRITEOFF,
    'the write-off must NOT be counted into cleared accrual platform_revenue');
});

// ---------------------------------------------------------------------------
// G17-G20 — the ERASED-ADVERTISER SURFACE AUDIT (20260726120000).
//
// app.advertiser_gdpr_erase KEEPS the advertiser_users mappings (that is what makes a repeat erasure
// idempotent and keeps advertiser_data_export reachable), so a member of an erased org still
// resolves app.current_advertiser_id() and every self-serve RPC stays CALLABLE. 20260726110000
// closed only the spending path (window_open + resume). These four prove the rest of the surface is
// now classified correctly: creation/edit/deposit REFUSE, and the two GDPR rights STAY OPEN.
//
// Every one of them asserts the LIVE precondition first — a refusal on a fixture that never worked
// is indistinguishable from a no-op, and this repo has been bitten by that before.
// ---------------------------------------------------------------------------

// Drive one self-serve RPC and report ok/refusal in a single shape, so the before/after pairing
// below compares like with like.
async function callRpc(fn, args, jwt) {
  const res = await rpc(fn, args, jwt);
  return { ok: res.ok, status: res.status, blob: JSON.stringify(res.data ?? {}) };
}

test('G17 — the six self-serve creation/edit RPCs refuse an ERASED advertiser (and work while live)', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 50000000 });
  const FLOOR = Number(psql('select app.advertiser_min_bid_micros();'));
  assert.ok(FLOOR > 0, 'precondition: a real bid floor is configured');

  // --- PRECONDITION: all six really are reachable and SUCCEED for a LIVE advertiser. ---
  // Each call also builds the fixture the next one edits, so the post-erasure half operates on rows
  // that genuinely exist and are genuinely in an editable state — the guard must be the ONLY reason
  // the second half fails.
  const mkCampaign = await callRpc('advertiser_create_campaign', { p_name: 'G17 live campaign' }, A.jwt);
  assert.ok(mkCampaign.ok, `precondition: create_campaign refused while live: ${mkCampaign.blob}`);
  const campId = JSON.parse(mkCampaign.blob).campaign_id;

  const mkLine = await callRpc('advertiser_create_line_item',
    { p_campaign_id: campId, p_cpva_bid_micros: FLOOR * 2 }, A.jwt);
  assert.ok(mkLine.ok, `precondition: create_line_item refused while live: ${mkLine.blob}`);
  const liId = JSON.parse(mkLine.blob).line_item_id;

  const edLine = await callRpc('advertiser_edit_line_item',
    { p_id: liId, p_cpva_bid_micros: FLOOR * 3 }, A.jwt);
  assert.ok(edLine.ok, `precondition: edit_line_item refused while live: ${edLine.blob}`);

  const mkCreative = await callRpc('advertiser_submit_creative',
    { p_line_item_id: liId, p_line: 'G17 honest signed line', p_dest_url: 'https://example.test/g17', p_label: 'sponsored' }, A.jwt);
  assert.ok(mkCreative.ok, `precondition: submit_creative refused while live: ${mkCreative.blob}`);
  const crId = JSON.parse(mkCreative.blob).creative_id;

  const edCreative = await callRpc('advertiser_edit_creative',
    { p_id: crId, p_line: 'G17 edited line', p_dest_url: 'https://example.test/g17b', p_label: 'sponsored' }, A.jwt);
  assert.ok(edCreative.ok, `precondition: edit_creative refused while live: ${edCreative.blob}`);

  const upProfile = await callRpc('advertiser_update_profile', { p_name: 'G17 Live Name' }, A.jwt);
  assert.ok(upProfile.ok, `precondition: update_profile refused while live: ${upProfile.blob}`);
  assert.equal(psql(`select name from public.advertisers where id='${A.advId}';`), 'G17 Live Name',
    'precondition: the profile rename really landed while live');

  // --- ERASE ---
  const erased = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(erased.data.ok, true, `erase failed: ${JSON.stringify(erased.data)}`);

  // The mapping really IS kept — otherwise these RPCs would refuse with 'unauthenticated' (28000)
  // and this whole test would be asserting the wrong refusal.
  assert.equal(psql(`select count(*) from public.advertiser_users where advertiser_id='${A.advId}';`), '1',
    'precondition: erasure keeps the member mapping, so current_advertiser_id() still resolves');
  assert.equal(psql(`select (deleted_at is not null) from public.advertisers where id='${A.advId}';`), 't');

  // The edit targets must still be in an EDITABLE state after erasure, so a refusal cannot be the
  // pre-existing state check firing instead of the new guard. (erase pauses only 'active' rows.)
  assert.equal(psql(`select status from public.line_items where id='${liId}';`), 'draft');
  assert.equal(psql(`select status from public.creatives where id='${crId}';`), 'pending_review');

  // --- AFTER: every one of the six refuses, with account_deleted. ---
  const after = [
    ['advertiser_create_campaign',  { p_name: 'G17 post-erasure campaign' }],
    ['advertiser_create_line_item', { p_campaign_id: campId, p_cpva_bid_micros: FLOOR * 2 }],
    ['advertiser_edit_line_item',   { p_id: liId, p_cpva_bid_micros: FLOOR * 4 }],
    ['advertiser_submit_creative',  { p_line_item_id: liId, p_line: 'G17 post line', p_dest_url: 'https://example.test/g17c', p_label: 'sponsored' }],
    ['advertiser_edit_creative',    { p_id: crId, p_line: 'G17 post edit', p_dest_url: 'https://example.test/g17d', p_label: 'sponsored' }],
    ['advertiser_update_profile',   { p_name: 'G17 Resurrected Name' }],
  ];
  for (const [fn, args] of after) {
    const res = await callRpc(fn, args, A.jwt);
    assert.ok(!res.ok && res.status >= 400, `${fn} must refuse an erased advertiser, got ${res.status} ${res.blob}`);
    assert.match(res.blob, /account_deleted/, `${fn} must refuse with account_deleted, got ${res.blob}`);
  }

  // Refusals must be REAL — nothing was written behind them.
  assert.equal(psql(`select count(*) from public.campaigns where advertiser_id='${A.advId}' and name='G17 post-erasure campaign';`), '0',
    'no campaign was created for an erased org');
  assert.equal(psql(`select count(*) from public.line_items where campaign_id='${campId}';`), '1',
    'no second line_item was created for an erased org');
  assert.equal(psql(`select cpva_bid_micros from public.line_items where id='${liId}';`), String(FLOOR * 3),
    'the refused edit did not change the bid');
  assert.equal(psql(`select line from public.creatives where id='${crId}';`), 'G17 edited line',
    'the refused creative edit did not change the copy');
  assert.equal(psql(`select count(*) from public.creatives where line_item_id='${liId}';`), '1',
    'no second creative was submitted for an erased org');

  // The most important one: the erased org's name must still be the anonymized tombstone. A
  // successful update_profile would have UNDONE the erasure's in-place anonymization.
  assert.match(psql(`select name from public.advertisers where id='${A.advId}';`), /^deleted-/,
    'the refused rename must leave the anonymized name intact — erasure is not reversible by rename');
});

test('G18 — the DEPOSIT path refuses an ERASED advertiser (pre-money, at the DB resolver)', { skip: SKIP }, async () => {
  // advertiser-portal POST /funding/checkout resolves the depositing org via
  // public.advertiser_deposit_self_id BEFORE it creates a Stripe Checkout session. Gating there is
  // what makes the refusal pre-money: an erased org can never be charged for credit it could never
  // spend (window_open excludes deleted_at orgs). The edge function only surfaces this refusal, so
  // testing the RPC tests the gate itself — and does so without touching Stripe.
  const A = seedAdvertiser({ balance: 0 });

  // --- PRECONDITION: a LIVE advertiser resolves normally, so the refusal below is the erasure
  // guard and not a broken fixture. ---
  const live = await rpc('advertiser_deposit_self_id', {}, A.jwt);
  assert.ok(live.ok, `precondition: deposit resolver refused a LIVE advertiser: ${JSON.stringify(live.data)}`);
  assert.equal(live.data, A.advId, 'precondition: the resolver returns the caller\'s OWN advertiser id');

  // The ungated read-path twin must agree while live — the two differ ONLY after erasure.
  const selfLive = await rpc('advertiser_self_id', {}, A.jwt);
  assert.equal(selfLive.data, A.advId, 'precondition: advertiser_self_id agrees while live');

  // --- ERASE ---
  const erased = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(erased.data.ok, true, `erase failed: ${JSON.stringify(erased.data)}`);

  // --- AFTER: the deposit resolver refuses; no Checkout session can be opened. ---
  const dead = await rpc('advertiser_deposit_self_id', {}, A.jwt);
  assert.ok(!dead.ok && dead.status >= 400, `deposit resolver must refuse an erased org, got ${dead.status}`);
  assert.match(JSON.stringify(dead.data ?? {}), /account_deleted/, 'deposit refusal must carry account_deleted');

  // ...while the UNGATED identity primitive still resolves. This is the whole reason the deposit
  // path got its own resolver: advertiser_self_id backs the read-only surfaces, which stay open.
  const selfDead = await rpc('advertiser_self_id', {}, A.jwt);
  assert.ok(selfDead.ok, 'advertiser_self_id must stay ungated — the read-only surfaces depend on it');
  assert.equal(selfDead.data, A.advId, 'advertiser_self_id still resolves after erasure');

  // Structural backstop on the credit authority: an erased org has no way to get a topup_intent row,
  // because the only self-serve entry is the checkout endpoint we just closed. `authenticated` holds
  // SELECT-only on the table (no INSERT grant), so PostgREST cannot route around the edge function.
  const direct = await fetch(`${REST_BASE}/advertiser_topup_intents`, {
    method: 'POST',
    headers: { apikey: ANON, Authorization: `Bearer ${A.jwt}`, 'content-type': 'application/json' },
    body: JSON.stringify({ checkout_session_id: `cs_test_${randomUUID()}`, advertiser_id: A.advId, amount_micros: 5000000, status: 'pending' }),
  });
  assert.ok(!direct.ok, 'an authenticated caller must not be able to INSERT a topup_intent directly');
  assert.equal(psql(`select count(*) from public.advertiser_topup_intents where advertiser_id='${A.advId}';`), '0',
    'no credit-authority row exists for the erased org');
});

test('G19 — advertiser_data_export STILL WORKS after erasure (Art. 15/20 over-gating guard)', { skip: SKIP }, async () => {
  // This is the guard against fixing the gap too hard. GDPR Art. 15/20 is the data subject's right
  // of ACCESS and PORTABILITY; it does not lapse because they exercised Art. 17. An erasure that
  // destroyed the export would recreate exactly the class of defect Phase 2 exists to remove
  // (20260726100000: conditioning a data-protection right on something the user cannot reach), so
  // this failing matters as much as any refusal above.
  const A = seedAdvertiser({ balance: 20000000 });

  const before = await rpc('advertiser_data_export', {}, A.jwt);
  assert.ok(before.ok, `precondition: export failed while live: ${JSON.stringify(before.data)}`);
  assert.ok(before.data.campaigns.length >= 1 && before.data.creatives.length >= 1,
    'precondition: the export is over a NON-EMPTY fixture, so "still works" is not vacuous');
  const campsBefore = before.data.campaigns.length;
  const depositsBefore = before.data.deposits.length;

  const erased = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(erased.data.ok, true, `erase failed: ${JSON.stringify(erased.data)}`);

  const after = await rpc('advertiser_data_export', {}, A.jwt);
  assert.ok(after.ok, `advertiser_data_export MUST remain callable after erasure, got ${after.status} ${JSON.stringify(after.data)}`);
  assert.doesNotMatch(JSON.stringify(after.data ?? {}), /account_deleted/,
    'the export must not be gated behind an account_deleted refusal');

  // ...and it must still return the subject's actual records, not an empty husk. The preserved
  // financial history is the part a data subject most needs after erasure.
  assert.equal(after.data.advertiser.id, A.advId, 'the export still resolves the caller\'s own org');
  assert.equal(after.data.campaigns.length, campsBefore, 'campaigns still exported after erasure');
  assert.equal(after.data.deposits.length, depositsBefore, 'the preserved deposit ledger still exports');
  assert.ok(after.data.spend && after.data.spend.totals, 'the embedded spend summary still resolves');

  // The exported org name is the anonymized one — erasure still did its job; only ACCESS survived.
  assert.match(after.data.advertiser.name, /^deleted-/, 'the export reflects the anonymized name');
});

test('G20 — advertiser_writeoff_credit STILL WORKS after erasure (opt-in abandonment stays open)', { skip: SKIP }, async () => {
  // An erased org electing to abandon residual credit is legitimate — it is the documented opt-in
  // counterpart to the dormant-balance default, and erasure deliberately leaves the balance on the
  // books. Gating it would trap the residual credit forever with no way to resolve it.
  const A = seedAdvertiser({ balance: 30000000 });
  const zeroSumBefore = psql('select coalesce(sum(amount_micros), 0) from public.ledger_entries');

  const erased = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(erased.data.ok, true, `erase failed: ${JSON.stringify(erased.data)}`);
  assert.equal(psql(`select balance_micros from public.advertiser_balances where advertiser_id='${A.advId}';`),
    '30000000', 'precondition: erasure leaves the residual credit on the books');

  const wo = await rpc('advertiser_writeoff_credit', {}, A.jwt);
  assert.ok(wo.ok, `writeoff MUST remain callable after erasure, got ${wo.status} ${JSON.stringify(wo.data)}`);
  assert.equal(wo.data.ok, true, `writeoff refused an erased org: ${JSON.stringify(wo.data)}`);
  assert.equal(String(wo.data.written_off_micros), '30000000');
  assert.equal(psql(`select balance_micros from public.advertiser_balances where advertiser_id='${A.advId}';`), '0',
    'the residual credit really was zeroed');

  // Zero-sum must survive the post-erasure path exactly as it does the live one (G11).
  assert.equal(psql('select coalesce(sum(amount_micros), 0) from public.ledger_entries'), zeroSumBefore,
    'the post-erasure write-off keeps the ledger zero-sum');
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id='${wo.data.entry_group_id}' and account='platform_cash';`),
    '0', 'no cash leg on a write-off, erased or not');
});

// ---------------------------------------------------------------------------
// G21-G26 — GDPR PHASE 3: the PENDING-DELETION state machine (20260727100000).
//
// A request that cannot complete immediately used to dead-end at {ok:false, reason} while the Art.
// 12(3) one-month clock ran — the user had to come back and retry by hand. It now SCHEDULES itself:
// a deletion_requested_at watermark, a freeze so the account does nothing new while pending, an
// hourly cron that re-runs the SAME gate and completes the ones that now pass (delegating to the
// UNCHANGED erasure body), and a cancel available right up until erasure fires.
// ---------------------------------------------------------------------------

test('G21 — spend_down is now an accepted disposition; junk still is not', { skip: SKIP }, () => {
  const A = seedAdvertiser({ balance: 40000000 });

  for (const d of ['dormant', 'writeoff', 'spend_down']) {
    psql(`update public.advertisers set deletion_disposition = '${d}' where id = '${A.advId}'`);
    assert.equal(psql(
      `select deletion_disposition from public.advertisers where id = '${A.advId}'`), d);
  }
  assert.throws(() => psql(
    `update public.advertisers set deletion_disposition = 'junk' where id = '${A.advId}'`));

  // Both roles gain the pending watermark, nullable and null by default.
  assert.equal(psql(
    `select coalesce(deletion_requested_at::text, 'NULL') from public.advertisers where id = '${A.advId}'`), 'NULL');
  const P = seedPublisher();
  assert.equal(psql(
    `select coalesce(deletion_requested_at::text, 'NULL') from public.publishers where id = '${P.pubId}'`), 'NULL');

  // The watermark must NOT be a protected column — the erase/request paths run as `authenticated`
  // and app.advertisers_protect_cols would raise 42501 if it guarded this.
  psql(`update public.advertisers set deletion_requested_at = now() where id = '${A.advId}'`);
  assert.notEqual(psql(
    `select coalesce(deletion_requested_at::text, 'NULL') from public.advertisers where id = '${A.advId}'`), 'NULL');
  psql(`update public.advertisers set deletion_requested_at = null, deletion_disposition = null where id = '${A.advId}'`);

  // This fixture is funded AND never erased, so its line stays serve-eligible for the rest of the
  // run and competes for fills with the rotation-sensitive suites (serving.integration's clearing
  // price and frequency cap). Same reason G15 does this — see stopServing's comment.
  stopServing(A.advId);
});

test('G22 — spend_down defers erasure and deliberately KEEPS campaigns serving', { skip: SKIP }, async () => {
  // Phase 2 removed the idle-balance gate, so this advertiser would be erased IMMEDIATELY on a
  // plain request. spend_down is therefore not a blocked outcome the cron rescues — it is a
  // DELIBERATE election to defer, and the principal use of the pending state.
  const A = seedAdvertiser({ balance: 40000000 });
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}'`), 'active',
    'precondition: the campaign is live before the request');

  const res = await rpc('advertiser_gdpr_self_delete', { p_disposition: 'spend_down' }, A.jwt);
  assert.equal(res.data.ok, true, JSON.stringify(res.data));
  assert.equal(res.data.state, 'pending');
  assert.equal(res.data.reason, 'spend_down');
  assert.equal(psql(`select deletion_disposition from public.advertisers where id='${A.advId}'`), 'spend_down');

  // The ONE case where the freeze is skipped BY DESIGN — credit must stay spendable to spend down.
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}'`), 'active');
  assert.equal(psql(`select status from public.line_items where id='${A.liId}'`), 'active');
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}'`), 't');
  assert.ok(psql(`select deletion_requested_at from public.advertisers where id='${A.advId}'`).length > 0);

  // spend_down's whole point is that this org KEEPS serving — which means it stays in the global
  // rotation, funded, for the remainder of the run. Pull it once the assertions are made, or it
  // competes for fills with the rotation-sensitive suites. Same reason G15 does this.
  stopServing(A.advId);
});

test('G23 — dormant with money in flight enters pending AND freezes serving', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 0 });
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros, status)
        values ('sess_p3_${A.advId.slice(0,8)}','${A.advId}',10000000,'pending')`);
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}'`), 'active',
    'precondition: the campaign is live before the request');

  const res = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);   // the no-arg form must still work
  assert.equal(res.data.ok, true, JSON.stringify(res.data));
  assert.equal(res.data.state, 'pending');
  assert.equal(res.data.reason, 'topup_pending', 'the underlying money guard is unchanged');
  assert.equal(psql(`select deletion_disposition from public.advertisers where id='${A.advId}'`), 'dormant');

  assert.equal(psql(`select status from public.campaigns where id='${A.campId}'`), 'paused');
  assert.equal(psql(`select status from public.line_items where id='${A.liId}'`), 'paused');
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}'`), 't');

  // The freeze HOLDS: the self-serve resume RPCs must refuse while pending, or one click undoes it
  // — the same defect class the erased-surface audit (20260726110000) closed one state later.
  for (const [fn, id] of [['advertiser_set_campaign_status', A.campId], ['advertiser_set_line_item_status', A.liId]]) {
    const resume = await rpc(fn, { p_id: id, p_target: 'active' }, A.jwt);
    assert.ok(!resume.ok && resume.status >= 400, `${fn} must refuse a pending advertiser, got ${resume.status}`);
    assert.match(JSON.stringify(resume.data ?? {}), /deletion_pending/, `${fn} must refuse with deletion_pending`);
  }
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}'`), 'paused',
    'the refused resume really did not write');

  // A repeat request must not restart the Art. 12(3) clock.
  const at = psql(`select deletion_requested_at from public.advertisers where id='${A.advId}'`);
  await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(psql(`select deletion_requested_at from public.advertisers where id='${A.advId}'`), at);

  // ...and a terminal refusal must NEVER become a deferral: the house advertiser can never be
  // erased, so scheduling one would freeze the sentinel identity forever.
  const H = seedAdvertiser({ isHouse: true });
  const house = await rpc('advertiser_gdpr_self_delete', {}, H.jwt);
  assert.equal(house.data.ok, false, 'house_advertiser is terminal, not deferrable');
  assert.equal(house.data.reason, 'house_advertiser');
  assert.equal(psql(`select coalesce(deletion_requested_at::text,'NULL') from public.advertisers where id='${H.advId}'`), 'NULL',
    'the house advertiser must NOT be scheduled for a deletion that can never complete');
  assert.equal(psql(`select status from public.campaigns where id='${H.campId}'`), 'active',
    'and must NOT be frozen');

  // H is left deliberately unfrozen by the assertion above, so it stays in the global rotation.
  // Pull it, or it perturbs the auction the rotation-sensitive suites measure.
  stopServing(H.advId);
});

// app.gdpr_complete_pending() is GLOBAL — it sweeps every pending row in the database, including
// ones parked by sibling tests (G22's spend_down org, G23's still-blocked one) and by other suites
// running against the same stack. So every assertion below is about a SPECIFIC id, and the summary
// counters are only ever asserted with >=. A test that pinned an exact global count would fail for
// reasons that have nothing to do with the code under test.
const sweep = () => JSON.parse(psql('select app.gdpr_complete_pending()::text'));

test('G24 — the cron completes a pending deletion once the blocker clears', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 0 });
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros, status)
        values ('sess_p3c_${A.advId.slice(0,8)}','${A.advId}',10000000,'pending')`);
  const req = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(req.data.state, 'pending', `precondition: the request must defer, got ${JSON.stringify(req.data)}`);

  // STILL BLOCKED — the cron must NOT erase yet. This half is what makes the test non-vacuous: an
  // "it erased" assertion on the second half would pass just as well against a cron that ignores
  // the gate entirely.
  let out = sweep();
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}'`), 't',
    'the cron must re-run the SAME gate, not blindly erase whatever is pending');
  assert.ok(out.still_pending >= 1, 'and must report it as still pending');
  assert.ok(psql(`select deletion_requested_at from public.advertisers where id='${A.advId}'`).length > 0,
    'the watermark survives an unsuccessful pass');

  // BLOCKER CLEARS -> the next pass completes it, through the UNCHANGED erasure body.
  psql(`update public.advertiser_topup_intents set status='credited' where advertiser_id='${A.advId}'`);
  out = sweep();
  assert.ok(out.advertisers_erased >= 1, `expected at least one erasure, got ${JSON.stringify(out)}`);
  assert.equal(psql(`select (deleted_at is not null) from public.advertisers where id='${A.advId}'`), 't');
  assert.match(psql(`select name from public.advertisers where id='${A.advId}'`), /^deleted-/,
    'the real erasure body ran — the name is anonymized, not merely flagged');
  assert.equal(psql(`select coalesce(deletion_requested_at::text,'NULL') from public.advertisers where id='${A.advId}'`),
    'NULL', 'the watermark is cleared on completion, so it only ever means "pending"');
  assert.ok(Number(psql(`select count(*) from public.advertiser_action_log
                          where advertiser_id='${A.advId}' and action='gdpr_erase'`)) >= 1,
    'the completion is audited exactly like a direct erasure — same body, same log');

  // IDEMPOTENT: a further pass must neither error nor touch this row again. Asserting the
  // timestamp is unchanged is stronger than asserting a zero counter, and immune to a sibling
  // suite completing its own row in the same pass.
  const erasedAt = psql(`select deleted_at from public.advertisers where id='${A.advId}'`);
  sweep();
  assert.equal(psql(`select deleted_at from public.advertisers where id='${A.advId}'`), erasedAt,
    'a completed row is never re-erased');
});

test('G25 — the cron holds a spend_down pending until the credit is actually exhausted', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 40000000 });
  const req = await rpc('advertiser_gdpr_self_delete', { p_disposition: 'spend_down' }, A.jwt);
  assert.equal(req.data.state, 'pending');

  // PRECONDITION, proven live: nothing else blocks this org. Phase 2 removed the idle-balance gate,
  // so the ONLY thing keeping it pending is the outstanding credit — which is exactly the claim.
  assert.equal(psql(`select count(*) from public.advertiser_topup_intents
                      where advertiser_id='${A.advId}' and status='pending'`), '0');
  assert.equal(psql(`select count(*) from public.advertiser_charges
                      where advertiser_id='${A.advId}' and status='pending'`), '0');

  sweep();
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}'`), 't',
    'credit outstanding — the cron must leave a spend_down pending');
  assert.equal(psql(`select balance_micros from public.advertiser_balances where advertiser_id='${A.advId}'`),
    '40000000', 'and must never sweep the balance itself as a side effect');

  // Reserved credit is committed to open serve windows, so it is NOT spent down yet either.
  psql(`update public.advertiser_balances set balance_micros = 0, reserved_micros = 15000000
         where advertiser_id='${A.advId}'`);
  sweep();
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}'`), 't',
    'a zero balance with credit still RESERVED is not spent down — erasing there would strand a hold');

  // Fully exhausted -> the next pass erases, and the disposition survives as the record of why.
  psql(`update public.advertiser_balances set reserved_micros = 0 where advertiser_id='${A.advId}'`);
  sweep();
  assert.equal(psql(`select (deleted_at is not null) from public.advertisers where id='${A.advId}'`), 't');
  assert.equal(psql(`select deletion_disposition from public.advertisers where id='${A.advId}'`), 'spend_down',
    'the disposition is preserved past completion — it is the record of what became of the credit');
});

test('G26 — a pending row past 25 days raises the Art. 12(3) alert, and clears it on completion', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 0 });
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros, status)
        values ('sess_p3a_${A.advId.slice(0,8)}','${A.advId}',10000000,'pending')`);
  await rpc('advertiser_gdpr_self_delete', {}, A.jwt);

  const key = `advertiser:${A.advId}`;
  const openAlerts = () => psql(`select count(*) from app.alert_events
     where check_name='gdpr_pending_overdue' and dedup_key='${key}' and status='open'`);

  // PRECONDITION: a fresh request is NOT overdue. Without this half, an alert that fired
  // unconditionally would pass the assertion below.
  sweep();
  assert.equal(openAlerts(), '0', 'a request made today must not be reported as overdue');

  // Backdate past 25 days — Art. 12(3) gives one month, so the alert must fire with days to spare.
  psql(`update public.advertisers set deletion_requested_at = now() - interval '26 days' where id='${A.advId}'`);
  const out = sweep();
  assert.ok(out.alerts_raised >= 1, `expected an overdue alert, got ${JSON.stringify(out)}`);
  assert.equal(openAlerts(), '1');

  // Deduped: a second pass must not spam a new row for the same subject every hour.
  sweep();
  assert.equal(openAlerts(), '1', 'the open-alert dedup index holds across passes');

  // Completion resolves it — an alert nobody can clear is an alert everybody learns to ignore.
  psql(`update public.advertiser_topup_intents set status='credited' where advertiser_id='${A.advId}'`);
  sweep();
  assert.equal(psql(`select (deleted_at is not null) from public.advertisers where id='${A.advId}'`), 't');
  assert.equal(openAlerts(), '0', 'the alert resolves once the deletion actually completes');
  assert.equal(psql(`select count(*) from app.alert_events
     where check_name='gdpr_pending_overdue' and dedup_key='${key}' and status='resolved'`), '1');
});

test('G27 — cancel restores EXACTLY what the freeze paused, is self-scoped, and dies at erasure', { skip: SKIP }, async () => {
  const A = seedAdvertiser({ balance: 0 });
  const B = seedAdvertiser({ balance: 0 });

  // A second campaign the advertiser had ALREADY paused of their own accord before ever asking to
  // be deleted. Cancel must NOT resurrect it: a blanket "unpause everything" would silently put an
  // advertiser's deliberately-stopped campaign back on air and start spending their money again.
  const preId = randomUUID();
  psql(`insert into public.campaigns (id, advertiser_id, name, status)
        values ('${preId}','${A.advId}','pre-paused','paused')`);

  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros, status)
        values ('sess_p3x_${A.advId.slice(0,8)}','${A.advId}',10000000,'pending')`);
  const req = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(req.data.state, 'pending', `precondition: ${JSON.stringify(req.data)}`);
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}'`), 'paused',
    'precondition: the freeze really paused the live campaign');

  const res = await rpc('advertiser_gdpr_cancel_deletion', {}, A.jwt);
  assert.ok(res.ok, `cancel failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true);
  assert.equal(res.data.state, 'cancelled');

  assert.equal(psql(`select coalesce(deletion_requested_at::text,'NULL') from public.advertisers where id='${A.advId}'`),
    'NULL', 'the watermark is cleared — the cron must never pick this row up again');
  assert.equal(psql(`select coalesce(deletion_disposition,'NULL') from public.advertisers where id='${A.advId}'`),
    'NULL', 'and the elected disposition goes with it');
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}'`), 'active',
    'the campaign the freeze paused is restored');
  assert.equal(psql(`select status from public.line_items where id='${A.liId}'`), 'active');
  assert.equal(psql(`select status from public.campaigns where id='${preId}'`), 'paused',
    'a campaign the ADVERTISER had already paused stays paused — cancel restores, it does not resurrect');

  // The freeze is lifted at the gates too, not just in the data.
  const resume = await rpc('advertiser_set_campaign_status', { p_id: A.campId, p_target: 'active' }, A.jwt);
  assert.ok(resume.ok, `resume must work again after cancel: ${JSON.stringify(resume.data)}`);

  // Nothing pending any more.
  const twice = await rpc('advertiser_gdpr_cancel_deletion', {}, A.jwt);
  assert.equal(twice.data.ok, false);
  assert.equal(twice.data.reason, 'not_pending');

  // And the cron must never come back for it. A cancel the hourly pass then overrides would be the
  // worst outcome in this whole phase: an irreversible erasure of an account its owner just saved.
  // (The cron additionally re-reads each row FOR UPDATE, which covers the concurrent case this
  // single-session assertion cannot reach.)
  psql(`update public.advertiser_topup_intents set status='credited' where advertiser_id='${A.advId}'`);
  sweep();
  assert.equal(psql(`select (deleted_at is null) from public.advertisers where id='${A.advId}'`), 't',
    'a cancelled deletion must never be completed by the cron, even with every blocker cleared');

  // Self-scoped: A's cancel could never have reached B. Prove B is untouched and independently
  // cancellable, so "untouched" is not just "B was never pending in the first place".
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros, status)
        values ('sess_p3y_${B.advId.slice(0,8)}','${B.advId}',10000000,'pending')`);
  await rpc('advertiser_gdpr_self_delete', {}, B.jwt);
  assert.ok(psql(`select deletion_requested_at from public.advertisers where id='${B.advId}'`).length > 0,
    'B is pending');
  await rpc('advertiser_gdpr_cancel_deletion', {}, A.jwt);
  assert.ok(psql(`select deletion_requested_at from public.advertisers where id='${B.advId}'`).length > 0,
    "A's cancel must not clear B's pending deletion");
  assert.equal((await rpc('advertiser_gdpr_cancel_deletion', {}, B.jwt)).data.ok, true, 'B cancels its own');

  // Cancel is available RIGHT UP UNTIL erasure fires — and not one moment after. A's deposit is
  // still mid-flight from the top of this test, so settle it first: otherwise the request below
  // would (correctly) defer again and never reach the state this half is about.
  psql(`update public.advertiser_topup_intents set status='credited' where advertiser_id='${A.advId}'`);
  const erased = await rpc('advertiser_gdpr_self_delete', {}, A.jwt);
  assert.equal(erased.data.ok, true);
  assert.equal(erased.data.state, 'erased', 'precondition: nothing blocks A any more, so it erases now');
  const late = await rpc('advertiser_gdpr_cancel_deletion', {}, A.jwt);
  assert.equal(late.data.ok, false);
  assert.equal(late.data.reason, 'already_deleted', 'erasure is terminal — cancel cannot undo it');
  assert.match(psql(`select name from public.advertisers where id='${A.advId}'`), /^deleted-/,
    'the refused cancel left the anonymized name intact');

  // B was cancelled, so its campaigns are back to active and it is in the rotation again. A is
  // erased and structurally excluded, but pull both for symmetry — no test below needs either.
  stopServing(A.advId);
  stopServing(B.advId);
});
