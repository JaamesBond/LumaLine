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
function migrationPresent() {
  try { return psql("select to_regprocedure('public.advertiser_gdpr_self_delete()') is not null;") === 't'; }
  catch { return false; }
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

function teardown() {
  try {
    const parts = [`set session_replication_role = replica;`];
    const advs = advIds.map((x) => `'${x}'`).join(',');
    if (advs) {
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
