// test/advertiser-moderation-money.integration.mjs — M9-T5: admin moderation + admin money + self-deal.
//
// 20260716200000_advertiser_moderation_admin_money_gdpr.sql is the admin control surface over the
// self-serve portal. This suite drives it through PostgREST (admin sessions carry a simulated `aal`
// claim that flows into request.jwt.claims) and psql (app.admins / app.money_admins + the economic
// fixtures live off the Data API). Self-skips without the local stack / psql / the 200000 migration.
//
// WHAT IS TESTED:
//   M1  — approve_creative (admin aal1): pending_review→active + cascade draft campaign/line_item→active,
//         audited to advertiser_action_log (immutable)
//   M2  — reject_creative: pending_review→rejected with a reason; audited
//   M3  — suspend_creative (kill switch): active→paused, audited to BOTH the advertiser + admin trails
//   M4  — moderation authz: an advertiser session and anon cannot approve/reject/suspend
//   M5  — admin_prepay_clawback (BALANCE path, aal2): reverses the impression + re-credits the
//         advertiser's balance by the drawn amount, zero-sum, balance == −SUM(advertiser_funds),
//         audited both trails, idempotent (already_clawed_back); aal1 refused
//   M6  — admin_prepay_clawback (STRIPE path): a postpay/stripe-settled charge delegates to
//         admin_open_clawback → settled_via='stripe', refund_required (never a balance re-credit)
//   M7  — admin_advertiser_adjust_balance (aal2): credit books zero-sum + raises balance; a debit is
//         AVAILABLE-guarded (refused past balance−reserved); aal1 refused; anon revoked
//   M8  — scan_selfdeal_risk: a publisher sharing an advertiser member's email DOMAIN → the impression
//         is clawed_back, a payout hold is recorded, and payout_status is downgraded verified→pending

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
function psqlJson(sql) { return JSON.parse(psql(sql)); }
// Run a statement expected to FAIL; return the DB error text (stderr), or '' if it unexpectedly succeeded.
function psqlExpectError(sql) { try { psql(sql); return ''; } catch (e) { return String(e.stderr || e.message || e); } }

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
  try {
    return psql("select (to_regprocedure('public.advertiser_approve_creative(uuid)') is not null and to_regprocedure('public.admin_prepay_clawback(uuid,text)') is not null and to_regprocedure('app.scan_selfdeal_risk(interval)') is not null);") === 't';
  } catch { return false; }
}

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const PRESENT  = PSQL_OK ? migrationPresent() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !PRESENT ? '20260716200000 not applied — SKIPPING'
  : false;
if (SKIP) console.log(`[advertiser-moderation-money.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Personas.
//   ADMIN      — app.admins, aal1                       → moderation
//   MADMIN     — app.admins + app.money_admins, aal2    → money actions
//   MONEY_AAL1 — app.admins + app.money_admins, aal1    → refused on money (session is aal1)
//   OWNER      — an advertiser session (not an admin)   → refused on moderation
// ---------------------------------------------------------------------------
const ADMIN      = { authId: randomUUID() };
const MADMIN     = { authId: randomUUID() };
const MONEY_AAL1 = { authId: randomUUID() };
const OWNER      = { authId: randomUUID() };
const ADMIN_JWT      = mintJwt(ADMIN.authId);                 // aal1 (no aal → default)
const MADMIN_JWT     = mintJwt(MADMIN.authId,     { aal: 'aal2' });
const MONEY_AAL1_JWT = mintJwt(MONEY_AAL1.authId);
const OWNER_JWT      = mintJwt(OWNER.authId);

const advIds = [];
const pubIds = [];
const authIds = [ADMIN.authId, MADMIN.authId, MONEY_AAL1.authId, OWNER.authId];

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')
    on conflict (id) do nothing;`);
}

// A prepay advertiser + campaign(draft) + line_item(draft) + optional pending_review creative.
function seedAdvertiser({ billingMode = 'prepay', campStatus = 'draft', liStatus = 'draft', balance = 0, reserved = 0 } = {}) {
  const advId = randomUUID(), campId = randomUUID(), liId = randomUUID();
  psql(`insert into public.advertisers (id, name, status, billing_mode, is_house)
        values ('${advId}', 'Mod ${advId.slice(0, 8)}', 'active', '${billingMode}', false);`);
  psql(`insert into public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
        values ('${advId}', ${balance}, ${reserved});`);
  psql(`insert into public.campaigns (id, advertiser_id, name, status)
        values ('${campId}', '${advId}', 'camp', '${campStatus}');`);
  // Non-house prepay line_item must satisfy the check_selfserve_line_item CHECK (cpc=0, cpva>=1000).
  psql(`insert into public.line_items (id, campaign_id, cpva_bid_micros, cpc_bid_micros, status)
        values ('${liId}', '${campId}', 5000, 0, '${liStatus}');`);
  advIds.push(advId);
  return { advId, campId, liId };
}
function seedCreative(liId, status = 'pending_review') {
  const crId = randomUUID();
  psql(`insert into public.creatives (id, line_item_id, line, dest_url, label, status)
        values ('${crId}', '${liId}', 'Try our honest signed ads', 'https://example.test/x', 'sponsored', '${status}');`);
  return crId;
}
function seedPublisher(email) {
  const authId = randomUUID(), pubId = randomUUID();
  seedUser(authId, email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, payout_status, status)
        values ('${pubId}', '${authId}', 'mm-${pubId.slice(0,8)}', 'FR', 'acct_${pubId.slice(0,8)}', 'verified', 'active');`);
  authIds.push(authId);
  pubIds.push(pubId);
  return { authId, pubId };
}
// Impression + its balanced 3-leg cpva_accrual group (advertiser_billing leg advertiser_id=NULL, as
// app.accrue books). impressions.window_id is a logical ref (no FK to ad_windows), so no ad_window row
// is needed — public.clawback + admin_open_clawback resolve the window from the impression itself.
function seedImpressionAccrual({ pubId, liId, gross, winId = randomUUID(), state = 'cleared', ageDays = 1 }) {
  const impId = randomUUID(), grp = randomUUID();
  psql(`insert into public.impressions (id, window_id, publisher_id, line_item_id, attention_seconds, gross_micros, state, created_at)
        values ('${impId}', '${winId}', '${pubId}', '${liId}', 5, ${gross}, '${state}', now() - interval '${ageDays} days');`);
  if (gross > 0) {
    const pub = Math.round(gross * 0.6), plat = gross - pub;
    psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
      ('${grp}','cpva_accrual','advertiser_billing',${gross},'${state}','impression','${impId}',null),
      ('${grp}','cpva_accrual','publisher_earnings',${-pub},'${state}','impression','${impId}','${pubId}'),
      ('${grp}','cpva_accrual','platform_revenue',${-plat},'${state}','impression','${impId}',null);`);
  }
  return { impId, winId, grp };
}
function seedCharge({ grp, advId, impId, amount, settledVia, batchId = null, stripeChargeId = null, status = 'succeeded' }) {
  const cents = Math.round(amount / 10000);
  psql(`insert into public.advertiser_charges (entry_group_id, advertiser_id, impression_id, amount_micros, amount_cents, status, settled_via, stripe_charge_id, charge_batch_id)
        values ('${grp}', '${advId}', '${impId}', ${amount}, ${cents}, '${status}', '${settledVia}',
          ${stripeChargeId ? `'${stripeChargeId}'` : 'null'}, ${batchId ? `'${batchId}'` : 'null'});`);
}
function getBalance(advId) {
  const [b, r] = psql(`select balance_micros||'|'||reserved_micros from public.advertiser_balances where advertiser_id='${advId}';`).split('|');
  return { balance: Number(b), reserved: Number(r) };
}
function sumLeg(advId, account) {
  return Number(psql(`select coalesce(sum(amount_micros),0) from public.ledger_entries where advertiser_id='${advId}' and account='${account}';`));
}
function advActionCount(advId, action) {
  return Number(psql(`select count(*) from public.advertiser_action_log where advertiser_id='${advId}' and action='${action}';`));
}
function adminActionCount(action, targetId) {
  return Number(psql(`select count(*) from app.admin_action_log where action='${action}' and target_id='${targetId}';`));
}

function teardown() {
  try {
    const parts = [`set session_replication_role = replica;`];
    const advs = advIds.map((x) => `'${x}'`).join(',');
    const pubs = pubIds.map((x) => `'${x}'`).join(',');
    if (pubs) {
      parts.push(`delete from public.clawback_reviews where impression_id in (select id from public.impressions where publisher_id in (${pubs}));`);
      parts.push(`delete from public.ledger_entries where publisher_id in (${pubs}) or source_id in (select id from public.impressions where publisher_id in (${pubs}));`);
      parts.push(`delete from public.publisher_payout_holds where publisher_id in (${pubs});`);
      parts.push(`delete from public.risk_flags where window_id in (select window_id from public.impressions where publisher_id in (${pubs}));`);
    }
    if (advs) {
      parts.push(`delete from public.ledger_entries where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_charges where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_balance_ledger where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_action_log where advertiser_id in (${advs});`);
      parts.push(`delete from public.impressions where line_item_id in (select li.id from public.line_items li join public.campaigns c on c.id=li.campaign_id where c.advertiser_id in (${advs}));`);
      parts.push(`delete from public.ad_windows where line_item_id in (select li.id from public.line_items li join public.campaigns c on c.id=li.campaign_id where c.advertiser_id in (${advs}));`);
      parts.push(`delete from public.creatives where line_item_id in (select li.id from public.line_items li join public.campaigns c on c.id=li.campaign_id where c.advertiser_id in (${advs}));`);
      parts.push(`delete from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id in (${advs}));`);
      parts.push(`delete from public.campaigns where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_balances where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_users where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertisers where id in (${advs});`);
    }
    if (pubs) {
      parts.push(`delete from public.devices where publisher_id in (${pubs});`);
      parts.push(`delete from public.publishers where id in (${pubs});`);
    }
    parts.push(`delete from app.admin_action_log where actor in (${authIds.map((a) => `'${a}'`).join(',')});`);
    parts.push(`delete from app.money_admins where auth_user_id in ('${MADMIN.authId}','${MONEY_AAL1.authId}');`);
    parts.push(`delete from app.admins where auth_user_id in ('${ADMIN.authId}','${MADMIN.authId}','${MONEY_AAL1.authId}');`);
    parts.push(`delete from app.alert_events where check_name like 'advertiser_%' and split_part(dedup_key,':',2) in (${advs || `''`});`);
    parts.push(`delete from auth.users where id in (${authIds.map((a) => `'${a}'`).join(',')});`);
    parts.push(`reset session_replication_role;`);
    psql(parts.join('\n'));
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedUser(ADMIN.authId, `mm-admin-${ADMIN.authId}@example.com`);
  seedUser(MADMIN.authId, `mm-madmin-${MADMIN.authId}@example.com`);
  seedUser(MONEY_AAL1.authId, `mm-m1-${MONEY_AAL1.authId}@example.com`);
  seedUser(OWNER.authId, `mm-owner-${OWNER.authId}@example.com`);
  psql(`insert into app.admins (auth_user_id) values ('${ADMIN.authId}'), ('${MADMIN.authId}'), ('${MONEY_AAL1.authId}') on conflict do nothing;`);
  psql(`insert into app.money_admins (auth_user_id) values ('${MADMIN.authId}'), ('${MONEY_AAL1.authId}') on conflict do nothing;`);
  process.on('exit', teardown);
}

// ---------------------------------------------------------------------------
test('M1: approve_creative activates the creative + cascades the draft chain, audited', { skip: SKIP }, async () => {
  const { advId, campId, liId } = seedAdvertiser({ campStatus: 'draft', liStatus: 'draft' });
  const crId = seedCreative(liId, 'pending_review');

  // The advertiser org owner cannot approve their own creative (not an admin).
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role) values ('${OWNER.authId}','${advId}','owner');`);
  const self = await rpc('advertiser_approve_creative', { p_creative_id: crId }, OWNER_JWT);
  assert.ok(!self.ok && self.status >= 400, 'advertiser cannot approve its own creative');
  psql(`delete from public.advertiser_users where advertiser_id='${advId}';`);

  const res = await rpc('advertiser_approve_creative', { p_creative_id: crId }, ADMIN_JWT);
  assert.ok(res.ok, `approve failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true);
  assert.equal(res.data.status, 'active');
  assert.equal(psql(`select status from public.creatives where id='${crId}';`), 'active', 'creative active');
  assert.equal(psql(`select status from public.line_items where id='${liId}';`), 'active', 'line_item cascaded active');
  assert.equal(psql(`select status from public.campaigns where id='${campId}';`), 'active', 'campaign cascaded active');
  assert.equal(advActionCount(advId, 'approve_creative'), 1, 'audited to advertiser_action_log');

  // The action log is append-only: a direct UPDATE/DELETE is rejected by the immutability trigger.
  assert.match(psqlExpectError(`update public.advertiser_action_log set action='x' where advertiser_id='${advId}';`),
    /append-only/, 'advertiser_action_log is immutable');
});

test('M2: reject_creative → rejected with a reason, audited', { skip: SKIP }, async () => {
  const { advId, liId } = seedAdvertiser();
  const crId = seedCreative(liId, 'pending_review');
  const res = await rpc('advertiser_reject_creative', { p_creative_id: crId, p_reason: 'off-policy category' }, ADMIN_JWT);
  assert.ok(res.ok, `reject failed: ${JSON.stringify(res.data)}`);
  assert.equal(res.data.status, 'rejected');
  assert.equal(psql(`select status from public.creatives where id='${crId}';`), 'rejected');
  assert.equal(advActionCount(advId, 'reject_creative'), 1);
  // Empty reason is refused.
  const cr2 = seedCreative(liId, 'pending_review');
  const bad = await rpc('advertiser_reject_creative', { p_creative_id: cr2, p_reason: '  ' }, ADMIN_JWT);
  assert.ok(!bad.ok, 'empty reason refused');
});

test('M3: suspend_creative kill switch (active→paused), audited to both trails', { skip: SKIP }, async () => {
  const { advId, liId } = seedAdvertiser({ liStatus: 'active' });
  const crId = seedCreative(liId, 'active');
  const res = await rpc('advertiser_suspend_creative', { p_creative_id: crId, p_reason: 'dest bait-and-switch' }, ADMIN_JWT);
  assert.ok(res.ok, `suspend failed: ${JSON.stringify(res.data)}`);
  assert.equal(res.data.status, 'paused');
  assert.equal(psql(`select status from public.creatives where id='${crId}';`), 'paused', 'stops serving instantly (window_open needs active)');
  assert.equal(advActionCount(advId, 'suspend_creative'), 1, 'advertiser trail');
  assert.equal(adminActionCount('advertiser_suspend_creative', crId), 1, 'admin destructive trail');
  // A non-active creative is a clean no-op.
  const again = await rpc('advertiser_suspend_creative', { p_creative_id: crId, p_reason: 'x' }, ADMIN_JWT);
  assert.equal(again.data.ok, false);
  assert.equal(again.data.reason, 'not_active');
});

test('M4: moderation authz — advertiser session + anon are refused', { skip: SKIP }, async () => {
  const { advId, liId } = seedAdvertiser();
  const crId = seedCreative(liId, 'pending_review');
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role) values ('${OWNER.authId}','${advId}','owner');`);
  for (const fn of ['advertiser_approve_creative', 'advertiser_reject_creative', 'advertiser_suspend_creative']) {
    const body = fn === 'advertiser_approve_creative' ? { p_creative_id: crId } : { p_creative_id: crId, p_reason: 'x' };
    const owner = await rpc(fn, body, OWNER_JWT);
    assert.ok(!owner.ok && owner.status >= 400, `${fn}: advertiser refused`);
    const anon = await rpc(fn, body, null);
    assert.ok(!anon.ok, `${fn}: anon refused`);
  }
  psql(`delete from public.advertiser_users where advertiser_id='${advId}';`);
  assert.equal(psql(`select status from public.creatives where id='${crId}';`), 'pending_review', 'creative untouched by refused calls');
});

test('M5: admin_prepay_clawback (BALANCE) reverses + re-credits balance, zero-sum, idempotent', { skip: SKIP }, async () => {
  const { advId, liId } = seedAdvertiser();
  const { pubId } = seedPublisher(`mm-p5-${randomUUID()}@example.com`);
  // Deposit €100 (via the real primitive → deposit ledger group + balance 100M).
  const sess = `s5_${advId.slice(0, 8)}`, pi = `pi5_${advId.slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros) values ('${sess}','${advId}',100000000);`);
  psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','e5',100000000);`);

  // A €1 cleared impression + accrual + a balance-settled succeeded charge under a batch. The advertiser
  // held €1 of reserve for it (set directly), so the draw-down is clean (reserved covers the sum).
  const batch = randomUUID();
  const { impId, winId, grp } = seedImpressionAccrual({ pubId, liId, gross: 1000000 });
  seedCharge({ grp, advId, impId, amount: 1000000, settledVia: 'balance', batchId: batch });
  psql(`update public.advertiser_balances set reserved_micros=1000000 where advertiser_id='${advId}';`);
  // Real draw-down of the batch → balance 100M→99M, reserved→0, no alarm (reserved covered).
  const d = psqlJson(`select app.advertiser_draw_down_batch('${advId}','${batch}',1000000);`);
  assert.equal(d.drawn, true);
  assert.equal(getBalance(advId).balance, 99000000, 'balance spent down by the draw');

  // aal1 money-member is refused.
  const aal1 = await rpc('admin_prepay_clawback', { p_impression_id: impId, p_reason: 'fraud' }, MONEY_AAL1_JWT);
  assert.ok(!aal1.ok && aal1.status >= 400, 'aal1 refused on a money action');

  const res = await rpc('admin_prepay_clawback', { p_impression_id: impId, p_reason: 'verified fraud' }, MADMIN_JWT);
  assert.ok(res.ok, `clawback failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true);
  assert.equal(res.data.settled_via, 'balance');
  assert.equal(res.data.re_credited_micros, 1000000, 're-credited the drawn amount');

  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'impression clawed_back');
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id='${grp}' and state<>'reversed';`), '0', 'accrual reversed');
  assert.equal(getBalance(advId).balance, 100000000, 'balance re-credited back to the full deposit');
  // Balance identity holds end-to-end: balance == −SUM(advertiser_funds).
  assert.equal(getBalance(advId).balance, -sumLeg(advId, 'advertiser_funds'), 'balance == −SUM(advertiser_funds)');
  assert.equal(psql(`select count(*) from public.advertiser_balance_ledger where advertiser_id='${advId}' and kind='refund';`), '1', 'a refund sub-ledger row booked');
  assert.equal(advActionCount(advId, 'admin_prepay_clawback'), 1, 'advertiser trail');
  assert.equal(adminActionCount('admin_prepay_clawback', winId), 1, 'admin money trail');

  // Idempotent: a second call is a no-op (impression already clawed_back).
  const again = await rpc('admin_prepay_clawback', { p_impression_id: impId, p_reason: 'x' }, MADMIN_JWT);
  assert.equal(again.data.ok, false);
  assert.equal(again.data.reason, 'already_clawed_back');
  assert.equal(getBalance(advId).balance, 100000000, 'no double re-credit');
});

test('M5b: BALANCE clawback of a CREDITED-but-UNDRAWN impression RELEASES the stranded reserve', { skip: SKIP }, async () => {
  // The stranded-reserve must-fix: a credited-but-undrawn window holds reserve_micros=gross and the
  // balance holds reserved=gross. A clawback lands BEFORE draw-down — the impression flips to
  // clawed_back and never enters a charge batch, so draw-down would never zero its window. Without
  // the fix, reserved_micros stays permanently inflated (the advertiser silently loses AVAILABLE
  // credit). admin_prepay_clawback must release + zero the reserve.
  const { advId, liId } = seedAdvertiser();
  const { pubId } = seedPublisher(`mm-p5b-${randomUUID()}@example.com`);
  const deviceId = randomUUID();
  psql(`insert into public.devices (id, publisher_id) values ('${deviceId}','${pubId}');`);

  // Deposit €100 (never drawn — the window is credited but the draw-down hasn't run).
  const sess = `s5b_${advId.slice(0, 8)}`, pi = `pi5b_${advId.slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros) values ('${sess}','${advId}',100000000);`);
  psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','e5b',100000000);`);

  // A credited-undrawn window: reserve trued to gross (8M), balance holds reserved=8M, NO charge row.
  const gross = 8000000, winId = randomUUID();
  psql(`update public.advertiser_balances set reserved_micros=${gross} where advertiser_id='${advId}';`);
  const { impId } = seedImpressionAccrual({ pubId, liId, gross, winId, state: 'cleared' });
  psql(`insert into public.ad_windows (window_id, publisher_id, device_id, line_item_id, challenge, nonce, reserve_micros, state)
        values ('${winId}','${pubId}','${deviceId}','${liId}','ch','no',${gross},'credited');`);
  assert.equal(getBalance(advId).reserved, gross, 'reserved holds the credited-undrawn window');

  const res = await rpc('admin_prepay_clawback', { p_impression_id: impId, p_reason: 'verified fraud' }, MADMIN_JWT);
  assert.ok(res.ok, `clawback failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true);
  assert.equal(res.data.settled_via, 'balance');
  assert.equal(res.data.re_credited_micros, 0, 'an UNDRAWN impression re-credits 0 (nothing was drawn)');

  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'impression clawed_back');
  assert.equal(psql(`select reserve_micros from public.ad_windows where window_id='${winId}';`), '0', 'the window reserve is zeroed');
  assert.equal(getBalance(advId).reserved, 0, 'the STRANDED reserve is released back (8M -> 0)');
  assert.equal(getBalance(advId).balance, 100000000, 'balance unchanged (undrawn — no re-credit)');
});

test('M5c: DIRECT admin_open_clawback of a prepay credited-undrawn impression RELEASES the reserve', { skip: SKIP }, async () => {
  // The same stranded-reserve seam as M5b, but through the GENERIC admin_open_clawback (M8) instead
  // of admin_prepay_clawback. admin_open_clawback is directly callable by money-admins AND is the
  // delegate admin_prepay_clawback routes the Stripe/postpay path to, so it must release the prepay
  // reserve on its own (migration 20260716220000). public.clawback() predates prepay and never
  // touches the reserve, so without the fix a direct call here would strand reserved_micros forever.
  const { advId, liId } = seedAdvertiser();
  const { pubId } = seedPublisher(`mm-p5c-${randomUUID()}@example.com`);
  const deviceId = randomUUID();
  psql(`insert into public.devices (id, publisher_id) values ('${deviceId}','${pubId}');`);

  // Deposit €100 (never drawn), then hold €8 of reserve for a credited-undrawn window (no charge row).
  const sess = `s5c_${advId.slice(0, 8)}`, pi = `pi5c_${advId.slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros) values ('${sess}','${advId}',100000000);`);
  psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','e5c',100000000);`);

  const gross = 8000000, winId = randomUUID();
  psql(`update public.advertiser_balances set reserved_micros=${gross} where advertiser_id='${advId}';`);
  const { impId } = seedImpressionAccrual({ pubId, liId, gross, winId, state: 'cleared' });
  psql(`insert into public.ad_windows (window_id, publisher_id, device_id, line_item_id, challenge, nonce, reserve_micros, state)
        values ('${winId}','${pubId}','${deviceId}','${liId}','ch','no',${gross},'credited');`);
  assert.equal(getBalance(advId).reserved, gross, 'reserved holds the credited-undrawn window');

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: 'verified fraud' }, MADMIN_JWT);
  assert.ok(res.ok, `clawback failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true);
  assert.equal(res.data.reserve_released_micros, gross, 'the released reserve is reported in the result');
  assert.equal(res.data.refund_required, false, 'no charge row → nothing to refund');

  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'impression clawed_back');
  assert.equal(psql(`select reserve_micros from public.ad_windows where window_id='${winId}';`), '0', 'the window reserve is zeroed');
  assert.equal(getBalance(advId).reserved, 0, 'the STRANDED reserve is released back (8M -> 0)');
  assert.equal(getBalance(advId).balance, 100000000, 'balance unchanged (admin_open_clawback releases the reserve, never re-credits)');

  // Idempotent: a repeat is refused as already_clawed_back and moves nothing.
  const again = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: 'x' }, MADMIN_JWT);
  assert.equal(again.data.ok, false, 'repeat refused');
  assert.equal(again.data.reason, 'already_clawed_back');
  assert.equal(getBalance(advId).reserved, 0, 'reserve stays 0 on the idempotent repeat');
});

// A postpay window carries reserve_micros=0, so the release is a safe no-op: admin_open_clawback of a
// postpay impression must reverse normally without touching any advertiser balance.
test('M5d: admin_open_clawback of a POSTPAY impression is a reserve-release no-op', { skip: SKIP }, async () => {
  const { advId, liId } = seedAdvertiser({ billingMode: 'postpay', campStatus: 'active', liStatus: 'active' });
  const { pubId } = seedPublisher(`mm-p5d-${randomUUID()}@example.com`);
  const { impId, grp } = seedImpressionAccrual({ pubId, liId, gross: 1000000 });
  seedCharge({ grp, advId, impId, amount: 1000000, settledVia: 'stripe', stripeChargeId: `pi_${grp.slice(0, 8)}` });

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: 'postpay dispute' }, MADMIN_JWT);
  assert.ok(res.ok, `clawback failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true);
  assert.equal(res.data.reserve_released_micros, 0, 'no reserve to release for a postpay window');
  assert.equal(res.data.refund_required, true, 'a succeeded CPVA charge → refund_required');
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'impression clawed_back');
  assert.equal(getBalance(advId).reserved, 0, 'postpay reserved stays 0');
});

test('M6: admin_prepay_clawback (STRIPE) delegates to the card path (settled_via=stripe, refund_required)', { skip: SKIP }, async () => {
  const { advId, liId } = seedAdvertiser({ billingMode: 'postpay', campStatus: 'active', liStatus: 'active' });
  const { pubId } = seedPublisher(`mm-p6-${randomUUID()}@example.com`);
  const { impId, grp } = seedImpressionAccrual({ pubId, liId, gross: 1000000 });
  seedCharge({ grp, advId, impId, amount: 1000000, settledVia: 'stripe', stripeChargeId: `pi_${grp.slice(0, 8)}` });

  const res = await rpc('admin_prepay_clawback', { p_impression_id: impId, p_reason: 'card dispute' }, MADMIN_JWT);
  assert.ok(res.ok, `stripe clawback failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.ok, true, 'delegated card clawback succeeds');
  assert.equal(res.data.settled_via, 'stripe', 'routed to the Stripe refund path');
  assert.equal(res.data.refund_required, true, 'a succeeded CPVA charge → refund_required');
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'impression clawed_back by the delegate');
  // No prepay balance re-credit for a card charge.
  assert.equal(psql(`select count(*) from public.advertiser_balance_ledger where advertiser_id='${advId}' and kind='refund';`), '0', 'no balance re-credit for a card charge');
});

test('M7: admin_advertiser_adjust_balance — credit books zero-sum; debit is AVAILABLE-guarded', { skip: SKIP }, async () => {
  const { advId } = seedAdvertiser();
  // Credit +€50 (advertiser starts at 0).
  const c = await rpc('admin_advertiser_adjust_balance', { p_advertiser_id: advId, p_delta_micros: 50000000, p_reason: 'goodwill' }, MADMIN_JWT);
  assert.ok(c.ok, `credit failed: ${JSON.stringify(c.data)}`);
  assert.equal(getBalance(advId).balance, 50000000, 'balance credited');
  assert.equal(getBalance(advId).balance, -sumLeg(advId, 'advertiser_funds'), 'balance == −SUM(advertiser_funds) after adjust');

  // Reserve €40 → available €10. A €20 debit is refused; a €5 debit succeeds.
  psql(`update public.advertiser_balances set reserved_micros=40000000 where advertiser_id='${advId}';`);
  const over = await rpc('admin_advertiser_adjust_balance', { p_advertiser_id: advId, p_delta_micros: -20000000, p_reason: 'correction' }, MADMIN_JWT);
  assert.equal(over.data.ok, false, 'debit past AVAILABLE refused');
  assert.equal(over.data.reason, 'exceeds_available');
  assert.equal(getBalance(advId).balance, 50000000, 'refused debit does not move balance');

  const ok = await rpc('admin_advertiser_adjust_balance', { p_advertiser_id: advId, p_delta_micros: -5000000, p_reason: 'correction' }, MADMIN_JWT);
  assert.ok(ok.data.ok, `in-bounds debit failed: ${JSON.stringify(ok.data)}`);
  assert.equal(getBalance(advId).balance, 45000000, 'balance debited within available');

  // authz: aal1 refused, anon revoked.
  const aal1 = await rpc('admin_advertiser_adjust_balance', { p_advertiser_id: advId, p_delta_micros: 1000000, p_reason: 'x' }, MONEY_AAL1_JWT);
  assert.ok(!aal1.ok && aal1.status >= 400, 'aal1 refused');
  const anon = await rpc('admin_advertiser_adjust_balance', { p_advertiser_id: advId, p_delta_micros: 1000000, p_reason: 'x' }, null);
  assert.ok(!anon.ok, 'anon revoked');
});

test('M8: scan_selfdeal_risk claws back a shared-email-domain impression + holds the payout', { skip: SKIP }, () => {
  const domain = `collude-${randomUUID().slice(0, 8)}.test`;
  const { advId, liId } = seedAdvertiser({ campStatus: 'active', liStatus: 'active' });
  // The advertiser org member and the crediting publisher share the email DOMAIN (not the exact uid).
  const memberAuth = randomUUID();
  seedUser(memberAuth, `advertiser@${domain}`);
  authIds.push(memberAuth);
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role) values ('${memberAuth}','${advId}','owner');`);
  const { pubId } = seedPublisher(`publisher@${domain}`);
  const { impId, winId } = seedImpressionAccrual({ pubId, liId, gross: 1000000, state: 'cleared' });

  const r = psqlJson(`select app.scan_selfdeal_risk();`);
  assert.ok(r.impressions_flagged >= 1, `the shared-domain impression must be flagged, got ${JSON.stringify(r)}`);
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'the linked impression is reversed');
  assert.equal(psql(`select count(*) from public.risk_flags where window_id='${winId}' and reason='selfdeal:shared_email';`), '1', 'a self-deal flag recorded');
  assert.equal(psql(`select count(*) from public.publisher_payout_holds where publisher_id='${pubId}' and released_at is null;`), '1', 'the publisher payout is held for review');
  assert.equal(psql(`select payout_status from public.publishers where id='${pubId}';`), 'pending', 'payout eligibility downgraded (batch predicate skips non-verified)');

  psql(`delete from public.advertiser_users where advertiser_id='${advId}';`);
});
