// test/admin-open-clawback.integration.mjs — M8-T7 (Phase 2): the guarded manual clawback RPC.
//
// public.admin_open_clawback(p_impression_id, p_reason) (20260716140000) is the ONE new
// money-mutating admin surface: an audited, aal2-money-admin-gated manual clawback of an
// IMPRESSION and its whole window. It delegates the reversal to the existing idempotent
// public.clawback(), enforces a payout-leg-aware negative-payable post-condition, refuses
// un-refundable/racy situations, and audits to app.admin_action_log.
//
// Sessions are minted HS256 JWTs carrying a simulated `aal` claim that flows through PostgREST
// into request.jwt.claims (read by app.jwt_claim) — the same mechanism the device JWT's
// publisher_id claim uses. app.admins / app.money_admins / app.admin_action_log live in the
// private `app` schema (off the Data API) so their seeding + assertions go through psql, and the
// economic fixtures (back-dated impressions/clicks, cleared ledger groups, paid payouts,
// advertiser_charges) are seeded via psql so ages and paid legs are controllable. Self-skips if
// the local stack, psql, or the Phase-2 migration is unavailable.
//
// WHAT IS TESTED:
//   AC1  — happy path: fresh cleared impression + sibling CPC click, unpaid, succeeded CPVA charge
//          → whole window reversed (every group state='reversed', each group SUM=0), impression +
//          click clawed_back, exactly ONE approved review, exactly ONE window-keyed risk_flag, an
//          admin_action_log row, refund_required=true
//   AC2  — MONEY-SAFETY: aged, cleared, PAID earning → refused (earning_already_paid), ZERO
//          mutation persists; payable stays >= 0 before AND after
//   AC2b — MONEY-SAFETY (two-earning): a PAID earning A is refused even though the publisher holds
//          OTHER unpaid matured balance B that keeps AGGREGATE payable >= 0 (the exact hole the
//          aggregate-only post-condition missed); the UNPAID B is still allowed
//   AC3  — OVER-CONSERVATISM FIX: aged (>7d) cleared but UNPAID earning → allowed in-dashboard
//   AC4  — active payout (pending) for the publisher → {ok:false,reason:'payout_active'}, no effect
//   AC5  — window carrying a succeeded CPC charge → {ok:false,reason:'cpc_charge_present...'}, no effect
//   AC6  — idempotency: second call → already_clawed_back; pre-existing review → review_exists;
//          the partial unique index rejects a duplicate non-rejected review
//   AC7  — sentinel/gross<=0 → {ok:true,reason:'no_op_gross_zero'}, no ledger/review, but an audit row
//   AC8  — authz: aal1 money-member → 28000; aal2 non-member → 28000; anon → EXECUTE revoked;
//          empty reason → refused; unknown impression → refused

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
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
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function psqlExpectError(sql) {
  try { psql(sql); return ''; } catch (e) { return String(e.stderr || e.message || e); }
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
// The Phase-2 action RPC + the foundation it depends on must both be applied. Skip loudly if not.
function migrationPresent() {
  try {
    return psql("select (to_regprocedure('public.admin_open_clawback(uuid,text)') is not null and to_regprocedure('app.is_money_admin()') is not null and to_regprocedure('app.payout_hold_interval()') is not null);") === 't';
  } catch { return false; }
}

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const PRESENT  = PSQL_OK ? migrationPresent() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !PRESENT ? 'admin_open_clawback / foundation not applied — SKIPPING'
  : false;
if (SKIP) console.log(`[admin-open-clawback.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Personas — the is_money_admin() truth table (member AND aal2):
//   MADMIN     — app.admins + app.money_admins, aal2 → the only persona that may act
//   MONEY_AAL1 — app.admins + app.money_admins, aal1 → refused (session is aal1)
//   NONMEMBER  — no allow-list,                 aal2 → refused (not an admin at all)
// ---------------------------------------------------------------------------
const MADMIN     = { authId: randomUUID() };
const MONEY_AAL1 = { authId: randomUUID() };
const NONMEMBER  = { authId: randomUUID() };
const MADMIN_JWT     = mintJwt(MADMIN.authId,     { aal: 'aal2' });
const MONEY_AAL1_JWT = mintJwt(MONEY_AAL1.authId);                 // no aal → COALESCE default 'aal1'
const NONMEMBER_JWT  = mintJwt(NONMEMBER.authId,  { aal: 'aal2' });

const ADV = randomUUID();   // one throwaway advertiser for advertiser_charges FK
const REASON = 'M8 manual dispute clawback — verified fraud';

const created = [];   // { authId, pubId }

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

function newPublisher() {
  const authId = randomUUID(), pubId = randomUUID();
  seedUser(authId, `aoc-${authId}@example.com`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, status)
    values ('${pubId}','${authId}','aoc-${pubId.slice(0,8)}','FR','active');`);
  created.push({ authId, pubId });
  return { authId, pubId };
}

// Cleared cpva impression + its balanced 3-leg ledger group (gross>0). gross=0 → sentinel, no ledger.
function addImpression(pubId, { gross, ageDays = 1, winId = randomUUID(), state = 'cleared' } = {}) {
  const impId = randomUUID(), grp = randomUUID();
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, created_at)
    values ('${impId}','${winId}','${pubId}',5,${gross},'${state}', now() - interval '${ageDays} days');`);
  if (gross > 0) {
    const pub = Math.round(gross * 0.6), plat = gross - pub;
    psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
      ('${grp}','cpva_accrual','advertiser_billing',${gross},'${state}','impression','${impId}',null),
      ('${grp}','cpva_accrual','publisher_earnings',${-pub},'${state}','impression','${impId}','${pubId}'),
      ('${grp}','cpva_accrual','platform_revenue',${-plat},'${state}','impression','${impId}',null);`);
  }
  return { impId, winId, grp };
}

// Cleared cpc click on the SAME window + its balanced 3-leg cpc_accrual group.
function addClick(pubId, winId, { gross, ageDays = 1, state = 'cleared' } = {}) {
  const clickId = randomUUID(), grp = randomUUID();
  const tokenHash = randomUUID().replace(/-/g, '');
  const pub = Math.round(gross * 0.6), plat = gross - pub;
  psql(`insert into public.clicks (id, window_id, publisher_id, click_token_hash, gross_micros, state, created_at)
    values ('${clickId}','${winId}','${pubId}','${tokenHash}',${gross},'${state}', now() - interval '${ageDays} days');`);
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','cpc_accrual','advertiser_billing',${gross},'${state}','click','${clickId}',null),
    ('${grp}','cpc_accrual','publisher_earnings',${-pub},'${state}','click','${clickId}','${pubId}'),
    ('${grp}','cpc_accrual','platform_revenue',${-plat},'${state}','click','${clickId}',null);`);
  return { clickId, grp };
}

// A succeeded advertiser_charge on a ledger group. impressionId set = CPVA (refundable);
// null = CPC (impression_id NULL, no refund path).
function addCharge({ grp, impressionId = null, amountMicros, status = 'succeeded' }) {
  const cents = Math.round(amountMicros / 10000);
  psql(`insert into public.advertiser_charges (entry_group_id, advertiser_id, impression_id, amount_micros, amount_cents, status, stripe_charge_id)
    values ('${grp}','${ADV}', ${impressionId ? `'${impressionId}'` : 'null'}, ${amountMicros}, ${cents}, '${status}',
      ${status === 'succeeded' ? `'pi_test_${grp.slice(0, 8)}'` : 'null'});`);
}

// A PAID payout + its balanced cleared payout ledger group (publisher_earnings +amt / platform_cash -amt).
// Both legs share ONE entry_group_id in a single INSERT so the deferred zero-sum trigger passes.
function addPaidPayout(pubId, amountMicros) {
  const payoutId = randomUUID(), grp = randomUUID();
  psql(`insert into public.payouts (id, publisher_id, amount_micros, status, stripe_transfer_id, paid_at)
    values ('${payoutId}','${pubId}',${amountMicros},'paid','tr_test_${payoutId.slice(0,8)}', now());`);
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','payout','publisher_earnings',${amountMicros},'cleared','payout','${payoutId}','${pubId}'),
    ('${grp}','payout','platform_cash',${-amountMicros},'cleared','payout','${payoutId}',null);`);
  return payoutId;
}

// A pending (active) payout — no ledger booked at reserve.
function addPendingPayout(pubId, amountMicros) {
  const payoutId = randomUUID();
  psql(`insert into public.payouts (id, publisher_id, amount_micros, status)
    values ('${payoutId}','${pubId}',${amountMicros},'pending');`);
  return payoutId;
}

function payable(pubId) {
  return Number(psql(`select app.publisher_payable_micros('${pubId}'::uuid, app.payout_hold_interval());`));
}
function auditCount(action, targetId) {
  return Number(psql(`select count(*) from app.admin_action_log where actor='${MADMIN.authId}' and action='${action}' and target_id='${targetId}';`));
}

function seedFixture() {
  seedUser(MADMIN.authId, `aoc-madmin-${MADMIN.authId}@example.com`);
  seedUser(MONEY_AAL1.authId, `aoc-m1-${MONEY_AAL1.authId}@example.com`);
  seedUser(NONMEMBER.authId, `aoc-non-${NONMEMBER.authId}@example.com`);
  psql(`insert into app.admins (auth_user_id) values ('${MADMIN.authId}'), ('${MONEY_AAL1.authId}');`);
  psql(`insert into app.money_admins (auth_user_id) values ('${MADMIN.authId}'), ('${MONEY_AAL1.authId}');`);
  psql(`insert into public.advertisers (id, name) values ('${ADV}','aoc-adv');`);
}

function teardownFixture() {
  try {
    for (const { authId, pubId } of created) {
      try {
        psql(`delete from public.clawback_reviews where impression_id in (select id from public.impressions where publisher_id='${pubId}');`);
        psql(`delete from public.advertiser_charges where impression_id in (select id from public.impressions where publisher_id='${pubId}');`);
        psql(`delete from public.risk_flags where impression_id in (select id from public.impressions where publisher_id='${pubId}')
             or window_id in (select window_id from public.impressions where publisher_id='${pubId}')
             or window_id in (select window_id from public.clicks where publisher_id='${pubId}');`);
        // Delete WHOLE ledger groups atomically (the deferred balance trigger forbids a partial group).
        psql(`delete from public.ledger_entries where entry_group_id in (
             select entry_group_id from public.ledger_entries
              where publisher_id='${pubId}'
                 or source_id in (select id from public.impressions where publisher_id='${pubId}')
                 or source_id in (select id from public.clicks where publisher_id='${pubId}')
                 or source_id in (select id from public.payouts where publisher_id='${pubId}'));`);
        psql(`delete from public.payouts where publisher_id='${pubId}';`);
        psql(`delete from public.impressions where publisher_id='${pubId}';`);
        psql(`delete from public.clicks where publisher_id='${pubId}';`);
        psql(`delete from public.devices where publisher_id='${pubId}';`);
        psql(`delete from public.publishers where id='${pubId}';`);
        psql(`delete from auth.users where id='${authId}';`);
      } catch { /* best-effort per publisher */ }
    }
    const actors = [MADMIN.authId, MONEY_AAL1.authId, NONMEMBER.authId];
    psql(`delete from public.advertiser_charges where advertiser_id='${ADV}';`);
    psql(`delete from public.advertisers where id='${ADV}';`);
    psql(`delete from app.admin_action_log where actor in (${actors.map((a) => `'${a}'`).join(',')});`);
    psql(`delete from app.money_admins where auth_user_id in ('${MADMIN.authId}','${MONEY_AAL1.authId}');`);
    psql(`delete from app.admins where auth_user_id in ('${MADMIN.authId}','${MONEY_AAL1.authId}');`);
    psql(`delete from auth.users where id in (${actors.map((a) => `'${a}'`).join(',')});`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

// ---------------------------------------------------------------------------
// AC1 — happy path: whole-window reversal, one review, one flag, audited, refund_required.
// ---------------------------------------------------------------------------
test('AC1: fresh cleared impression + sibling CPC click (unpaid) is clawed back whole-window', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId, winId, grp: cpvaGrp } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });
  const { clickId, grp: cpcGrp } = addClick(pubId, winId, { gross: 500_000, ageDays: 1 });
  addCharge({ grp: cpvaGrp, impressionId: impId, amountMicros: 1_000_000, status: 'succeeded' }); // CPVA → refundable

  assert.ok(payable(pubId) >= 0, 'payable must be >= 0 before the call');

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(res.ok, `money-admin call must succeed, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(res.data?.window_id, winId, 'returns the reversed window id');
  assert.equal(res.data?.refund_required, true, 'a succeeded CPVA charge → refund_required=true');

  // Impression + sibling click both clawed_back.
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'impression clawed_back');
  assert.equal(psql(`select state from public.clicks where id='${clickId}';`), 'clawed_back', 'sibling click clawed_back');

  // Every ledger leg on the window is reversed, and each group still sums to 0.
  const notReversed = psql(`select count(*) from public.ledger_entries where entry_group_id in ('${cpvaGrp}','${cpcGrp}') and state <> 'reversed';`);
  assert.equal(notReversed, '0', 'all window ledger legs (CPVA + CPC groups) reversed');
  const unbalanced = psql(`select count(*) from (select entry_group_id from public.ledger_entries where entry_group_id in ('${cpvaGrp}','${cpcGrp}') group by entry_group_id having sum(amount_micros) <> 0) g;`);
  assert.equal(unbalanced, '0', 'each reversed group still sums to 0');

  // Exactly one approved review for the impression, fully attributed.
  const rev = psql(`select count(*)||'|'||coalesce(max(status),'')||'|'||coalesce(max(reviewed_by::text),'')||'|'||coalesce(max(review_reason),'')||'|'||(max(reviewed_at) is not null)
    from public.clawback_reviews where impression_id='${impId}';`);
  const [rc, rstatus, rby, rreason, rat] = rev.split('|');
  assert.equal(rc, '1', 'exactly one review row for the impression');
  assert.equal(rstatus, 'approved', 'review approved');
  assert.equal(rby, MADMIN.authId, 'reviewed_by attributes to the money-admin');
  assert.equal(rreason, REASON, 'review_reason captured');
  // `(max(reviewed_at) is not null)` is concatenated with `||`, so Postgres renders the boolean as
  // 'true'/'false' (booltext), NOT the standalone 't'/'f' (boolout).
  assert.equal(rat, 'true', 'reviewed_at set');

  // Exactly one window-keyed risk_flag (impression_id NULL) for the reason.
  const flag = psql(`select count(*)||'|'||coalesce(max((impression_id is null)::text),'') from public.risk_flags where window_id='${winId}' and reason='${REASON.replace(/'/g, "''")}';`);
  const [fc, fnull] = flag.split('|');
  assert.equal(fc, '1', 'exactly one window-keyed risk_flag');
  // `(impression_id is null)::text` casts the boolean to 'true'/'false' (booltext), not 't'/'f'.
  assert.equal(fnull, 'true', 'the flag is window-keyed (impression_id NULL)');

  // One append-only audit row for the window action, with refund_required + impression in the payload.
  const audit = psql(`select count(*)||'|'||coalesce(max(actor_aal),'')||'|'||coalesce(max(target_type),'')||'|'||coalesce(max(payload->>'refund_required'),'')||'|'||coalesce(max(payload->>'impression_id'),'')
    from app.admin_action_log where actor='${MADMIN.authId}' and action='admin_open_clawback' and target_id='${winId}';`);
  const [ac, aal, ttype, arefund, aimp] = audit.split('|');
  assert.equal(ac, '1', 'exactly one audit row for the window action');
  assert.equal(aal, 'aal2', 'actor_aal recorded from the JWT');
  assert.equal(ttype, 'window', 'target_type=window');
  assert.equal(arefund, 'true', 'refund_required captured in the audit payload');
  assert.equal(aimp, impId, 'impression_id captured in the audit payload');

  assert.ok(payable(pubId) >= 0, 'payable must remain >= 0 after the call');
});

// ---------------------------------------------------------------------------
// AC2 — money-safety: a PAID/covered earning is REFUSED by the per-earning paid-watermark
// (app.impression_earning_paid) BEFORE any mutation; zero mutation persists.
// ---------------------------------------------------------------------------
test('AC2: aged cleared PAID earning → refused (earning_already_paid), zero mutation persists', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId, winId, grp } = addImpression(pubId, { gross: 1_000_000, ageDays: 10 }); // matured; earning 600k
  addPaidPayout(pubId, 600_000);                                                          // fully covered by a paid payout

  const before = payable(pubId);
  assert.ok(before >= 0, `payable must be >= 0 before (got ${before})`);

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  // The FIFO paid-watermark refuses a paid earning up front — a clean {ok:false}, not a RAISE.
  assert.ok(res.ok, `paid-earning refusal returns 200 with ok:false, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, false);
  assert.equal(res.data?.reason, 'earning_already_paid', 'a paid earning is refused by the watermark');

  // ZERO mutation: impression cleared, ledger cleared, no review, no audit (refused before effect).
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'cleared', 'impression unchanged (still cleared)');
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id='${grp}' and state <> 'cleared';`), '0', 'ledger group not reversed');
  assert.equal(psql(`select count(*) from public.clawback_reviews where impression_id='${impId}';`), '0', 'no review row persisted');
  assert.equal(auditCount('admin_open_clawback', winId), 0, 'no audit row (refused before effect)');
  assert.ok(payable(pubId) >= 0, 'payable must remain >= 0 after the refused call');
});

// ---------------------------------------------------------------------------
// AC2b — money-safety, TWO earnings: the aggregate publisher_payable>=0 post-condition ALONE is
// insufficient. Publisher holds A (paid, oldest) AND B (unpaid, newer, B>=A). Clawing back A keeps
// aggregate payable >= 0 (B covers the drop), yet A is already PAID — the per-earning watermark
// must refuse A while still allowing the genuinely-unpaid B.
// ---------------------------------------------------------------------------
test('AC2b: a PAID earning is refused even when other unpaid balance keeps aggregate payable >= 0', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  // A: oldest (10d), matured, pub-share 600k — included in a completed (paid) payout.
  const A = addImpression(pubId, { gross: 1_000_000, ageDays: 10 });
  addPaidPayout(pubId, 600_000);
  // B: newer (8d), matured, pub-share 600k — UNPAID.
  const B = addImpression(pubId, { gross: 1_000_000, ageDays: 8 });

  // earned = 1.2M, paid = 600k → aggregate payable = 600k >= 0. The aggregate-only check would COMMIT
  // a clawback of A here; the per-earning watermark must not.
  assert.equal(payable(pubId), 600_000, 'aggregate payable is 600k (A paid, B unpaid)');

  // Clawing back the PAID earning A is refused by the watermark (cum-older(A)=0 < paid=600k).
  const resA = await rpc('admin_open_clawback', { p_impression_id: A.impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(resA.ok, `refusal returns 200, got ${resA.status}: ${JSON.stringify(resA.data)}`);
  assert.equal(resA.data?.ok, false);
  assert.equal(resA.data?.reason, 'earning_already_paid', 'the PAID earning A must be refused');
  assert.equal(psql(`select state from public.impressions where id='${A.impId}';`), 'cleared', "A's impression stays cleared");
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id='${A.grp}' and state <> 'cleared';`), '0', "A's ledger stays cleared");

  // The genuinely-UNPAID earning B is still allowed (cum-older(B)=600k is NOT < paid=600k).
  const resB = await rpc('admin_open_clawback', { p_impression_id: B.impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(resB.ok && resB.data?.ok === true, `unpaid B must be allowed, got ${resB.status}: ${JSON.stringify(resB.data)}`);
  assert.equal(psql(`select state from public.impressions where id='${B.impId}';`), 'clawed_back', 'B clawed_back');

  // A remains untouched and paid; payable stays >= 0 (now 0: only A's paid earning remains).
  assert.equal(psql(`select state from public.impressions where id='${A.impId}';`), 'cleared', 'A still cleared after B reversed');
  const resA2 = await rpc('admin_open_clawback', { p_impression_id: A.impId, p_reason: REASON }, MADMIN_JWT);
  assert.equal(resA2.data?.reason, 'earning_already_paid', 'A is still refused as paid after B is reversed');
  assert.ok(payable(pubId) >= 0, 'payable stays >= 0 throughout');
});

// ---------------------------------------------------------------------------
// AC3 — over-conservatism fix: aged (>7d) cleared but UNPAID earning is allowed in-dashboard.
// ---------------------------------------------------------------------------
test('AC3: aged cleared UNPAID earning is allowed (payable stays >= 0)', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId, grp } = addImpression(pubId, { gross: 1_000_000, ageDays: 10 }); // matured, unpaid

  const before = payable(pubId);
  assert.equal(before, 600_000, 'the matured unpaid earning is payable before the call');

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(res.ok, `aged-but-unpaid clawback must be allowed, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'clawed_back', 'impression clawed_back');
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id='${grp}' and state='reversed';`), '3', 'ledger group reversed');
  assert.equal(payable(pubId), 0, 'payable drops to 0 (nothing left uncovered); stays >= 0');
});

// ---------------------------------------------------------------------------
// AC4 — active payout for the publisher → refuse, no effect.
// ---------------------------------------------------------------------------
test('AC4: active (pending) payout → {ok:false,reason:payout_active}, no effect', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId, grp } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });
  addPendingPayout(pubId, 25_000_000);

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(res.ok, `refusal returns 200 with ok:false, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, false);
  assert.equal(res.data?.reason, 'payout_active');
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'cleared', 'impression untouched');
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id='${grp}' and state <> 'cleared';`), '0', 'ledger untouched');
  assert.equal(psql(`select count(*) from public.clawback_reviews where impression_id='${impId}';`), '0', 'no review created');
});

// ---------------------------------------------------------------------------
// AC5 — window carrying a succeeded CPC charge → refuse (no refund path), no effect.
// ---------------------------------------------------------------------------
test('AC5: window with a succeeded CPC charge → {ok:false,reason:cpc_charge_present_no_refund_path}', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId, winId, grp: cpvaGrp } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });
  const { clickId, grp: cpcGrp } = addClick(pubId, winId, { gross: 500_000, ageDays: 1 });
  addCharge({ grp: cpcGrp, impressionId: null, amountMicros: 500_000, status: 'succeeded' }); // CPC → un-refundable

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(res.ok, `refusal returns 200 with ok:false, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, false);
  assert.equal(res.data?.reason, 'cpc_charge_present_no_refund_path');
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'cleared', 'impression untouched');
  assert.equal(psql(`select state from public.clicks where id='${clickId}';`), 'cleared', 'click untouched');
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id in ('${cpvaGrp}','${cpcGrp}') and state <> 'cleared';`), '0', 'no ledger reversed');
});

// ---------------------------------------------------------------------------
// AC6 — idempotency: already_clawed_back; review_exists; unique index rejects a dup review.
// ---------------------------------------------------------------------------
test('AC6a: second call on an already-clawed impression → already_clawed_back', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });

  const first = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.equal(first.data?.ok, true, `first call must succeed: ${JSON.stringify(first.data)}`);

  const second = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(second.ok, `second call returns 200 with ok:false, got ${second.status}`);
  assert.equal(second.data?.ok, false);
  assert.equal(second.data?.reason, 'already_clawed_back');
  assert.equal(psql(`select count(*) from public.clawback_reviews where impression_id='${impId}';`), '1', 'still exactly one review after the repeat');
});

test('AC6b: pre-existing non-rejected review → review_exists (no effect)', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId, winId, grp } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });
  // Seed a pending review (simulating a scan_ivt result) with its own risk_flag.
  const rfId = randomUUID();
  psql(`insert into public.risk_flags (id, impression_id, window_id, reason) values ('${rfId}','${impId}','${winId}','ivt:rate');`);
  psql(`insert into public.clawback_reviews (risk_flag_id, impression_id, status) values ('${rfId}','${impId}','pending');`);

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(res.ok, `refusal returns 200 with ok:false, got ${res.status}`);
  assert.equal(res.data?.ok, false);
  assert.equal(res.data?.reason, 'review_exists');
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'cleared', 'impression untouched');
  assert.equal(psql(`select count(*) from public.ledger_entries where entry_group_id='${grp}' and state <> 'cleared';`), '0', 'ledger untouched');
});

test('AC6c: the partial unique index rejects a second non-rejected review per impression', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId, winId } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });
  // First non-rejected review via the RPC.
  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.equal(res.data?.ok, true, `clawback must succeed: ${JSON.stringify(res.data)}`);

  // A direct INSERT of a second APPROVED review for the same impression must violate the index.
  const rfId = psql(`select id from public.risk_flags where window_id='${winId}' limit 1;`);
  const err = psqlExpectError(`insert into public.clawback_reviews (risk_flag_id, impression_id, status) values ('${rfId}','${impId}','approved');`);
  assert.match(err, /clawback_reviews_one_active_per_impression|duplicate key|unique/i,
    `a second non-rejected review must be rejected by the partial unique index, got: ${err || 'no error'}`);
});

// ---------------------------------------------------------------------------
// AC7 — sentinel/gross<=0 → no-op, no ledger/review, but an audit row.
// ---------------------------------------------------------------------------
test('AC7: sentinel (gross=0) → {ok:true,reason:no_op_gross_zero}, no ledger/review, but audited', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId } = addImpression(pubId, { gross: 0, ageDays: 1 }); // sentinel: no ledger group booked

  const res = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MADMIN_JWT);
  assert.ok(res.ok, `sentinel no-op returns 200, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(res.data?.reason, 'no_op_gross_zero');
  assert.equal(psql(`select count(*) from public.clawback_reviews where impression_id='${impId}';`), '0', 'no review row for a sentinel no-op');
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'cleared', 'sentinel impression unchanged');
  // The gross-zero no-op still writes ONE audit row (target_type=impression, no_op payload).
  const audit = psql(`select count(*)||'|'||coalesce(max(target_type),'')||'|'||coalesce(max(payload->>'no_op'),'')
    from app.admin_action_log where actor='${MADMIN.authId}' and action='admin_open_clawback' and target_id='${impId}';`);
  const [ac, ttype, noop] = audit.split('|');
  assert.equal(ac, '1', 'exactly one audit row for the sentinel no-op');
  assert.equal(ttype, 'impression', 'target_type=impression for the no-op');
  assert.equal(noop, 'gross_zero', 'no_op reason captured in the payload');
});

// ---------------------------------------------------------------------------
// AC8 — authz + input guards.
// ---------------------------------------------------------------------------
test('AC8: authz — aal1 money-member, aal2 non-member, anon are all refused', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });

  const aal1 = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, MONEY_AAL1_JWT);
  assert.ok(!aal1.ok && aal1.status >= 400, `aal1 money-member must be refused, got ${aal1.status}: ${JSON.stringify(aal1.data)}`);

  const nonmember = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, NONMEMBER_JWT);
  assert.ok(!nonmember.ok && nonmember.status >= 400, `aal2 non-member must be refused, got ${nonmember.status}`);

  const anon = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: REASON }, null);
  assert.ok(!anon.ok, `anon EXECUTE must be revoked, got ${anon.status}`);

  // None of the refused calls touched the impression.
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'cleared', 'impression untouched by refused calls');
});

test('AC8b: empty reason and unknown impression are refused (for a money-admin)', { skip: SKIP }, async () => {
  const { pubId } = newPublisher();
  const { impId } = addImpression(pubId, { gross: 1_000_000, ageDays: 1 });

  const emptyReason = await rpc('admin_open_clawback', { p_impression_id: impId, p_reason: '   ' }, MADMIN_JWT);
  assert.ok(!emptyReason.ok, `empty reason must be refused, got ${emptyReason.status}: ${JSON.stringify(emptyReason.data)}`);
  assert.equal(psql(`select state from public.impressions where id='${impId}';`), 'cleared', 'empty-reason call left the impression untouched');

  const unknown = await rpc('admin_open_clawback', { p_impression_id: randomUUID(), p_reason: REASON }, MADMIN_JWT);
  assert.ok(!unknown.ok, `unknown impression must be refused, got ${unknown.status}: ${JSON.stringify(unknown.data)}`);
});
