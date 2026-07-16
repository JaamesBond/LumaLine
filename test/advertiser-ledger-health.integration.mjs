// test/advertiser-ledger-health.integration.mjs — M9-T6: prepay ledger-health invariants + recon split.
//
// 20260716210000_advertiser_ledger_health_and_recon.sql ships public.advertiser_ledger_health() (the
// admin read that ASSERTS the prepay money invariants + counts drift), public.advertiser_health_sync()
// (drift alerting via monitor_sync_alerts), and the billing_recon_totals change that EXCLUDES prepay so
// GET /reconcile stays green. Driven via PostgREST (health as an admin session) + psql (service_role
// sync/recon + drift injection). Self-skips without stack/psql/the migration.
//
// Because advertiser_ledger_health() is a GLOBAL aggregate and `node --test` runs test files in
// parallel against the same DB (other files intentionally seed "drifted" advertisers), this suite
// asserts what holds at ANY snapshot: the per-advertiser identities are checked with SCOPED psql
// queries; the RPC is asserted for its admin gate, well-formed shape, and drift-detection DIRECTION
// (a count that is >= 1 and a boolean that flips false once THIS advertiser drifts); the drift alert
// is isolated by its per-advertiser dedup_key; the recon exclusion is checked with a scoped predicate.
//
// WHAT IS TESTED:
//   H1 — advertiser_ledger_health is admin-gated (non-admin 28000, anon revoked) + well-formed (keys/types)
//   H2 — BALANCE identity (balance == −SUM cleared advertiser_funds): holds per-advertiser after a
//        deposit; an injected cache bump breaks it AND the RPC counts the drift (balance_identity_ok false)
//   H3 — RESERVED identity (reserved == SUM ad_windows.reserve_micros): a wrong cache is drift; the RPC
//        counts it; app.advertiser_reconcile_reserved repairs it
//   H4 — advertiser_health_sync fires an OPEN drift alert for the advertiser, then RESOLVES it on recovery
//   H5 — the recon predicate EXCLUDES a prepay advertiser's cleared cpva accrual but INCLUDES a postpay one

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
  try { return psql("select (to_regprocedure('public.advertiser_ledger_health()') is not null and to_regprocedure('public.advertiser_health_sync()') is not null);") === 't'; }
  catch { return false; }
}

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const PRESENT  = PSQL_OK ? migrationPresent() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !PRESENT ? '20260716210000 not applied — SKIPPING'
  : false;
if (SKIP) console.log(`[advertiser-ledger-health.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
const ADMIN = { authId: randomUUID() };
const PLAIN = { authId: randomUUID() };   // a mapped advertiser session (non-admin) → health refused
const ADMIN_JWT = mintJwt(ADMIN.authId);
const PLAIN_JWT = mintJwt(PLAIN.authId);

const advIds = [];
const pubIds = [];
const authIds = [ADMIN.authId, PLAIN.authId];

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')
    on conflict (id) do nothing;`);
}

function seedAdvertiser({ billingMode = 'prepay', balance = 0, reserved = 0 } = {}) {
  const advId = randomUUID(), campId = randomUUID(), liId = randomUUID();
  psql(`insert into public.advertisers (id, name, status, billing_mode, is_house)
        values ('${advId}', 'Health ${advId.slice(0, 8)}', 'active', '${billingMode}', false);`);
  psql(`insert into public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
        values ('${advId}', ${balance}, ${reserved});`);
  psql(`insert into public.campaigns (id, advertiser_id, name, status) values ('${campId}','${advId}','camp','active');`);
  psql(`insert into public.line_items (id, campaign_id, cpva_bid_micros, cpc_bid_micros, status)
        values ('${liId}','${campId}',${billingMode === 'prepay' ? 5000 : 0},0,'active');`);
  advIds.push(advId);
  return { advId, campId, liId };
}
function seedPublisher() {
  const authId = randomUUID(), pubId = randomUUID(), deviceId = randomUUID();
  seedUser(authId, `hlth-p-${authId}@example.com`);
  psql(`insert into public.publishers (id, auth_user_id, handle, status) values ('${pubId}','${authId}','hp-${pubId.slice(0,8)}','active');`);
  psql(`insert into public.devices (id, publisher_id) values ('${deviceId}','${pubId}');`);
  authIds.push(authId); pubIds.push(pubId);
  return { pubId, deviceId };
}
// Cleared cpva impression + accrual (advertiser_billing +G, advertiser_id NULL — as app.accrue books).
function seedImpressionAccrual({ pubId, liId, gross }) {
  const impId = randomUUID(), winId = randomUUID(), grp = randomUUID();
  psql(`insert into public.impressions (id, window_id, publisher_id, line_item_id, attention_seconds, gross_micros, state, created_at)
        values ('${impId}','${winId}','${pubId}','${liId}',5,${gross},'cleared', now());`);
  const pub = Math.round(gross * 0.6), plat = gross - pub;
  psql(`insert into public.ledger_entries (entry_group_id,event_type,account,amount_micros,state,source_type,source_id,publisher_id) values
    ('${grp}','cpva_accrual','advertiser_billing',${gross},'cleared','impression','${impId}',null),
    ('${grp}','cpva_accrual','publisher_earnings',${-pub},'cleared','impression','${impId}','${pubId}'),
    ('${grp}','cpva_accrual','platform_revenue',${-plat},'cleared','impression','${impId}',null);`);
  return { impId, winId, grp };
}
function creditDeposit(advId, amount) {
  const sess = `hs_${randomUUID().slice(0, 8)}`, pi = `hpi_${randomUUID().slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros) values ('${sess}','${advId}',${amount});`);
  psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','${randomUUID()}',${amount});`);
}
// Per-advertiser BALANCE identity: balance_micros == −SUM(cleared advertiser_funds legs). 't'/'f'.
function balanceIdentityOk(advId) {
  return psql(`select (b.balance_micros = -coalesce((select sum(le.amount_micros) from public.ledger_entries le
      where le.advertiser_id='${advId}' and le.account='advertiser_funds' and le.state='cleared'),0))
      from public.advertiser_balances b where b.advertiser_id='${advId}';`) === 't';
}
async function health() {
  const r = await rpc('advertiser_ledger_health', {}, ADMIN_JWT);
  assert.ok(r.ok, `health failed: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
}

function teardown() {
  try {
    const parts = [`set session_replication_role = replica;`];
    const advs = advIds.map((x) => `'${x}'`).join(',');
    const pubs = pubIds.map((x) => `'${x}'`).join(',');
    if (pubs) {
      parts.push(`delete from public.ledger_entries where publisher_id in (${pubs}) or source_id in (select id from public.impressions where publisher_id in (${pubs}));`);
      parts.push(`delete from public.impressions where publisher_id in (${pubs});`);
      parts.push(`delete from public.ad_windows where publisher_id in (${pubs});`);
      parts.push(`delete from public.devices where publisher_id in (${pubs});`);
    }
    if (advs) {
      parts.push(`delete from public.ledger_entries where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_balance_ledger where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_topup_intents where advertiser_id in (${advs});`);
      parts.push(`delete from public.ad_windows where line_item_id in (select li.id from public.line_items li join public.campaigns c on c.id=li.campaign_id where c.advertiser_id in (${advs}));`);
      parts.push(`delete from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id in (${advs}));`);
      parts.push(`delete from public.campaigns where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_balances where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertiser_users where advertiser_id in (${advs});`);
      parts.push(`delete from public.advertisers where id in (${advs});`);
      parts.push(`delete from app.alert_events where check_name like 'advertiser_%' and split_part(dedup_key,':',2) in (${advs});`);
    }
    if (pubs) parts.push(`delete from public.publishers where id in (${pubs});`);
    parts.push(`delete from app.admins where auth_user_id='${ADMIN.authId}';`);
    parts.push(`delete from auth.users where id in (${authIds.map((a) => `'${a}'`).join(',')});`);
    parts.push(`reset session_replication_role;`);
    psql(parts.join('\n'));
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedUser(ADMIN.authId, `hlth-admin-${ADMIN.authId}@example.com`);
  seedUser(PLAIN.authId, `hlth-plain-${PLAIN.authId}@example.com`);
  psql(`insert into app.admins (auth_user_id) values ('${ADMIN.authId}') on conflict do nothing;`);
  // Map PLAIN to an advertiser so it's a real (non-admin) advertiser session for the gate test.
  const { advId } = seedAdvertiser();
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role) values ('${PLAIN.authId}','${advId}','owner');`);
  process.on('exit', teardown);
}

const KEYS = [
  'advertisers_count', 'total_balance_micros', 'total_reserved_micros', 'total_held_liability_micros',
  'total_bad_debt_micros', 'total_deposited_micros', 'total_drawn_micros',
  'balance_drift_count', 'reserved_drift_count', 'available_negative_count', 'balance_negative_count',
  'per_advertiser_unbalanced_count',
  'balance_identity_ok', 'reserved_identity_ok', 'solvency_ok', 'per_advertiser_zero_sum_ok',
  'held_liability_matches_balance',
];

// ---------------------------------------------------------------------------
test('H1: advertiser_ledger_health is admin-gated and well-formed', { skip: SKIP }, async () => {
  const plain = await rpc('advertiser_ledger_health', {}, PLAIN_JWT);
  assert.ok(!plain.ok && plain.status >= 400, 'a mapped non-admin advertiser session is refused');
  const anon = await rpc('advertiser_ledger_health', {}, null);
  assert.ok(!anon.ok, 'anon EXECUTE revoked');

  const d = await health();
  for (const k of KEYS) assert.ok(k in d, `missing key ${k}`);
  assert.equal(typeof d.balance_identity_ok, 'boolean');
  assert.equal(typeof d.reserved_identity_ok, 'boolean');
  assert.equal(typeof d.solvency_ok, 'boolean');
  assert.ok(Number.isFinite(Number(d.total_balance_micros)) && Number.isFinite(Number(d.balance_drift_count)));
});

test('H2: BALANCE identity holds per-advertiser after a deposit; a cache bump is detected as drift', { skip: SKIP }, async () => {
  const { advId } = seedAdvertiser();
  creditDeposit(advId, 30000000);
  assert.ok(balanceIdentityOk(advId), 'balance == −SUM(advertiser_funds) after a deposit');

  // Inject drift: bump the spendable cache WITHOUT a matching ledger leg.
  psql(`update public.advertiser_balances set balance_micros = balance_micros + 123456 where advertiser_id='${advId}';`);
  assert.ok(!balanceIdentityOk(advId), 'the identity now fails for this advertiser');
  const d = await health();
  assert.ok(Number(d.balance_drift_count) >= 1, 'the RPC counts at least the drifted advertiser');
  assert.equal(d.balance_identity_ok, false, 'balance_identity_ok is false while any advertiser drifts');

  // Correct it → the per-advertiser identity holds again.
  psql(`update public.advertiser_balances set balance_micros = balance_micros - 123456 where advertiser_id='${advId}';`);
  assert.ok(balanceIdentityOk(advId), 'identity restored after correction');
});

test('H3: RESERVED identity — a wrong cache is drift; reconcile repairs it to SUM(reserve_micros)', { skip: SKIP }, async () => {
  const { advId, liId } = seedAdvertiser({ balance: 100000000, reserved: 0 });
  const { pubId, deviceId } = seedPublisher();
  for (const amt of [5000000, 3000000]) {   // open windows holding 5M + 3M = 8M
    psql(`insert into public.ad_windows (window_id, publisher_id, device_id, line_item_id, challenge, nonce, reserve_micros, state)
          values ('${randomUUID()}','${pubId}','${deviceId}','${liId}','ch','no',${amt},'open');`);
  }
  // Cache is wrong (should be 8M).
  psql(`update public.advertiser_balances set reserved_micros = 999 where advertiser_id='${advId}';`);
  const d = await health();
  assert.ok(Number(d.reserved_drift_count) >= 1, 'the RPC counts the reserved drift');
  assert.equal(d.reserved_identity_ok, false, 'reserved_identity_ok flips false');

  // Reconcile recomputes reserved := SUM(ad_windows.reserve_micros) = 8M under the row lock.
  psqlJson(`select app.advertiser_reconcile_reserved('${advId}');`);
  assert.equal(psql(`select reserved_micros from public.advertiser_balances where advertiser_id='${advId}';`), '8000000', 'reserved corrected to the window sum');
});

test('H4: advertiser_health_sync fires an OPEN drift alert, then resolves it on recovery', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser();
  creditDeposit(advId, 20000000);
  const dedup = `advertiser_balance_drift:${advId}`;

  // Inject balance drift → sync fires a critical open alert for THIS advertiser.
  psql(`update public.advertiser_balances set balance_micros = balance_micros + 777 where advertiser_id='${advId}';`);
  psqlJson(`select public.advertiser_health_sync();`);
  assert.equal(psql(`select count(*) from app.alert_events where check_name='advertiser_balance_drift' and dedup_key='${dedup}' and status='open';`), '1',
    'a drift alert is OPEN for the advertiser');

  // Correct + re-run → THIS advertiser's alert is RESOLVED (no open row remains for its dedup_key).
  psql(`update public.advertiser_balances set balance_micros = balance_micros - 777 where advertiser_id='${advId}';`);
  psqlJson(`select public.advertiser_health_sync();`);
  assert.equal(psql(`select count(*) from app.alert_events where check_name='advertiser_balance_drift' and dedup_key='${dedup}' and status='open';`), '0',
    'the alert is resolved on recovery');
});

test('H5: the recon predicate EXCLUDES prepay accruals but INCLUDES postpay ones', { skip: SKIP }, () => {
  const { pubId } = seedPublisher();
  const pp = seedAdvertiser({ billingMode: 'postpay' });
  seedImpressionAccrual({ pubId, liId: pp.liId, gross: 3000000 });
  const pr = seedAdvertiser({ billingMode: 'prepay' });
  seedImpressionAccrual({ pubId, liId: pr.liId, gross: 7000000 });

  // Scoped to MY two advertisers (robust under parallel test files): the recon's exact predicate.
  const scoped = (extra) => Number(psql(`select coalesce(sum(le.amount_micros),0)
      from public.ledger_entries le
      join public.impressions i  on i.id  = le.source_id
      join public.line_items  li on li.id = i.line_item_id
      join public.campaigns   c  on c.id  = li.campaign_id
      join public.advertisers a  on a.id  = c.advertiser_id
      where le.account='advertiser_billing' and le.event_type='cpva_accrual' and le.state='cleared'
        and c.advertiser_id in ('${pp.advId}','${pr.advId}') ${extra};`));

  assert.equal(scoped(''), 10000000, 'both accruals exist (postpay 3M + prepay 7M)');
  assert.equal(scoped("and a.billing_mode is distinct from 'prepay'"), 3000000,
    'the recon predicate keeps ONLY the postpay 3M — prepay is excluded');

  // Smoke: the real RPC runs and returns a non-negative number (its total includes the postpay leg).
  const total = Number(psql(`select total_micros from public.billing_recon_totals(now() - interval '1 day', now() + interval '1 day');`));
  assert.ok(total >= 3000000, 'billing_recon_totals runs and reflects at least the postpay accrual');
});
