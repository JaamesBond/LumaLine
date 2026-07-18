// test/advertiser-prepay.integration.mjs — M9-T2: advertiser prepay balance + money primitives.
//
// 20260716170000_advertiser_prepay_balance.sql is the prepay money core. These tests drive its
// app-schema SECDEF primitives directly via psql (service_role-only; psql connects as the owner,
// which bypasses the EXECUTE grants) and the public advertiser_balance_summary() via PostgREST with
// a session JWT. Self-skips if the local Supabase stack or psql is unavailable, and no-ops entirely
// if the migration has not been applied (advertiser_balances absent).
//
// WHAT IS TESTED (money-safety invariants):
//   D1  — deposit credit is idempotent on pi_id; the deposit group is zero-sum; topup_intent flips
//   R1  — advertiser_reserve is a guarded AVAILABLE hold; over-reserve past balance is refused
//   R2  — advertiser_release never drives reserved negative
//   C1  — CONCURRENCY: a burst of concurrent reserves for one advertiser never over-reserves past
//         balance and reserved never exceeds balance (the FOR-UPDATE / guarded-UPDATE serialization)
//   W1  — draw_down_batch draws atomically, zeroes the drawn windows' reserve, books a zero-sum
//         netting group, and is idempotent on charge_batch_id (retry never double-spends)
//   W2  — insufficient balance draws NOTHING and fires a LOUD 'critical' solvency alarm
//   W3  — reserved < sum still draws (balance covers) but fires a LOUD 'high' reserved_underflow alarm
//   B1  — chargeback-after-spend: reclaim=min(R,bal), bad_debt=max(0,R-bal), balance clamps at 0
//         (never negative), bad_debt leg booked, line_items paused, idempotent on dispute_id, and
//         the full BALANCE identity (balance == -SUM(advertiser_funds) == deposits-draws-reclaim)
//         reconciles to 0 end-to-end
//   K1  — reconcile_reserved corrects a drifted cache to SUM(ad_windows.reserve_micros) under lock
//   S1  — advertiser_balance_summary() self-scopes and returns balance/available/lifetime figures
//   N1  — the two CHECK(>=0) are structural: a direct negative balance/reserved write is rejected

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);
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
// One value from a jsonb-returning expression, JSON-parsed.
function psqlJson(sql) { return JSON.parse(psql(sql)); }
// Run a statement expected to FAIL; return the DB error text (stderr) or null if it unexpectedly succeeded.
function psqlError(sql) {
  try { psql(sql); return null; }
  catch (e) { return String(e?.stderr ?? e?.message ?? e); }
}
// Async single psql invocation (own connection) — used for the concurrency burst.
async function psqlAsync(sql) {
  const { stdout } = await execFileP('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8' });
  return stdout.trim();
}

async function rpc(fnName, body, jwt) {
  const token = jwt ?? ANON;
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, {
    method: 'POST',
    headers: { apikey: ANON, Authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const HAS_MIGRATION = PSQL_OK && psql(`select to_regclass('public.advertiser_balances') is not null;`) === 't';
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !HAS_MIGRATION ? 'advertiser_balances absent (migration not applied) — SKIPPING'
  : false;
if (SKIP) console.log(`[advertiser-prepay.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixtures. One shared publisher/device/auth identity backs every seeded ad_window; each test mints
// its own advertiser (fresh org + campaign + line_item + zero balance row) for isolation.
// ---------------------------------------------------------------------------
const PUB = { authId: randomUUID(), pubId: randomUUID(), deviceId: randomUUID() };
PUB.email  = `advp-pub-${PUB.authId}@example.com`;
PUB.handle = `advp-pub-${PUB.pubId.slice(0, 8)}`;

const MAP = { authId: randomUUID() };   // an auth identity mapped to an advertiser (summary RPC)
MAP.email = `advp-map-${MAP.authId}@example.com`;
const MAP_JWT = mintJwt(MAP.authId);

const advIds = [];   // every advertiser we create (teardown)

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')
    on conflict (id) do nothing;`);
}

// Create a fresh prepay advertiser with a campaign + line_item + balance row. Returns ids.
function seedAdvertiser({ balance = 0, reserved = 0, liStatus = 'active' } = {}) {
  const advId = randomUUID(), campId = randomUUID(), liId = randomUUID();
  psql(`insert into public.advertisers (id, name, status, billing_mode, is_house)
        values ('${advId}', 'Prepay ${advId.slice(0, 8)}', 'active', 'prepay', false);`);
  psql(`insert into public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
        values ('${advId}', ${balance}, ${reserved});`);
  psql(`insert into public.campaigns (id, advertiser_id, name, status)
        values ('${campId}', '${advId}', 'camp', 'active');`);
  psql(`insert into public.line_items (id, campaign_id, cpva_bid_micros, status)
        values ('${liId}', '${campId}', 5000, '${liStatus}');`);
  advIds.push(advId);
  return { advId, campId, liId };
}

function setBalance(advId, balance, reserved) {
  psql(`update public.advertiser_balances set balance_micros=${balance}, reserved_micros=${reserved} where advertiser_id='${advId}';`);
}
function getBalance(advId) {
  const [b, r] = psql(`select balance_micros||'|'||reserved_micros from public.advertiser_balances where advertiser_id='${advId}';`).split('|');
  return { balance: Number(b), reserved: Number(r) };
}

// Seed an ad_window with a reserve; optionally an impression + advertiser_charge under a batch.
function seedWindow(liId, reserveMicros, { batchId = null, chargeAmount = null } = {}) {
  const windowId = randomUUID();
  psql(`insert into public.ad_windows (window_id, publisher_id, device_id, line_item_id, challenge, nonce, reserve_micros, state)
        values ('${windowId}', '${PUB.pubId}', '${PUB.deviceId}', '${liId}', 'ch', 'no', ${reserveMicros}, 'credited');`);
  let impId = null;
  if (batchId && chargeAmount != null) {
    impId = randomUUID();
    psql(`insert into public.impressions (id, window_id, publisher_id, line_item_id, gross_micros, state)
          values ('${impId}', '${windowId}', '${PUB.pubId}', '${liId}', ${chargeAmount}, 'cleared');`);
    const cents = Math.round(chargeAmount / 10000);
    psql(`insert into public.advertiser_charges (entry_group_id, advertiser_id, impression_id, amount_micros, amount_cents, status, charge_batch_id)
          select '${randomUUID()}', c.advertiser_id, '${impId}', ${chargeAmount}, ${cents}, 'pending', '${batchId}'
          from public.line_items li join public.campaigns c on c.id=li.campaign_id where li.id='${liId}';`);
  }
  return { windowId, impId };
}

// Sum of the amount_micros of every ledger group touching this advertiser must be 0 per group.
function allGroupsBalanced(advId) {
  return psql(`select coalesce(bool_and(s=0), true) from (
      select entry_group_id, sum(amount_micros) s from public.ledger_entries
      where entry_group_id in (select distinct entry_group_id from public.ledger_entries where advertiser_id='${advId}')
      group by entry_group_id) g;`) === 't';
}
function sumLeg(advId, account) {
  return Number(psql(`select coalesce(sum(amount_micros),0) from public.ledger_entries where advertiser_id='${advId}' and account='${account}';`));
}
function openAlertCount(check, advId) {
  return Number(psql(`select count(*) from app.alert_events where check_name='${check}' and dedup_key='${check}:${advId}' and status='open';`));
}

function teardown() {
  try {
    const ids = advIds.map((x) => `'${x}'`).join(',');
    const parts = [`set session_replication_role = replica;`];   // disable triggers + FK checks for cleanup
    if (ids) {
      parts.push(`delete from public.advertiser_balance_ledger where advertiser_id in (${ids});`);
      parts.push(`delete from public.ledger_entries where advertiser_id in (${ids});`);
      parts.push(`delete from public.advertiser_charges where advertiser_id in (${ids});`);
      parts.push(`delete from public.advertiser_topup_intents where advertiser_id in (${ids});`);
      parts.push(`delete from public.advertiser_balances where advertiser_id in (${ids});`);
    }
    parts.push(`delete from public.impressions where publisher_id='${PUB.pubId}';`);
    parts.push(`delete from public.ad_windows where publisher_id='${PUB.pubId}';`);
    if (ids) {
      parts.push(`delete from public.advertiser_users where advertiser_id in (${ids});`);
      parts.push(`delete from public.advertisers where id in (${ids});`);
    }
    parts.push(`delete from public.devices where id='${PUB.deviceId}';`);
    parts.push(`delete from public.publishers where id='${PUB.pubId}';`);
    parts.push(`delete from auth.users where id in ('${PUB.authId}','${MAP.authId}');`);
    parts.push(`delete from app.alert_events where check_name in ('advertiser_insufficient_balance','advertiser_reserved_underflow')
                  and split_part(dedup_key,':',2) in (${ids || `''`});`);
    parts.push(`reset session_replication_role;`);
    psql(parts.join('\n'));
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedUser(PUB.authId, PUB.email);
  seedUser(MAP.authId, MAP.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, status) values ('${PUB.pubId}', '${PUB.authId}', '${PUB.handle}', 'active');`);
  psql(`insert into public.devices (id, publisher_id) values ('${PUB.deviceId}', '${PUB.pubId}');`);
  process.on('exit', teardown);
}

// ---------------------------------------------------------------------------
test('D1: deposit credit is idempotent on pi_id; group zero-sum; intent flips', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser();
  const sess = `sess_${advId.slice(0, 8)}`, pi = `pi_${advId.slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros)
        values ('${sess}', '${advId}', 100000000);`);

  const r1 = psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','evt_1',100000000);`);
  assert.equal(r1.credited, true, 'first credit succeeds');
  assert.equal(getBalance(advId).balance, 100000000, 'balance credited by the deposit');

  // Replay the SAME pi_id (a re-delivered webhook) with a different event id.
  const r2 = psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','evt_2',100000000);`);
  assert.equal(r2.credited, false, 'replay must not credit');
  assert.equal(r2.reason, 'duplicate');
  assert.equal(getBalance(advId).balance, 100000000, 'balance credited EXACTLY once');

  assert.equal(psql(`select status from public.advertiser_topup_intents where checkout_session_id='${sess}';`), 'credited');
  assert.ok(allGroupsBalanced(advId), 'the deposit ledger group sums to 0');
  // BALANCE identity: balance == -SUM(advertiser_funds legs) (deposit booked funds -D).
  assert.equal(-sumLeg(advId, 'advertiser_funds'), 100000000, 'held liability equals the balance');
  assert.equal(sumLeg(advId, 'platform_cash'), 100000000, 'cash-in leg present');
});

test('D1b: a positive amount is required; a zero/negative deposit raises', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser();
  const err = psqlError(`select app.advertiser_credit_deposit('${advId}','s','pi_z','e',0);`);
  assert.match(err ?? '', /amount must be positive/, 'zero deposit is rejected');
  assert.equal(getBalance(advId).balance, 0);
});

test('R1: advertiser_reserve is a guarded AVAILABLE hold; over-reserve is refused', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser({ balance: 100000000 });
  assert.equal(psql(`select app.advertiser_reserve('${advId}', 30000000);`), 't');
  assert.equal(psql(`select app.advertiser_reserve('${advId}', 30000000);`), 't');
  assert.equal(psql(`select app.advertiser_reserve('${advId}', 30000000);`), 't');
  assert.equal(getBalance(advId).reserved, 90000000, 'three holds of 30 taken');
  // available = 100 - 90 = 10 < 30 → refused, reserved unchanged.
  assert.equal(psql(`select app.advertiser_reserve('${advId}', 30000000);`), 'f', 'over-reserve past AVAILABLE refused');
  assert.equal(getBalance(advId).reserved, 90000000, 'a refused reserve does not mutate reserved');
  assert.ok(getBalance(advId).reserved <= getBalance(advId).balance, 'reserved never exceeds balance');
});

test('R2: advertiser_release never drives reserved negative', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser({ balance: 100000000, reserved: 20000000 });
  psql(`select app.advertiser_release('${advId}', 50000000);`);   // release more than held
  assert.equal(getBalance(advId).reserved, 0, 'reserved clamps at 0, never negative');
});

test('C1: concurrent reserves never over-reserve past balance', { skip: SKIP }, async () => {
  const { advId } = seedAdvertiser({ balance: 90000000 });
  // 8 concurrent reserves of 30 against a balance of 90 → EXACTLY 3 may succeed (row-lock serialized).
  const results = await Promise.all(
    Array.from({ length: 8 }, () => psqlAsync(`select app.advertiser_reserve('${advId}', 30000000);`)));
  const wins = results.filter((r) => r === 't').length;
  assert.equal(wins, 3, `exactly 3 of 8 concurrent reserves win, got ${wins}`);
  const { balance, reserved } = getBalance(advId);
  assert.equal(reserved, 90000000, 'reserved settles at exactly balance');
  assert.ok(reserved <= balance, 'reserved never exceeds balance under concurrency');
});

test('W1: draw_down_batch draws atomically, zeroes windows, zero-sum, idempotent', { skip: SKIP }, () => {
  const { advId, liId } = seedAdvertiser({ balance: 100000000, reserved: 50000000 });
  const batch = randomUUID();
  const w1 = seedWindow(liId, 25000000, { batchId: batch, chargeAmount: 25000000 });
  const w2 = seedWindow(liId, 25000000, { batchId: batch, chargeAmount: 25000000 });

  const d1 = psqlJson(`select app.advertiser_draw_down_batch('${advId}','${batch}',50000000);`);
  assert.equal(d1.drawn, true);
  assert.equal(d1.amount_micros, 50000000);
  const bal = getBalance(advId);
  assert.equal(bal.balance, 50000000, 'balance drawn down by the batch sum');
  assert.equal(bal.reserved, 0, 'reserved released by the batch sum');
  // The drawn windows' reserve is zeroed so reconcile's SUM excludes them.
  assert.equal(psql(`select coalesce(sum(reserve_micros),0) from public.ad_windows where window_id in ('${w1.windowId}','${w2.windowId}');`), '0');
  assert.ok(allGroupsBalanced(advId), 'the draw-down netting group sums to 0');
  assert.equal(sumLeg(advId, 'advertiser_billing'), -50000000, 'receivable netted (Cr advertiser_billing -sum)');

  // Idempotent: a retry/recovery of the SAME batch is a no-op.
  const d2 = psqlJson(`select app.advertiser_draw_down_batch('${advId}','${batch}',50000000);`);
  assert.equal(d2.drawn, false);
  assert.equal(d2.reason, 'duplicate');
  assert.equal(getBalance(advId).balance, 50000000, 'a duplicate draw never double-spends');
});

test('W2: insufficient balance draws nothing + fires a critical solvency alarm', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser({ balance: 10000000 });
  const batch = randomUUID();
  const d = psqlJson(`select app.advertiser_draw_down_batch('${advId}','${batch}',50000000);`);
  assert.equal(d.drawn, false);
  assert.equal(d.reason, 'insufficient_balance');
  assert.equal(getBalance(advId).balance, 10000000, 'balance untouched when uncovered');
  assert.ok(openAlertCount('advertiser_insufficient_balance', advId) >= 1, 'a loud solvency alarm fired');
});

test('W3: reserved < sum still draws (balance covers) but fires reserved_underflow', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser({ balance: 100000000, reserved: 10000000 });
  const batch = randomUUID();
  const d = psqlJson(`select app.advertiser_draw_down_batch('${advId}','${batch}',40000000);`);
  assert.equal(d.drawn, true, 'balance covers the draw even though reserved is short');
  assert.equal(getBalance(advId).reserved, 0, 'reserved clamps at 0');
  assert.equal(getBalance(advId).balance, 60000000);
  assert.ok(openAlertCount('advertiser_reserved_underflow', advId) >= 1, 'the drift is surfaced, not swallowed');
});

test('B1: chargeback-after-spend → bad-debt, balance clamps at 0, pause, idempotent, reconciles', { skip: SKIP }, () => {
  const { advId, liId } = seedAdvertiser({ liStatus: 'active' });
  const sess = `cbsess_${advId.slice(0, 8)}`, pi = `cbpi_${advId.slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros) values ('${sess}','${advId}',100000000);`);

  // Deposit €100.
  psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','cbe',100000000);`);
  assert.equal(getBalance(advId).balance, 100000000);

  // Spend €70 (real draw-down of a seeded batch; reserved is held then released).
  setBalance(advId, 100000000, 70000000);
  const batch = randomUUID();
  seedWindow(liId, 35000000, { batchId: batch, chargeAmount: 35000000 });
  seedWindow(liId, 35000000, { batchId: batch, chargeAmount: 35000000 });
  const d = psqlJson(`select app.advertiser_draw_down_batch('${advId}','${batch}',70000000);`);
  assert.equal(d.drawn, true);
  assert.equal(getBalance(advId).balance, 30000000, 'balance 100 - 70 = 30 after spend');

  // Dispute the €100 deposit AFTER €70 was already delivered.
  const cb = psqlJson(`select app.advertiser_apply_deposit_reversal('${advId}','dp_${advId.slice(0,8)}',100000000);`);
  assert.equal(cb.reversed, true);
  assert.equal(cb.reclaimed_micros, 30000000, 'reclaim = min(R, balance) = 30');
  assert.equal(cb.bad_debt_micros, 70000000, 'bad_debt = max(0, R - balance) = 70');
  assert.equal(getBalance(advId).balance, 0, 'balance clamps at 0 — NEVER negative');

  assert.equal(sumLeg(advId, 'advertiser_bad_debt'), 70000000, 'the platform write-off is booked + surfaced');
  assert.ok(allGroupsBalanced(advId), 'the chargeback group sums to 0');

  // The advertiser is paused (a disputed deposit funds no further delivery).
  assert.equal(psql(`select status from public.line_items where id='${liId}';`), 'paused', 'active line_items paused');

  // Idempotent on dispute_id.
  const cb2 = psqlJson(`select app.advertiser_apply_deposit_reversal('${advId}','dp_${advId.slice(0,8)}',100000000);`);
  assert.equal(cb2.reversed, false);
  assert.equal(cb2.reason, 'duplicate');
  assert.equal(getBalance(advId).balance, 0, 'a re-delivered dispute never double-reverses');

  // END-TO-END BALANCE identity: balance == -SUM(advertiser_funds) == deposits - draws - reclaimed == 0.
  // Assert balance + funds-legs == 0 (algebraically identical to balance == -funds-legs) to avoid the JS
  // -0 vs 0 strict-equality artifact (Object.is(0, -0) is false) when both sides are zero.
  assert.equal(getBalance(advId).balance + sumLeg(advId, 'advertiser_funds'), 0,
    'balance reconciles to the held-liability legs');
  assert.equal(sumLeg(advId, 'advertiser_funds'), 0, 'position fully unwound (100 - 70 draw - 30 reclaim)');
});

test('B2: dispute BEFORE spend (R <= balance) → bad_debt=0, exactly TWO legs, zero-sum', { skip: SKIP }, () => {
  // The common "dispute a fresh, unspent deposit" path — the `IF v_bad > 0` branch SKIPS the
  // advertiser_bad_debt leg, so the group has exactly two legs and still sums to 0.
  const { advId } = seedAdvertiser({ liStatus: 'active' });
  const sess = `b2s_${advId.slice(0, 8)}`, pi = `b2pi_${advId.slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros) values ('${sess}','${advId}',100000000);`);
  psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','${pi}','b2e',100000000);`);
  assert.equal(getBalance(advId).balance, 100000000);

  const disp = `b2_${advId.slice(0, 8)}`;
  const cb = psqlJson(`select app.advertiser_apply_deposit_reversal('${advId}','${disp}',100000000);`);
  assert.equal(cb.reversed, true);
  assert.equal(cb.reclaimed_micros, 100000000, 'reclaim = min(R, balance) = full 100');
  assert.equal(cb.bad_debt_micros, 0, 'bad_debt = max(0, R - balance) = 0');
  assert.equal(getBalance(advId).balance, 0, 'balance clamps to 0');
  assert.equal(sumLeg(advId, 'advertiser_bad_debt'), 0, 'no bad_debt leg booked when the deposit was unspent');
  // The chargeback ledger group has EXACTLY two legs (platform_cash + advertiser_funds), summing to 0.
  const legCount = psql(`select count(*) from public.ledger_entries le
    where le.entry_group_id = (select entry_group_id from public.advertiser_balance_ledger
      where advertiser_id='${advId}' and dispute_id='${disp}');`);
  assert.equal(legCount, '2', 'exactly two legs when bad_debt=0 (no spurious 0-amount bad_debt row)');
  assert.ok(allGroupsBalanced(advId), 'the two-leg chargeback group sums to 0');
});

test('B3: reversal against an advertiser with NO balance row → full amount is bad_debt, balance stays 0', { skip: SKIP }, () => {
  // The no-balance-row upsert path: v_bal COALESCEs to 0, so reclaim=0 and the whole R is bad debt;
  // the balance row is created clamped at 0 (never negative).
  const advId = randomUUID();
  psql(`insert into public.advertisers (id, name, status, billing_mode, is_house)
        values ('${advId}', 'NoBal ${advId.slice(0, 8)}', 'active', 'prepay', false);`);
  advIds.push(advId);
  // Intentionally NO advertiser_balances row seeded.
  const disp = `b3_${advId.slice(0, 8)}`;
  const cb = psqlJson(`select app.advertiser_apply_deposit_reversal('${advId}','${disp}',40000000);`);
  assert.equal(cb.reversed, true);
  assert.equal(cb.reclaimed_micros, 0, 'nothing to reclaim without a balance');
  assert.equal(cb.bad_debt_micros, 40000000, 'the full amount is a platform write-off');
  assert.equal(getBalance(advId).balance, 0, 'the created balance row is clamped at 0');
  assert.equal(sumLeg(advId, 'advertiser_bad_debt'), 40000000, 'bad_debt surfaced');
  assert.ok(allGroupsBalanced(advId), 'the reversal group still sums to 0');
});

test('K1: reconcile_reserved corrects a drifted cache to SUM(reserve_micros) under lock', { skip: SKIP }, () => {
  const { advId, liId } = seedAdvertiser({ balance: 100000000, reserved: 999 /* WRONG */ });
  seedWindow(liId, 20000000);
  seedWindow(liId, 15000000);   // authoritative SUM = 35000000
  const r = psqlJson(`select app.advertiser_reconcile_reserved('${advId}');`);
  assert.equal(r.changed, true);
  assert.equal(r.reserved_after, 35000000, 'reserved recomputed from the windows');
  assert.equal(getBalance(advId).reserved, 35000000, 'cache corrected');
  assert.equal(psql(`select count(*) from public.advertiser_balance_ledger where advertiser_id='${advId}' and kind='reserve_reconcile';`), '1');
});

test('S1: advertiser_balance_summary self-scopes + returns balance/available/lifetime', { skip: SKIP }, async () => {
  const { advId } = seedAdvertiser();
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role) values ('${MAP.authId}','${advId}','owner');`);
  const sess = `smsess_${advId.slice(0, 8)}`;
  psql(`insert into public.advertiser_topup_intents (checkout_session_id, advertiser_id, amount_micros) values ('${sess}','${advId}',80000000);`);
  psqlJson(`select app.advertiser_credit_deposit('${advId}','${sess}','smpi_${advId.slice(0,8)}','e',80000000);`);
  psql(`update public.advertiser_balances set reserved_micros=30000000 where advertiser_id='${advId}';`);

  const res = await rpc('advertiser_balance_summary', {}, MAP_JWT);
  assert.ok(res.ok, `summary failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data.balance_micros, 80000000);
  assert.equal(res.data.reserved_micros, 30000000);
  assert.equal(res.data.available_micros, 50000000, 'available = balance - reserved');
  assert.equal(res.data.lifetime_deposited_micros, 80000000);

  // A session mapped to NO advertiser is rejected (self-scope, no attacker id).
  const anon = await rpc('advertiser_balance_summary', {}, mintJwt(randomUUID()));
  assert.ok(!anon.ok, 'an unmapped session cannot read any balance');
});

test('N1: the CHECK(>=0) constraints are structural (a direct negative write is rejected)', { skip: SKIP }, () => {
  const { advId } = seedAdvertiser({ balance: 10000000 });
  const eb = psqlError(`update public.advertiser_balances set balance_micros=-1 where advertiser_id='${advId}';`);
  assert.match(eb ?? '', /balance_micros_check|violates check constraint/, 'negative balance rejected by CHECK');
  const er = psqlError(`update public.advertiser_balances set reserved_micros=-1 where advertiser_id='${advId}';`);
  assert.match(er ?? '', /reserved_micros_check|violates check constraint/, 'negative reserved rejected by CHECK');
});
