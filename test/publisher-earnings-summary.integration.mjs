// test/publisher-earnings-summary.integration.mjs — M7: portal earnings summary RPC.
//
// publisher_earnings_summary() returns {matured_micros, held_micros, lifetime_micros,
// paid_micros, balance_micros} for the CALLER's own publisher (derived from
// app.current_publisher_id()). `matured` reuses app.publisher_payable_micros(pid,'7 days')
// so the number the portal shows agrees with what a payout will actually pay; `held` is
// balance - matured; `lifetime` is gross cleared accrual earnings; `paid` is net of reversals.
//
// Setup via psql; RPC called with a per-publisher HS256 session JWT (sub = auth_user_id).
// Self-skips if the local stack or psql is unavailable.
//
// WHAT IS TESTED:
//   E1 — matured vs held split by impression age (10d old = matured, 1d old = held)
//   E2 — a payout reduces both `paid` and `matured`/`balance`; `held` and `lifetime` hold
//   E3 — isolation: A's summary excludes B; B's own summary returns B's figures
//   E4 — a session with no publisher row is rejected (unauthenticated)

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

async function summary(jwt) {
  const resp = await fetch(`${REST_BASE}/rpc/publisher_earnings_summary`, {
    method: 'POST',
    headers: { apikey: ANON, Authorization: `Bearer ${jwt}`, 'content-type': 'application/json', accept: 'application/json' },
    body: '{}',
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
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING' : !PSQL_OK ? 'psql unavailable — SKIPPING' : false;
if (SKIP) console.log(`[publisher-earnings-summary.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixtures.
//   A — matured impression (10d, 600k) + held impression (1d, 300k) → lifetime 900k.
//   B — one matured impression (10d, 500k), used for the isolation check.
// ---------------------------------------------------------------------------
const A = { authId: randomUUID(), pubId: randomUUID(),
  impMatured: randomUUID(), winMatured: randomUUID(), grpMatured: randomUUID(),
  impHeld: randomUUID(), winHeld: randomUUID(), grpHeld: randomUUID(),
  payoutId: randomUUID(), grpPayout: randomUUID() };
A.email = `earn-a-${A.authId}@example.com`;
A.handle = `earn-a-${A.pubId.slice(0, 8)}`;
const A_JWT = mintJwt(A.authId);

const B = { authId: randomUUID(), pubId: randomUUID(), impId: randomUUID(), winId: randomUUID(), grpId: randomUUID() };
B.email = `earn-b-${B.authId}@example.com`;
B.handle = `earn-b-${B.pubId.slice(0, 8)}`;
const B_JWT = mintJwt(B.authId);

const ORPHAN_JWT = mintJwt(randomUUID());

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

// One CPVA accrual group: advertiser_billing +gross, publisher_earnings -0.6*gross, platform -0.4*gross.
function seedAccrual(pubId, impId, winId, grpId, gross, ageDays) {
  const pub = Math.round(gross * 0.6), plat = gross - pub;
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, created_at)
    values ('${impId}', '${winId}', '${pubId}', 5, ${gross}, 'cleared', now() - interval '${ageDays} days');`);
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
      ('${grpId}','cpva_accrual','advertiser_billing', ${gross}, 'cleared','impression','${impId}', null),
      ('${grpId}','cpva_accrual','publisher_earnings', ${-pub},  'cleared','impression','${impId}', '${pubId}'),
      ('${grpId}','cpva_accrual','platform_revenue',   ${-plat}, 'cleared','impression','${impId}', null);`);
}

function seedFixture() {
  seedUser(A.authId, A.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, status)
    values ('${A.pubId}', '${A.authId}', '${A.handle}', 'FR', 'active');`);
  seedAccrual(A.pubId, A.impMatured, A.winMatured, A.grpMatured, 1000000, 10); // pub 600k, matured
  seedAccrual(A.pubId, A.impHeld,    A.winHeld,    A.grpHeld,    500000,  1);  // pub 300k, held

  seedUser(B.authId, B.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, status)
    values ('${B.pubId}', '${B.authId}', '${B.handle}', 'DE', 'active');`);
  seedAccrual(B.pubId, B.impId, B.winId, B.grpId, 833334, 10); // pub ~500k, matured
}

function seedPayoutA() {
  psql(`insert into public.payouts (id, publisher_id, amount_micros, status, hold_until, min_payout_micros, paid_at, stripe_transfer_id)
    values ('${A.payoutId}', '${A.pubId}', 200000, 'paid', now(), 1000000, now(), 'tr_test_${A.payoutId.slice(0,8)}');`);
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
      ('${A.grpPayout}','payout','publisher_earnings', 200000,  'cleared','payout','${A.payoutId}', '${A.pubId}'),
      ('${A.grpPayout}','payout','platform_cash',     -200000,  'cleared','payout','${A.payoutId}', null);`);
}

function teardownFixture() {
  try {
    for (const g of [A.grpMatured, A.grpHeld, A.grpPayout, B.grpId]) psql(`delete from public.ledger_entries where entry_group_id='${g}';`);
    psql(`delete from public.payouts where publisher_id='${A.pubId}';`);
    psql(`delete from public.impressions where publisher_id in ('${A.pubId}','${B.pubId}');`);
    psql(`delete from public.publishers where id in ('${A.pubId}','${B.pubId}');`);
    psql(`delete from auth.users where id in ('${A.authId}','${B.authId}');`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

test('E1: matured vs held split by impression age', { skip: SKIP }, async () => {
  const res = await summary(A_JWT);
  assert.ok(res.ok, `summary failed: ${res.status} ${JSON.stringify(res.data)}`);
  const d = res.data;
  assert.equal(Number(d.matured_micros),  600000, 'matured = 10-day-old impression only');
  assert.equal(Number(d.held_micros),     300000, 'held = 1-day-old impression (inside 7-day hold)');
  assert.equal(Number(d.lifetime_micros), 900000, 'lifetime = both accruals');
  assert.equal(Number(d.paid_micros),          0, 'nothing paid yet');
  assert.equal(Number(d.balance_micros),  900000, 'balance = lifetime - paid');
});

test('E2: a payout reduces paid + matured + balance; held and lifetime hold', { skip: SKIP }, async () => {
  seedPayoutA();
  const res = await summary(A_JWT);
  assert.ok(res.ok, `summary failed: ${res.status} ${JSON.stringify(res.data)}`);
  const d = res.data;
  assert.equal(Number(d.paid_micros),     200000, 'paid reflects the payout leg');
  assert.equal(Number(d.matured_micros),  400000, 'matured = 600k earned-past-hold - 200k paid');
  assert.equal(Number(d.balance_micros),  700000, 'balance = 900k - 200k');
  assert.equal(Number(d.held_micros),     300000, 'held = balance - matured, unchanged');
  assert.equal(Number(d.lifetime_micros), 900000, 'lifetime unaffected by a payout');
});

test('E3: isolation — A excludes B; B sees only its own figures', { skip: SKIP }, async () => {
  const a = await summary(A_JWT);
  assert.equal(Number(a.data.lifetime_micros), 900000, 'A lifetime must not include B');

  const b = await summary(B_JWT);
  assert.ok(b.ok, `B summary failed: ${b.status} ${JSON.stringify(b.data)}`);
  assert.equal(Number(b.data.lifetime_micros), 500000, 'B lifetime = B accrual only');
  assert.equal(Number(b.data.matured_micros),  500000, 'B matured (10-day-old)');
  assert.equal(Number(b.data.held_micros),          0, 'B has nothing in hold');
});

test('E4: a session with no publisher row is rejected (unauthenticated)', { skip: SKIP }, async () => {
  const res = await summary(ORPHAN_JWT);
  assert.ok(!res.ok, `expected an error for a publisher-less session, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.ok(res.status >= 400, `expected a 4xx/5xx, got ${res.status}`);
});
