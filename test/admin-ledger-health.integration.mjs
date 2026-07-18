// test/admin-ledger-health.integration.mjs — M8-T1: owner-dashboard ledger-health RPC.
//
// admin_ledger_health() is an ADMIN-ONLY global aggregate over public.ledger_entries for the
// owner dashboard's Overview: {global_sum_micros, unbalanced_group_count, cleared/provisional/
// reversed totals, zero_sum_ok, accrual_identity_ok, publisher_split_bps}. It is READ-ONLY;
// is_admin() (aal1) gates it (a first-line RAISE 28000), and anon/public EXECUTE is revoked.
//
// Because the RPC is GLOBAL (not self-scoped like publisher_earnings_summary), and `node --test`
// runs test files in parallel against the same local DB, this suite asserts the things that hold
// at ANY committed snapshot regardless of concurrent seeding:
//   * structural invariants — global_sum_micros == 0, unbalanced_group_count == 0,
//     zero_sum_ok == true, accrual_identity_ok == true (every committed group balances and every
//     cleared accrual group has advertiser_billing = -(publisher_earnings + platform_revenue),
//     both enforced atomically by the ledger constraint trigger + single-statement reversals);
//   * MONOTONIC LOWER BOUNDS — the aggregate must reflect AT LEAST this suite's own seeded
//     groups (cleared / provisional / reversed), which persist through the whole run.
//
// Setup via psql (auth.users + app.admins are not reachable via PostgREST); RPC called with a
// per-user HS256 session JWT (sub = auth_user_id). Self-skips if the stack or psql is down.
//
// WHAT IS TESTED:
//   H1 — an admin session gets a well-formed aggregate (all keys + types)
//   H1b — DATA-MINIMIZATION: the payload is aggregate micros/booleans ONLY — no email/IP/cost/
//         token/handle-shaped key can appear (locks the RPC to the known aggregate key set)
//   H2 — structural invariants hold (zero-sum, per-group balance, accrual identity, split bps)
//   H3 — the seeded cleared / provisional / reversed groups are reflected (branch lower bounds)
//   H4 — a normal (non-admin) publisher session is rejected with the in-body RAISE (403 / 28000)

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

async function health(jwt) {
  const resp = await fetch(`${REST_BASE}/rpc/admin_ledger_health`, {
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
if (SKIP) console.log(`[admin-ledger-health.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixtures.
//   ADMIN — an owner identity seeded into app.admins (may call the RPC).
//   PUB   — a normal publisher that OWNS the seeded ledger legs (may NOT call the RPC).
//   Three balanced groups under PUB exercise every aggregate branch:
//     CLEARED     cpva_accrual, gross 1_000_000 → adv +1e6, pub -6e5, plat -4e5
//     PROVISIONAL cpva_accrual, gross   500_000 → adv +5e5, pub -3e5, plat -2e5
//     REVERSED    clawback,     gross 1_000_000 → adv +1e6, pub -6e5, plat -4e5 (all 'reversed')
// ---------------------------------------------------------------------------
const CLEARED_GROSS = 1_000_000, CLEARED_PUB = 600_000, CLEARED_PLAT = 400_000;
const PROV_GROSS    =   500_000, PROV_PUB    = 300_000, PROV_PLAT    = 200_000;
const REV_GROSS     = 1_000_000, REV_PUB     = 600_000, REV_PLAT     = 400_000;

const ADMIN = { authId: randomUUID() };
ADMIN.email = `alh-admin-${ADMIN.authId}@example.com`;
const ADMIN_JWT = mintJwt(ADMIN.authId);

const PUB = { authId: randomUUID(), pubId: randomUUID(),
  grpCleared: randomUUID(), impCleared: randomUUID(),
  grpProv: randomUUID(), impProv: randomUUID(),
  grpRev: randomUUID(), impRev: randomUUID() };
PUB.email  = `alh-pub-${PUB.authId}@example.com`;
PUB.handle = `alh-pub-${PUB.pubId.slice(0, 8)}`;
const PUB_JWT = mintJwt(PUB.authId);

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

// One balanced 3-leg group in a single INSERT (one statement = one txn) so the deferred
// zero-sum constraint trigger passes at COMMIT. publisher_id is set only on the earnings leg.
function seedGroup(grpId, impId, eventType, state, gross, pub, plat) {
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
      ('${grpId}','${eventType}','advertiser_billing', ${gross}, '${state}','impression','${impId}', null),
      ('${grpId}','${eventType}','publisher_earnings', ${-pub},  '${state}','impression','${impId}', '${PUB.pubId}'),
      ('${grpId}','${eventType}','platform_revenue',   ${-plat}, '${state}','impression','${impId}', null);`);
}

function seedFixture() {
  seedUser(ADMIN.authId, ADMIN.email);
  psql(`insert into app.admins (auth_user_id) values ('${ADMIN.authId}') on conflict (auth_user_id) do nothing;`);

  seedUser(PUB.authId, PUB.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, status)
    values ('${PUB.pubId}', '${PUB.authId}', '${PUB.handle}', 'FR', 'active');`);

  seedGroup(PUB.grpCleared, PUB.impCleared, 'cpva_accrual', 'cleared',     CLEARED_GROSS, CLEARED_PUB, CLEARED_PLAT);
  seedGroup(PUB.grpProv,    PUB.impProv,    'cpva_accrual', 'provisional', PROV_GROSS,    PROV_PUB,    PROV_PLAT);
  seedGroup(PUB.grpRev,     PUB.impRev,     'clawback',     'reversed',    REV_GROSS,     REV_PUB,     REV_PLAT);
}

function teardownFixture() {
  try {
    for (const g of [PUB.grpCleared, PUB.grpProv, PUB.grpRev]) psql(`delete from public.ledger_entries where entry_group_id='${g}';`);
    psql(`delete from public.publishers where id='${PUB.pubId}';`);
    psql(`delete from app.admins where auth_user_id='${ADMIN.authId}';`);
    psql(`delete from auth.users where id in ('${ADMIN.authId}','${PUB.authId}');`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

const KEYS = [
  'global_sum_micros', 'unbalanced_group_count',
  'cleared_advertiser_billing_micros', 'cleared_publisher_earnings_micros', 'cleared_platform_revenue_micros',
  'provisional_advertiser_billing_micros', 'reversed_publisher_earnings_micros',
  'zero_sum_ok', 'accrual_identity_ok', 'publisher_split_bps',
];

test('H1: an admin session gets a well-formed aggregate', { skip: SKIP }, async () => {
  const res = await health(ADMIN_JWT);
  assert.ok(res.ok, `admin_ledger_health failed: ${res.status} ${JSON.stringify(res.data)}`);
  const d = res.data;
  assert.equal(typeof d, 'object');
  for (const k of KEYS) assert.ok(k in d, `missing key ${k}`);
  assert.equal(typeof d.zero_sum_ok, 'boolean');
  assert.equal(typeof d.accrual_identity_ok, 'boolean');
  // publisher_split_bps is an int or null (null only when there is zero cleared advertiser billing).
  assert.ok(d.publisher_split_bps === null || Number.isInteger(Number(d.publisher_split_bps)));
});

test('H1b: the payload is aggregate-only — NO email/IP/cost/token/handle keys (data-minimization)', { skip: SKIP }, async () => {
  const { data: d } = await health(ADMIN_JWT);
  // Lock the payload to the known aggregate key set: any future edit that widened the RPC to leak a
  // per-publisher email/handle/ip/cost/token field would fail here, not silently ship.
  const allow = new Set(KEYS);
  const extra = Object.keys(d).filter((k) => !allow.has(k));
  assert.deepEqual(extra, [], `admin_ledger_health emitted unexpected key(s): ${extra.join(', ')}`);
  // Secondary belt-and-suspenders: even a PII key added to BOTH the RPC and KEYS is caught here.
  const forbidden = /email|ip_hash|ip_addr|cost|token|handle|advertiser_name|publisher_id|address/i;
  const leaky = Object.keys(d).filter((k) => forbidden.test(k));
  assert.deepEqual(leaky, [], `admin_ledger_health emitted PII-shaped key(s): ${leaky.join(', ')}`);
});

test('H2: structural invariants hold (zero-sum, per-group balance, accrual identity)', { skip: SKIP }, async () => {
  const { data: d } = await health(ADMIN_JWT);
  assert.equal(Number(d.global_sum_micros),     0, 'the global committed ledger must be zero-sum');
  assert.equal(Number(d.unbalanced_group_count), 0, 'no committed entry_group may be unbalanced');
  assert.equal(d.zero_sum_ok,        true, 'zero_sum_ok mirrors the two invariants above');
  assert.equal(d.accrual_identity_ok, true, 'cleared advertiser_billing must equal publisher_earnings + platform_revenue');
  if (d.publisher_split_bps !== null) {
    const bps = Number(d.publisher_split_bps);
    assert.ok(bps >= 5900 && bps <= 6100, `publisher split should be ~6000 bps (60/40), got ${bps}`);
  }
});

test('H3: seeded cleared / provisional / reversed groups are reflected (branch lower bounds)', { skip: SKIP }, async () => {
  const { data: d } = await health(ADMIN_JWT);
  // Lower bounds: the aggregate is global, so it may exceed these, but must include our own seed.
  assert.ok(Number(d.cleared_advertiser_billing_micros)     >= CLEARED_GROSS, `cleared adv >= ${CLEARED_GROSS}, got ${d.cleared_advertiser_billing_micros}`);
  assert.ok(Number(d.cleared_publisher_earnings_micros)     >= CLEARED_PUB,   `cleared pub >= ${CLEARED_PUB}, got ${d.cleared_publisher_earnings_micros}`);
  assert.ok(Number(d.cleared_platform_revenue_micros)       >= CLEARED_PLAT,  `cleared plat >= ${CLEARED_PLAT}, got ${d.cleared_platform_revenue_micros}`);
  assert.ok(Number(d.provisional_advertiser_billing_micros) >= PROV_GROSS,    `provisional adv >= ${PROV_GROSS}, got ${d.provisional_advertiser_billing_micros}`);
  assert.ok(Number(d.reversed_publisher_earnings_micros)    >= REV_PUB,       `reversed pub >= ${REV_PUB}, got ${d.reversed_publisher_earnings_micros}`);
});

test('H4: a normal (non-admin) publisher session is rejected (in-body RAISE 28000)', { skip: SKIP }, async () => {
  const res = await health(PUB_JWT);
  assert.ok(!res.ok, `expected a non-admin to be rejected, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.ok(res.status >= 400, `expected a 4xx, got ${res.status}`);
  // authenticated-but-not-admin reaches the body → the first-line RAISE surfaces code 28000.
  if (res.data?.code) assert.equal(res.data.code, '28000', 'must be the unauthorized RAISE, not another error');
});
