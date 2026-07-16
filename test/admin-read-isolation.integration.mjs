// test/admin-read-isolation.integration.mjs — M8-T1: owner-dashboard read-surface isolation.
//
// The owner dashboard reads through two kinds of admin-gated surface:
//   * admin_ledger_health() — a SECURITY DEFINER RPC whose first-line app.is_admin() RAISE is
//     the real gate (an authenticated non-admin reaches the body and is RAISEd 28000; anon is
//     not even granted EXECUTE);
//   * public.ledger_entries directly — RLS `own-or-is_admin` (ledger_and_payouts.sql:70-75): an
//     admin sees EVERY row, a publisher sees ONLY its own publisher_earnings legs, anon sees none.
//
// This suite proves both, and specifically that there is NO cross-tenant leak: publisher A can
// never see publisher B's ledger rows (nor the advertiser_billing/platform legs that carry no
// publisher_id), while the admin — legitimately — sees the full superset including B's rows.
//
// Setup via psql (auth.users + app.admins are off the Data API); reads via PostgREST with a
// per-user HS256 session JWT. Self-skips if the stack or psql is down.
//
// WHAT IS TESTED:
//   I1 — an admin session may call admin_ledger_health() (sees the aggregate)
//   I2 — a normal publisher session calling admin_ledger_health() is RAISEd (403 / 28000)
//   I3 — an anon session calling admin_ledger_health() is rejected (no EXECUTE grant)
//   I4 — publisher A reading ledger_entries sees ONLY its own earnings leg; B's rows are absent
//   I5 — an admin reading the SAME rows sees the full superset, INCLUDING B's rows (authorized)
//   I6 — an anon reading ledger_entries leaks ZERO rows
//   I7 — DISPUTES SCOPING PROOF: a DEVICE-JWT publisher (publisher_id claim) that OWNS a dispute
//        sees ONLY its own dispute row, never another publisher's — proving disputes_publisher
//        SCOPES on the claim rather than blanket-empties
//   I8 — a WEB (Scheme A) non-admin session sees ZERO disputes — but because a web session lacks
//        the device-JWT publisher_id claim (fail-closed), NOT because of tenant scoping
//   I9 — the admin sees BOTH disputes via disputes_admin (is_admin), the full superset
//   I10 — a WEB non-admin session reads ZERO rows via advertiser_charges / clawback_reviews /
//         v_campaign_delivery (all is_admin-only surfaces); the admin reads the seeded rows
//   I11 — v_publisher_balance is OWN-scoped (not admin-only): A sees only A's balance, never B's;
//         the admin sees BOTH (contrast with the is_admin-only surfaces in I10)
//   I12 — anon reads ZERO through disputes / advertiser_charges / clawback_reviews / v_campaign_delivery

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

// GET public.ledger_entries filtered to this suite's two groups, with the given session JWT.
async function getLedger(jwt) {
  const resp = await fetch(
    `${REST_BASE}/ledger_entries?entry_group_id=in.(${A.grp},${B.grp})&select=entry_group_id,account,amount_micros,publisher_id`,
    { headers: { apikey: ANON, Authorization: `Bearer ${jwt}`, accept: 'application/json' } },
  );
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

// GET any admin surface (table or view) with an arbitrary session JWT. Returns { ok, status, data }.
async function getWith(pathAndQuery, jwt) {
  const resp = await fetch(`${REST_BASE}/${pathAndQuery}`, {
    headers: { apikey: ANON, Authorization: `Bearer ${jwt}`, accept: 'application/json' },
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}
// Row count for a no-leak assertion: an empty array OR a non-array error body (4xx permission-denied)
// are BOTH zero-leak, so anything that isn't a populated array counts as zero rows visible.
function rowCount(res) {
  return Array.isArray(res.data) ? res.data.length : 0;
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING' : !PSQL_OK ? 'psql unavailable — SKIPPING' : false;
if (SKIP) console.log(`[admin-read-isolation.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixtures.
//   ADMIN — an owner identity in app.admins.
//   A, B  — two normal publishers, each owning ONE cleared 60/40 CPVA group. A must never see
//           B and vice-versa; the admin sees both.
// ---------------------------------------------------------------------------
const GROSS = 1_000_000, PUB = 600_000, PLAT = 400_000;

const ADMIN = { authId: randomUUID() };
ADMIN.email = `iso-admin-${ADMIN.authId}@example.com`;
const ADMIN_JWT = mintJwt(ADMIN.authId);

const A = { authId: randomUUID(), pubId: randomUUID(), grp: randomUUID(), imp: randomUUID() };
A.email = `iso-a-${A.authId}@example.com`; A.handle = `iso-a-${A.pubId.slice(0, 8)}`;
const A_JWT = mintJwt(A.authId);

const B = { authId: randomUUID(), pubId: randomUUID(), grp: randomUUID(), imp: randomUUID() };
B.email = `iso-b-${B.authId}@example.com`; B.handle = `iso-b-${B.pubId.slice(0, 8)}`;
const B_JWT = mintJwt(B.authId);

// A DEVICE JWT for publisher A: carries the publisher_id claim (like the CLI device session), which
// is the ONLY thing disputes_publisher scopes on. A web (Scheme A) session — A_JWT above — has no
// such claim, so it fails-closed to zero disputes. These two prove the CORRECTED disputes model.
const A_DEVICE_JWT = mintJwt(A.authId, { publisher_id: A.pubId, device_id: randomUUID() });

// Admin-only read surfaces + the own-scoped balance view. Disputes have a nullable impression_id and
// clawback_reviews / advertiser_charges here use impression_id NULL so no impressions row is needed
// (the isolation fixture only seeds ledger_entries, not impressions).
const ADV        = randomUUID();   // advertiser (FK for the charge + campaign)
const CAMPAIGN   = randomUUID();
const LINE_ITEM  = randomUUID();
const CHARGE_GRP = randomUUID();   // advertiser_charges.entry_group_id (UNIQUE, not a FK)
const RF         = randomUUID();   // risk_flag (FK for the review)
const REVIEW     = randomUUID();
const DISP_A     = randomUUID();   // dispute owned by A
const DISP_B     = randomUUID();   // dispute owned by B
const WIN        = randomUUID();   // window id for the risk_flag

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

// One balanced cleared 60/40 CPVA group in a single INSERT (atomic zero-sum at COMMIT).
function seedGroup(pub, grp, imp) {
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
      ('${grp}','cpva_accrual','advertiser_billing', ${GROSS}, 'cleared','impression','${imp}', null),
      ('${grp}','cpva_accrual','publisher_earnings', ${-PUB},  'cleared','impression','${imp}', '${pub.pubId}'),
      ('${grp}','cpva_accrual','platform_revenue',   ${-PLAT}, 'cleared','impression','${imp}', null);`);
}

function seedFixture() {
  seedUser(ADMIN.authId, ADMIN.email);
  psql(`insert into app.admins (auth_user_id) values ('${ADMIN.authId}') on conflict (auth_user_id) do nothing;`);

  for (const p of [A, B]) {
    seedUser(p.authId, p.email);
    psql(`insert into public.publishers (id, auth_user_id, handle, country, status)
      values ('${p.pubId}', '${p.authId}', '${p.handle}', 'FR', 'active');`);
    seedGroup(p, p.grp, p.imp);
  }

  // Disputes — one per publisher (impression_id NULL so no impressions row is required).
  psql(`insert into public.disputes (id, publisher_id, impression_id, description, status) values
      ('${DISP_A}', '${A.pubId}', null, 'iso dispute A', 'open'),
      ('${DISP_B}', '${B.pubId}', null, 'iso dispute B', 'open');`);

  // Advertiser + campaign + line_item (feeds v_campaign_delivery; admin-only via RLS on campaigns/line_items).
  psql(`insert into public.advertisers (id, name) values ('${ADV}', 'iso-adv');`);
  psql(`insert into public.campaigns (id, advertiser_id, name) values ('${CAMPAIGN}', '${ADV}', 'iso-camp');`);
  psql(`insert into public.line_items (id, campaign_id) values ('${LINE_ITEM}', '${CAMPAIGN}');`);

  // A succeeded advertiser_charge (is_admin-only RLS). entry_group_id is UNIQUE but not a FK.
  psql(`insert into public.advertiser_charges (entry_group_id, advertiser_id, impression_id, amount_micros, amount_cents, status, stripe_charge_id)
      values ('${CHARGE_GRP}', '${ADV}', null, ${GROSS}, ${Math.round(GROSS / 10000)}, 'succeeded', 'pi_iso_${CHARGE_GRP.slice(0, 8)}');`);

  // A risk_flag + clawback_review (is_admin-only RLS). impression_id NULL avoids the impressions FK.
  psql(`insert into public.risk_flags (id, impression_id, window_id, reason) values ('${RF}', null, '${WIN}', 'iso-flag');`);
  psql(`insert into public.clawback_reviews (id, risk_flag_id, impression_id, status) values ('${REVIEW}', '${RF}', null, 'pending');`);
}

function teardownFixture() {
  try {
    psql(`delete from public.clawback_reviews where id='${REVIEW}';`);
    psql(`delete from public.risk_flags where id='${RF}';`);
    psql(`delete from public.advertiser_charges where entry_group_id='${CHARGE_GRP}';`);
    psql(`delete from public.disputes where id in ('${DISP_A}','${DISP_B}');`);
    psql(`delete from public.line_items where id='${LINE_ITEM}';`);
    psql(`delete from public.campaigns where id='${CAMPAIGN}';`);
    psql(`delete from public.advertisers where id='${ADV}';`);
    for (const g of [A.grp, B.grp]) psql(`delete from public.ledger_entries where entry_group_id='${g}';`);
    psql(`delete from public.publishers where id in ('${A.pubId}','${B.pubId}');`);
    psql(`delete from app.admins where auth_user_id='${ADMIN.authId}';`);
    psql(`delete from auth.users where id in ('${ADMIN.authId}','${A.authId}','${B.authId}');`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

test('I1: an admin session may call admin_ledger_health() (sees the aggregate)', { skip: SKIP }, async () => {
  const res = await health(ADMIN_JWT);
  assert.ok(res.ok, `admin should reach the aggregate, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.zero_sum_ok, true, 'admin gets the well-formed aggregate');
});

test('I2: a normal publisher calling admin_ledger_health() is RAISEd (403 / 28000)', { skip: SKIP }, async () => {
  const res = await health(A_JWT);
  assert.ok(!res.ok, `a non-admin must be rejected, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.ok(res.status >= 400, `expected a 4xx, got ${res.status}`);
  // authenticated-but-not-admin reaches the body → the in-body RAISE surfaces code 28000.
  if (res.data?.code) assert.equal(res.data.code, '28000', 'must be the unauthorized RAISE');
});

test('I3: an anon session calling admin_ledger_health() is rejected (no EXECUTE grant)', { skip: SKIP }, async () => {
  const res = await health(ANON);
  assert.ok(!res.ok, `anon must be rejected, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.ok(res.status >= 400, `expected a 4xx (anon has no EXECUTE on the RPC), got ${res.status}`);
});

test('I4: publisher A sees ONLY its own earnings leg; B\'s rows are absent (no cross-tenant leak)', { skip: SKIP }, async () => {
  const res = await getLedger(A_JWT);
  assert.ok(res.ok, `A ledger read failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.ok(Array.isArray(res.data), 'expected a row array');
  // RLS: A sees a row only when account='publisher_earnings' AND publisher_id=A. That is exactly
  // one row across the two groups — A's own earnings leg of A's group. Everything else is hidden.
  assert.equal(res.data.length, 1, `A must see exactly its own earnings leg, saw ${res.data.length}`);
  const row = res.data[0];
  assert.equal(row.account, 'publisher_earnings', 'A may only see a publisher_earnings leg');
  assert.equal(row.publisher_id, A.pubId, 'the visible leg must belong to A');
  assert.equal(row.entry_group_id, A.grp, 'the visible leg must be from A\'s own group');
  assert.ok(!res.data.some((r) => r.entry_group_id === B.grp), 'B\'s group must be entirely invisible to A');
  assert.ok(!res.data.some((r) => r.publisher_id === B.pubId), 'B\'s publisher_id must never appear for A');
});

test('I5: an admin sees the full superset, INCLUDING B\'s rows (authorized cross-tenant read)', { skip: SKIP }, async () => {
  const res = await getLedger(ADMIN_JWT);
  assert.ok(res.ok, `admin ledger read failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.ok(Array.isArray(res.data), 'expected a row array');
  assert.equal(res.data.length, 6, `admin must see all 6 legs (3 per group), saw ${res.data.length}`);
  const groups = new Set(res.data.map((r) => r.entry_group_id));
  assert.ok(groups.has(A.grp) && groups.has(B.grp), 'admin must see BOTH groups');
  const accounts = new Set(res.data.map((r) => r.account));
  for (const acct of ['advertiser_billing', 'publisher_earnings', 'platform_revenue']) {
    assert.ok(accounts.has(acct), `admin must see the ${acct} legs A could not`);
  }
  // The load-bearing cross-tenant assertion: the admin sees B's earnings leg, which A cannot.
  assert.ok(res.data.some((r) => r.publisher_id === B.pubId), 'admin must see B\'s earnings leg');
});

test('I6: an anon session leaks ZERO ledger rows', { skip: SKIP }, async () => {
  const res = await getLedger(ANON);
  if (res.ok) {
    assert.ok(Array.isArray(res.data), 'expected an array body');
    assert.equal(res.data.length, 0, 'anon must see zero rows (RLS policies are for authenticated only)');
  } else {
    // A permission-denied (no anon grant) is an equally-good no-leak outcome.
    assert.ok(res.status >= 400, `expected empty or a 4xx for anon, got ${res.status}`);
  }
});

// disputes filtered to this suite's two publishers (so unrelated data can't perturb the counts).
const DISPUTES_Q = `disputes?publisher_id=in.(${A.pubId},${B.pubId})&select=id,publisher_id`;

test('I7: DISPUTES SCOPING — a DEVICE-JWT owner sees ONLY its own dispute, not another publisher\'s', { skip: SKIP }, async () => {
  // disputes_publisher scopes on jwt_claim('publisher_id'); A's device JWT carries publisher_id=A.
  const res = await getWith(DISPUTES_Q, A_DEVICE_JWT);
  assert.ok(res.ok, `device read failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.ok(Array.isArray(res.data), 'expected a row array');
  assert.equal(res.data.length, 1, `A's device session must see exactly ONE dispute (its own), saw ${res.data.length}`);
  assert.equal(res.data[0].id, DISP_A, 'the visible dispute is A\'s own');
  assert.equal(res.data[0].publisher_id, A.pubId, 'scoped to A');
  assert.ok(!res.data.some((r) => r.id === DISP_B), 'B\'s dispute must be invisible — proving SCOPING, not blanket-empty');
});

test('I8: a WEB (Scheme A) non-admin session sees ZERO disputes — device-JWT fail-closed, NOT tenant scoping', { skip: SKIP }, async () => {
  // A_JWT is a plain web session (sub only, no publisher_id claim). It matches neither
  // disputes_publisher (claim is NULL) nor disputes_admin (not an admin) → zero. This is fail-closed
  // because the web session lacks the device-JWT publisher_id claim, NOT because RLS tenant-scoped it.
  const res = await getWith(DISPUTES_Q, A_JWT);
  assert.equal(rowCount(res), 0, `a web non-admin must see zero disputes, saw ${JSON.stringify(res.data)}`);
});

test('I9: the admin sees BOTH disputes via disputes_admin (is_admin superset)', { skip: SKIP }, async () => {
  const res = await getWith(DISPUTES_Q, ADMIN_JWT);
  assert.ok(res.ok, `admin dispute read failed: ${res.status}`);
  const ids = new Set((res.data ?? []).map((r) => r.id));
  assert.ok(ids.has(DISP_A) && ids.has(DISP_B), 'admin must see BOTH disputes');
});

test('I10: a WEB non-admin reads ZERO via advertiser_charges / clawback_reviews / v_campaign_delivery; admin reads the seeded rows', { skip: SKIP }, async () => {
  // These three are is_admin-only surfaces (advertiser_charges/clawback_reviews RLS is is_admin-only;
  // v_campaign_delivery is security_invoker over admin-only campaigns/line_items). A web publisher → 0.
  const acA = await getWith(`advertiser_charges?entry_group_id=eq.${CHARGE_GRP}&select=entry_group_id`, A_JWT);
  const crA = await getWith(`clawback_reviews?id=eq.${REVIEW}&select=id`, A_JWT);
  const cdA = await getWith(`v_campaign_delivery?line_item_id=eq.${LINE_ITEM}&select=line_item_id`, A_JWT);
  assert.equal(rowCount(acA), 0, 'web non-admin sees zero advertiser_charges');
  assert.equal(rowCount(crA), 0, 'web non-admin sees zero clawback_reviews');
  assert.equal(rowCount(cdA), 0, 'web non-admin sees zero v_campaign_delivery rows');

  // The admin reads the seeded rows through the SAME surfaces (authorized superset).
  const acAdm = await getWith(`advertiser_charges?entry_group_id=eq.${CHARGE_GRP}&select=entry_group_id`, ADMIN_JWT);
  const crAdm = await getWith(`clawback_reviews?id=eq.${REVIEW}&select=id`, ADMIN_JWT);
  const cdAdm = await getWith(`v_campaign_delivery?line_item_id=eq.${LINE_ITEM}&select=line_item_id`, ADMIN_JWT);
  assert.equal(rowCount(acAdm), 1, 'admin sees the seeded advertiser_charge');
  assert.equal(rowCount(crAdm), 1, 'admin sees the seeded clawback_review');
  assert.equal(rowCount(cdAdm), 1, 'admin sees the seeded campaign delivery row');
});

test('I11: v_publisher_balance is OWN-scoped — A sees only A\'s balance, never B\'s; admin sees BOTH', { skip: SKIP }, async () => {
  // Unlike the is_admin-only surfaces in I10, v_publisher_balance is security_invoker over
  // publishers (own-or-admin RLS), so a web publisher sees its OWN balance row — NOT zero. The
  // isolation guarantee here is own-only (no cross-tenant), matching ledger_entries in I4/I5.
  const q = `v_publisher_balance?publisher_id=in.(${A.pubId},${B.pubId})&select=publisher_id`;
  const a = await getWith(q, A_JWT);
  assert.ok(a.ok, `A balance read failed: ${a.status}`);
  const aIds = (a.data ?? []).map((r) => r.publisher_id);
  assert.deepEqual(aIds, [A.pubId], `A must see ONLY its own balance row, saw ${JSON.stringify(aIds)}`);

  const adm = await getWith(q, ADMIN_JWT);
  const admIds = new Set((adm.data ?? []).map((r) => r.publisher_id));
  assert.ok(admIds.has(A.pubId) && admIds.has(B.pubId), 'admin must see BOTH A and B balances');
});

test('I12: anon reads ZERO through disputes / advertiser_charges / clawback_reviews / v_campaign_delivery', { skip: SKIP }, async () => {
  const d = await getWith(DISPUTES_Q, ANON);
  const ac = await getWith(`advertiser_charges?entry_group_id=eq.${CHARGE_GRP}&select=entry_group_id`, ANON);
  const cr = await getWith(`clawback_reviews?id=eq.${REVIEW}&select=id`, ANON);
  const cd = await getWith(`v_campaign_delivery?line_item_id=eq.${LINE_ITEM}&select=line_item_id`, ANON);
  assert.equal(rowCount(d), 0, 'anon sees zero disputes');
  assert.equal(rowCount(ac), 0, 'anon sees zero advertiser_charges');
  assert.equal(rowCount(cr), 0, 'anon sees zero clawback_reviews');
  assert.equal(rowCount(cd), 0, 'anon sees zero v_campaign_delivery rows');
});
