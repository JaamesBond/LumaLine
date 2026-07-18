// test/advertiser-identity-rls.integration.mjs — M9-T1: advertiser identity + DB-as-boundary.
//
// 20260716150000_advertiser_identity_rls.sql makes the DATABASE the isolation boundary for the
// self-serve advertiser portal:
//   * public.advertiser_users maps a web session (auth.uid()) to an advertiser org;
//     app.current_advertiser_id() resolves it (SECDEF, off the Data API).
//   * additive per-advertiser SELECT policies let an advertiser read ONLY its own
//     advertisers/campaigns/line_items/creatives rows — never another advertiser's.
//   * the broad authenticated INSERT/UPDATE/DELETE grant on the four booking tables is REVOKED,
//     so a crafted PostgREST write from an advertiser session matches no grant (writes flow only
//     through SECDEF RPCs, added in a later migration).
//   * the advertisers read is column-scoped: stripe_customer_id / is_house never reach the client.
//   * ensure_advertiser_user() is strictly self-creating (no argument, fresh org), refuses a
//     caller who is already a publisher, and is idempotent.
//
// Setup + auth.users assertions use psql (auth.users + app.admins are off the Data API); reads
// go through PostgREST with a per-user HS256 session JWT. Self-skips if the stack or psql is down.
//
// WHAT IS TESTED:
//   R1  — advertiser A reads its OWN advertisers row (id/name/billing_mode); B's row is absent
//   R2  — A reads campaigns: only A's campaign, never B's (cross-advertiser isolation)
//   R3  — A reads line_items + creatives: only A's, via the FK-chain SELECT policies
//   R4  — advertiser B reads campaigns: only B's (symmetry — A's campaign absent)
//   R5  — advertiser_self_id()/advertiser_check() resolve the caller's OWN org server-side
//   R6  — column-scope: A cannot SELECT stripe_customer_id / is_house; allowed columns succeed
//   R7  — DML lockdown: A cannot INSERT a campaign, UPDATE its advertisers row, or PATCH line_items
//   R8  — anon is rejected everywhere (no table grant, no fn EXECUTE)
//   R9  — a caller already mapped to a publisher is REFUSED provisioning (bidirectional guard)
//   R10 — self-create: a fresh session provisions a prepay org + mapping (+ zero balance)
//   R11 — provisioning is idempotent (second call returns the same org, created=false)
//   R12 — an admin sees BOTH A's and B's rows (the *_admin_all policy coexists with select_own)

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

// PostgREST RPC with a session JWT (or the anon key when jwt is omitted).
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

// PostgREST GET of `table?query` with a session JWT (or anon).
async function restGet(table, query, jwt) {
  const token = jwt ?? ANON;
  const resp = await fetch(`${REST_BASE}/${table}?${query}`, {
    headers: { apikey: ANON, Authorization: `Bearer ${token}`, accept: 'application/json' },
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

// PostgREST write (POST/PATCH) — used to prove the authenticated write grant is revoked.
async function restWrite(method, table, query, body, jwt) {
  const token = jwt ?? ANON;
  const url = query ? `${REST_BASE}/${table}?${query}` : `${REST_BASE}/${table}`;
  const resp = await fetch(url, {
    method,
    headers: { apikey: ANON, Authorization: `Bearer ${token}`, 'content-type': 'application/json', Prefer: 'return=minimal' },
    body: JSON.stringify(body),
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
if (SKIP) console.log(`[advertiser-identity-rls.integration] ${SKIP}`);

const HAS_BALANCES = !SKIP && psql(`select to_regclass('public.advertiser_balances') is not null;`) === 't';

// ---------------------------------------------------------------------------
// Fixtures (seeded via psql):
//   A — advertiser org with a campaign + line_item + creative (postpay, so unconstrained by the
//       later CPVA min-bid CHECK on prepay line_items)
//   B — a second advertiser org (bystander) — A must never see it, and vice-versa
//   PUB   — an auth identity already mapped to a publisher (provisioning must refuse it)
//   FRESH — an auth identity with no mapping (self-create path)
//   ADMIN — an auth identity in app.admins (sees the full superset)
// ---------------------------------------------------------------------------
const A = { authId: randomUUID(), advId: randomUUID(), campId: randomUUID(), liId: randomUUID(), crId: randomUUID() };
A.email = `adv-a-${A.authId}@example.com`;
const A_JWT = mintJwt(A.authId);

const B = { authId: randomUUID(), advId: randomUUID(), campId: randomUUID() };
B.email = `adv-b-${B.authId}@example.com`;
const B_JWT = mintJwt(B.authId);

const PUB = { authId: randomUUID(), pubId: randomUUID() };
PUB.email = `adv-pub-${PUB.authId}@example.com`;
PUB.handle = `adv-pub-${PUB.pubId.slice(0, 8)}`;
const PUB_JWT = mintJwt(PUB.authId);

const FRESH = { authId: randomUUID(), advId: null };
FRESH.email = `adv-fresh-${FRESH.authId}@example.com`;
const FRESH_JWT = mintJwt(FRESH.authId);

const ADMIN = { authId: randomUUID() };
ADMIN.email = `adv-admin-${ADMIN.authId}@example.com`;
const ADMIN_JWT = mintJwt(ADMIN.authId);

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

function seedFixture() {
  seedUser(A.authId, A.email);
  seedUser(B.authId, B.email);
  seedUser(PUB.authId, PUB.email);
  seedUser(FRESH.authId, FRESH.email);
  seedUser(ADMIN.authId, ADMIN.email);

  // A + B advertiser orgs (postpay so line_items carry no min-bid constraint).
  psql(`insert into public.advertisers (id, name, status, billing_mode, stripe_customer_id)
    values ('${A.advId}', 'Adv A', 'active', 'postpay', 'cus_test_${A.advId.slice(0,8)}'),
           ('${B.advId}', 'Adv B', 'active', 'postpay', 'cus_test_${B.advId.slice(0,8)}');`);
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role)
    values ('${A.authId}', '${A.advId}', 'owner'),
           ('${B.authId}', '${B.advId}', 'owner');`);

  psql(`insert into public.campaigns (id, advertiser_id, name, status)
    values ('${A.campId}', '${A.advId}', 'A camp', 'active'),
           ('${B.campId}', '${B.advId}', 'B camp', 'active');`);
  psql(`insert into public.line_items (id, campaign_id, cpva_bid_micros, status)
    values ('${A.liId}', '${A.campId}', 5000, 'active');`);
  psql(`insert into public.creatives (id, line_item_id, line, dest_url, label, status)
    values ('${A.crId}', '${A.liId}', 'Sponsored: Acme Cloud', 'https://acme.example', 'sponsored', 'active');`);

  // PUB — already a publisher.
  psql(`insert into public.publishers (id, auth_user_id, handle, status)
    values ('${PUB.pubId}', '${PUB.authId}', '${PUB.handle}', 'active');`);

  // ADMIN.
  psql(`insert into app.admins (auth_user_id) values ('${ADMIN.authId}');`);
}

function teardownFixture() {
  const ids = [A.advId, B.advId, FRESH.advId].filter(Boolean).map((x) => `'${x}'`).join(',');
  try {
    if (HAS_BALANCES && ids) psql(`delete from public.advertiser_balances where advertiser_id in (${ids});`);
    psql(`delete from public.advertiser_users where auth_user_id in ('${A.authId}','${B.authId}','${FRESH.authId}');`);
    if (ids) psql(`delete from public.advertisers where id in (${ids});`);  // cascades campaigns/line_items/creatives
    psql(`delete from public.publishers where id='${PUB.pubId}';`);
    psql(`delete from app.admins where auth_user_id='${ADMIN.authId}';`);
    psql(`delete from auth.users where id in ('${A.authId}','${B.authId}','${PUB.authId}','${FRESH.authId}','${ADMIN.authId}');`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

test('R1: advertiser A reads its own advertisers row; B is absent', { skip: SKIP }, async () => {
  const res = await restGet('advertisers', 'select=id,name,billing_mode&order=id', A_JWT);
  assert.ok(res.ok, `read failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.ok(Array.isArray(res.data));
  const ids = res.data.map((r) => r.id);
  assert.deepEqual(ids, [A.advId], `A must see ONLY its own advertiser row, got ${JSON.stringify(ids)}`);
  assert.equal(res.data[0].billing_mode, 'postpay');
});

test('R2: A reads campaigns — only its own, never B\'s', { skip: SKIP }, async () => {
  const res = await restGet('campaigns', 'select=id,advertiser_id', A_JWT);
  assert.ok(res.ok, `read failed: ${res.status} ${JSON.stringify(res.data)}`);
  const ids = res.data.map((r) => r.id);
  assert.ok(ids.includes(A.campId), 'A must see its own campaign');
  assert.ok(!ids.includes(B.campId), 'A must NOT see B\'s campaign (cross-advertiser leak)');
  assert.ok(res.data.every((r) => r.advertiser_id === A.advId), 'every visible campaign belongs to A');
});

test('R3: A reads line_items + creatives — only its own', { skip: SKIP }, async () => {
  const li = await restGet('line_items', 'select=id,campaign_id', A_JWT);
  assert.ok(li.ok, `line_items read failed: ${li.status}`);
  assert.deepEqual(li.data.map((r) => r.id), [A.liId], 'A sees only its own line_item');

  const cr = await restGet('creatives', 'select=id,line_item_id', A_JWT);
  assert.ok(cr.ok, `creatives read failed: ${cr.status}`);
  assert.deepEqual(cr.data.map((r) => r.id), [A.crId], 'A sees only its own creative');
});

test('R4: advertiser B reads campaigns — only its own (symmetry)', { skip: SKIP }, async () => {
  const res = await restGet('campaigns', 'select=id,advertiser_id', B_JWT);
  assert.ok(res.ok, `read failed: ${res.status}`);
  const ids = res.data.map((r) => r.id);
  assert.ok(ids.includes(B.campId), 'B must see its own campaign');
  assert.ok(!ids.includes(A.campId), 'B must NOT see A\'s campaign');
});

test('R5: advertiser_self_id / advertiser_check resolve the caller\'s own org', { skip: SKIP }, async () => {
  const selfId = await rpc('advertiser_self_id', {}, A_JWT);
  assert.ok(selfId.ok, `advertiser_self_id failed: ${selfId.status} ${JSON.stringify(selfId.data)}`);
  assert.equal(selfId.data, A.advId, 'advertiser_self_id must return the caller\'s own advertiser id');

  const check = await rpc('advertiser_check', {}, A_JWT);
  assert.ok(check.ok);
  assert.equal(check.data, true, 'advertiser_check must be true for a mapped session');
});

test('R6: column-scope — stripe_customer_id / is_house are not readable; safe columns are', { skip: SKIP }, async () => {
  const stripe = await restGet('advertisers', `id=eq.${A.advId}&select=stripe_customer_id`, A_JWT);
  assert.ok(!stripe.ok, `selecting stripe_customer_id must be denied, got ${stripe.status}: ${JSON.stringify(stripe.data)}`);

  const house = await restGet('advertisers', `id=eq.${A.advId}&select=is_house`, A_JWT);
  assert.ok(!house.ok, `selecting is_house must be denied, got ${house.status}`);

  const ok = await restGet('advertisers', `id=eq.${A.advId}&select=id,name,status,billing_mode,created_at`, A_JWT);
  assert.ok(ok.ok, `the safe columns must be readable, got ${ok.status}: ${JSON.stringify(ok.data)}`);
  assert.equal(ok.data[0]?.id, A.advId);
});

test('R7: DML lockdown — A cannot INSERT/UPDATE the booking tables via PostgREST', { skip: SKIP }, async () => {
  const insCamp = await restWrite('POST', 'campaigns', '', { advertiser_id: A.advId, name: 'sneaky' }, A_JWT);
  assert.ok(!insCamp.ok, `INSERT campaign must be denied (grant revoked), got ${insCamp.status}`);

  const updAdv = await restWrite('PATCH', 'advertisers', `id=eq.${A.advId}`, { name: 'renamed-by-client' }, A_JWT);
  assert.ok(!updAdv.ok, `UPDATE advertisers must be denied (grant revoked), got ${updAdv.status}`);

  const updLi = await restWrite('PATCH', 'line_items', `id=eq.${A.liId}`, { cpva_bid_micros: 999999 }, A_JWT);
  assert.ok(!updLi.ok, `UPDATE line_items must be denied (grant revoked), got ${updLi.status}`);

  // And the row is genuinely untouched.
  const still = psql(`select name from public.advertisers where id='${A.advId}';`);
  assert.equal(still, 'Adv A', 'advertisers row must be unchanged by the rejected PATCH');
});

test('R8: anon is rejected everywhere', { skip: SKIP }, async () => {
  const camps = await restGet('campaigns', 'select=id', null);
  assert.ok(!camps.ok || (Array.isArray(camps.data) && camps.data.length === 0),
    `anon must read zero campaigns, got ${camps.status}: ${JSON.stringify(camps.data)}`);

  const check = await rpc('advertiser_check', {}, null);
  assert.ok(!check.ok, `anon must not be able to call advertiser_check, got ${check.status}`);

  const ensure = await rpc('ensure_advertiser_user', {}, null);
  assert.ok(!ensure.ok, `anon must not be able to call ensure_advertiser_user, got ${ensure.status}`);
});

test('R9: a caller already mapped to a publisher is refused provisioning', { skip: SKIP }, async () => {
  const res = await rpc('ensure_advertiser_user', {}, PUB_JWT);
  assert.ok(!res.ok, `a publisher must be refused advertiser provisioning, got ${res.status}: ${JSON.stringify(res.data)}`);
  const mapped = psql(`select count(*) from public.advertiser_users where auth_user_id='${PUB.authId}';`);
  assert.equal(mapped, '0', 'no advertiser_users row may be created for a publisher identity');
});

test('R9b: the MIRROR guard — ensure_publisher refuses an identity already mapped to an advertiser', { skip: SKIP }, async () => {
  // A is an advertiser (mapped in seedFixture). The bidirectional self-deal guard: ensure_publisher
  // must refuse a caller whose auth.uid() resolves to an advertiser_user, symmetric to R9.
  const res = await rpc('ensure_publisher', { p_handle: null }, A_JWT);
  assert.ok(!res.ok, `an advertiser must be refused publisher provisioning, got ${res.status}: ${JSON.stringify(res.data)}`);
  const madePub = psql(`select count(*) from public.publishers where auth_user_id='${A.authId}';`);
  assert.equal(madePub, '0', 'no publishers row may be created for an advertiser identity');
});

test('R10: self-create — a fresh session provisions a prepay org + mapping', { skip: SKIP }, async () => {
  const res = await rpc('ensure_advertiser_user', {}, FRESH_JWT);
  assert.ok(res.ok, `ensure_advertiser_user failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.created, true, 'first provisioning must report created=true');
  assert.ok(res.data?.advertiser_id, 'must return the new advertiser id');
  FRESH.advId = res.data.advertiser_id;

  const row = psql(`select name||'|'||billing_mode||'|'||is_house from public.advertisers where id='${FRESH.advId}';`);
  assert.equal(row, 'New advertiser|prepay|false', 'new org must be a prepay, non-house "New advertiser"');

  const mapped = psql(`select advertiser_id||'|'||role from public.advertiser_users where auth_user_id='${FRESH.authId}';`);
  assert.equal(mapped, `${FRESH.advId}|owner`, 'the caller must be mapped to the new org as owner');

  if (HAS_BALANCES) {
    const bal = psql(`select balance_micros||'|'||reserved_micros from public.advertiser_balances where advertiser_id='${FRESH.advId}';`);
    assert.equal(bal, '0|0', 'a zero balance row must be seeded');
  }

  const check = await rpc('advertiser_check', {}, FRESH_JWT);
  assert.equal(check.data, true, 'advertiser_check must now be true for the freshly provisioned session');
});

test('R11: provisioning is idempotent', { skip: SKIP }, async () => {
  const res = await rpc('ensure_advertiser_user', {}, FRESH_JWT);
  assert.ok(res.ok, `second call failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.created, false, 'second provisioning must be a no-op (created=false)');
  assert.equal(res.data?.advertiser_id, FRESH.advId, 'must return the SAME org, never mint a second');
  const count = psql(`select count(*) from public.advertisers where id='${FRESH.advId}';`);
  assert.equal(count, '1', 'exactly one org for the identity');
});

test('R12: an admin sees BOTH A and B (admin_all coexists with select_own)', { skip: SKIP }, async () => {
  const camps = await restGet('campaigns', 'select=id', ADMIN_JWT);
  assert.ok(camps.ok, `admin campaigns read failed: ${camps.status}`);
  const ids = camps.data.map((r) => r.id);
  assert.ok(ids.includes(A.campId) && ids.includes(B.campId), 'admin must see both A\'s and B\'s campaigns');

  const users = await restGet('advertiser_users', `advertiser_id=in.(${A.advId},${B.advId})&select=auth_user_id`, ADMIN_JWT);
  assert.ok(users.ok, `admin advertiser_users read failed: ${users.status}`);
  const authIds = users.data.map((r) => r.auth_user_id);
  assert.ok(authIds.includes(A.authId) && authIds.includes(B.authId), 'admin must see both mappings');
});
