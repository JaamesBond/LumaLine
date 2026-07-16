// test/advertiser-serving.integration.mjs — M9-T3: advertiser serving guard rails (hot path).
//
// 20260716180000_advertiser_serving_guardrails.sql patches the per-tick billing hot path:
// window_open (sentinel is_house fix, self-deal exclusion, prepay availability, backed reserve,
// NULL-on-fail), close_window (reserve true-up / release on every terminal path), sweep_stale_windows
// (release stranded reserves), and the structural CPVA-only + min-bid CHECK on line_items.
//
// TWO layers:
//   • STATIC (always runs, no DB) — asserts the migration file carries each required diff, so a
//     regression that drops the sentinel is_house fix / self-deal exclusion / reserve / release / CHECK
//     is caught in the protected-main `node --test` gate even without a local stack.
//   • INTEGRATION (self-skips without the local Supabase stack + psql) — drives the real window_open /
//     close_window / sweep_stale_windows RPCs and the CHECK constraint against the local DB.
//
// WHAT IS TESTED (integration):
//   CS1..CS4 — the CHECK: non-house PREPAY line_item with cpc>0 or a sub-floor cpva is rejected;
//              a floor-clearing cpva/cpc=0 prepay row is accepted; a POSTPAY row is unconstrained
//   RB1      — RESERVE BACKING: a served prepay creative stamps ad_windows.reserve_micros = estimate
//              and bumps advertiser_balances.reserved by that estimate (the backed-reserve invariant)
//   NF1      — NO-FILL on insufficient funds: a prepay advertiser whose AVAILABLE cannot cover the
//              estimate NEVER serves (no reserve, no impression) — a true no-fill
//   SD1      — SELF-DEAL exclusion: an advertiser sharing an auth.uid() with the viewing publisher is
//              never served to that publisher; an unrelated advertiser still serves (positive control)
//   SN1      — SENTINEL unaffected: the sentinel path serves ONLY is_house — an approved NON-house
//              zero-bid creative never reaches the anon/sentinel pool (needs seed.prod sentinel)
//   RG1      — REGRESSION: a POSTPAY creative still serves and carries reserve_micros = 0 (no reserve)
//   CT1      — close_window TRUE-UP: a credited prepay window releases estimate-gross and keeps
//              reserve_micros = gross (the credited-undrawn hold)
//   SW1      — sweep_stale_windows releases a stranded prepay reserve and zeroes reserve_micros

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

// ---------------------------------------------------------------------------
// STATIC (always runs) — the migration must carry each required hot-path diff.
// ---------------------------------------------------------------------------
const MIGRATION = join(
  dirname(fileURLToPath(import.meta.url)), '..', 'supabase', 'migrations',
  '20260716180000_advertiser_serving_guardrails.sql',
);
const SQL = readFileSync(MIGRATION, 'utf8');

test('STATIC: window_open sentinel path gains the is_house=true gate', () => {
  assert.match(SQL, /a\.is_house\s*=\s*true\s*\n\s*and li\.cpva_bid_micros\s*=\s*0/i,
    'the sentinel candidate filter must require a.is_house = true before the zero-bid gate');
});

test('STATIC: window_open real path gains the self-deal exclusion', () => {
  assert.match(SQL, /not exists\s*\([\s\S]*?advertiser_users au[\s\S]*?join public\.publishers p[\s\S]*?p\.id\s*=\s*v_pub/i,
    'the real candidate query must exclude an advertiser sharing an auth.uid() with the viewing publisher');
});

test('STATIC: window_open real path gains the prepay availability pre-filter', () => {
  assert.match(SQL, /a\.billing_mode\s*<>\s*'prepay'\s*or exists\s*\([\s\S]*?advertiser_balances ab[\s\S]*?balance_micros\s*-\s*ab\.reserved_micros/i,
    'a prepay advertiser must be gated on AVAILABLE >= estimate; postpay unaffected');
});

test('STATIC: window_open takes a backed reserve and NULLs the creative on failure', () => {
  assert.match(SQL, /if not app\.advertiser_reserve\(\s*v_creative\.advertiser_id\s*,\s*v_reserve\s*\)/i,
    'window_open must call app.advertiser_reserve for a prepay creative');
  assert.match(SQL, /v_serve\s*:=\s*false;\s*[^\n]*\n\s*v_reserve\s*:=\s*0;/i,
    'a failed reserve must fall through to a true no-fill (v_serve=false, v_reserve=0)');
  assert.match(SQL, /reserve_micros\)\s*\n\s*values\s*\([\s\S]*?v_reserve\)/i,
    'ad_windows insert must stamp reserve_micros = v_reserve');
});

test('STATIC: close_window releases / trues up the reserve on terminal paths', () => {
  assert.match(SQL, /perform app\.advertiser_release\(v_adv,\s*w\.reserve_micros\)/i,
    'abandon/void paths must release the full hold');
  assert.match(SQL, /perform app\.advertiser_release\(v_adv,\s*w\.reserve_micros\s*-\s*v_gross\)/i,
    'the credited path must release the over-estimate (estimate - gross)');
  assert.match(SQL, /reserve_micros\s*=\s*CASE WHEN w\.reserve_micros\s*>\s*0 THEN v_gross/i,
    'the credited window must keep reserve_micros = gross');
});

test('STATIC: sweep_stale_windows releases stranded reserves and preserves grants', () => {
  assert.match(SQL, /for update of w skip locked/i, 'sweep must claim rows with FOR UPDATE SKIP LOCKED');
  assert.match(SQL, /perform app\.advertiser_release\(v_adv,\s*r\.reserve_micros\)/i,
    'sweep must release each abandoned window\'s reserve');
  assert.match(SQL, /revoke execute on function public\.sweep_stale_windows\(interval\) from public, anon, authenticated/i);
});

test('STATIC: the CPVA-only + min-bid CHECK constraint is added structurally', () => {
  assert.match(SQL, /check_selfserve_line_item[\s\S]*?p_cpc\s*=\s*0 AND p_cpva\s*>=\s*app\.advertiser_min_bid_micros\(\)/i,
    'the helper must require cpc=0 AND cpva>=floor for non-house prepay');
  assert.match(SQL, /ADD CONSTRAINT\s+line_items_selfserve_bids\s+CHECK/i,
    'the line_items CHECK constraint must be added');
});

// ---------------------------------------------------------------------------
// INTEGRATION — self-skips without the local stack + psql + this migration.
// ---------------------------------------------------------------------------
const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL    = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// Sentinel identity — must match the SENTINEL_PUB constant in window_open + seed.prod.sql.
const SENTINEL = {
  sub: '5e470000-0000-4000-8000-000000000001',
  publisher_id: '5e470000-0000-4000-8000-0000000000b1',
  device_id: '5e470000-0000-4000-8000-0000000000d1',
};

const MIN_BID = 1000;     // app.advertiser_min_bid_micros() placeholder (20260716170000)
const CPVA    = 2000;     // a floor-clearing bid used across the serving tests
const ESTIMATE = 5 * CPVA; // ceil(5000/1000) * cpva = the serve-time reserve estimate = 10000
const BIG_WEIGHT = 1_000_000;   // dominate the seed line (weight 1) so a serve of our line is quick

function mintDeviceJwt({ sub, publisher_id, device_id }) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, publisher_id, device_id, iat: 1700000000, exp: 2000000000 });
  const sig = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function psqlError(sql) {
  try { psql(sql); return null; } catch (e) { return String(e?.stderr ?? e?.message ?? e); }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

async function rpc(name, body, jwt) {
  const headers = { apikey: ANON, 'content-type': 'application/json' };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  const res = await fetch(`${REST_BASE}/rpc/${name}`, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
  const text = await res.text();
  if (!res.ok) throw new Error(`rpc ${name} -> HTTP ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}
const openWindow = (jwt) => rpc('window_open', { p_activity_snapshot: 'session' }, jwt);

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const HAS_MIGRATION = PSQL_OK && psql(`select exists(select 1 from pg_constraint where conname='line_items_selfserve_bids');`) === 't';
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !HAS_MIGRATION ? 'line_items_selfserve_bids absent (migration not applied) — SKIPPING'
  : false;
if (SKIP) console.log(`[advertiser-serving.integration] ${SKIP}`);

const SENTINEL_SEEDED = !SKIP && psql(`select exists(select 1 from public.publishers where id='${SENTINEL.publisher_id}');`) === 't';
if (!SKIP && !SENTINEL_SEEDED) console.log('[advertiser-serving.integration] sentinel not seeded — SN1 will SKIP (apply seed.prod.sql).');

// ---------------------------------------------------------------------------
// Fixtures + teardown. Every test mints fresh random ids (isolated from other files).
// ---------------------------------------------------------------------------
const advIds = [], pubIds = [], authIds = [];

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '')
    on conflict (id) do nothing;`);
  authIds.push(id);
}

// A dedicated publisher + device + backing auth user, returning a device JWT.
function seedPublisher() {
  const authId = randomUUID(), pubId = randomUUID(), deviceId = randomUUID();
  seedUser(authId, `advserv-pub-${pubId.slice(0, 8)}@example.com`);
  psql(`insert into public.publishers (id, auth_user_id, handle, status) values ('${pubId}','${authId}','advserv-${pubId.slice(0,8)}','active');`);
  psql(`insert into public.devices (id, publisher_id) values ('${deviceId}','${pubId}');`);
  pubIds.push(pubId);
  return { authId, pubId, deviceId, jwt: mintDeviceJwt({ sub: authId, publisher_id: pubId, device_id: deviceId }) };
}

// A campaign under a fresh advertiser (prepay/postpay, house or not) + optional balance row.
function seedOrg({ billingMode = 'prepay', isHouse = false, balance = null, reserved = 0 } = {}) {
  const advId = randomUUID(), campId = randomUUID();
  psql(`insert into public.advertisers (id, name, status, billing_mode, is_house)
        values ('${advId}','Adv ${advId.slice(0,8)}','active','${billingMode}',${isHouse});`);
  if (balance !== null) {
    psql(`insert into public.advertiser_balances (advertiser_id, balance_micros, reserved_micros) values ('${advId}',${balance},${reserved});`);
  }
  psql(`insert into public.campaigns (id, advertiser_id, name, status) values ('${campId}','${advId}','camp','active');`);
  advIds.push(advId);
  return { advId, campId };
}

// A line_item + creative with a unique line (so we can spot it in window_open output).
//   status='active'         → in the real-publisher pool (the serve-dependent tests).
//   status='draft'          → NEVER served (CT1/SW1 seed windows directly — zero pool pollution).
//   budgetTotal=0           → excluded from the real-publisher rotation (0 < 0 in the total-budget
//                             guard, like the seed self-promo line) while still exercising the
//                             sentinel is_house gate — so SN1 is non-polluting too.
function seedServable(campId, { cpva = CPVA, cpc = 0, weight = BIG_WEIGHT, status = 'active', budgetTotal = null } = {}) {
  const liId = randomUUID(), crId = randomUUID(), line = `advserv-${crId.slice(0, 12)}`;
  const budCol = budgetTotal === null ? '' : ', budget_total_micros';
  const budVal = budgetTotal === null ? '' : `, ${budgetTotal}`;
  psql(`insert into public.line_items (id, campaign_id, cpva_bid_micros, cpc_bid_micros, weight, targeting, status, start_at, end_at${budCol})
        values ('${liId}','${campId}',${cpva},${cpc},${weight},'{}','${status}', now()-interval '1 hour', now()+interval '30 days'${budVal});`);
  psql(`insert into public.creatives (id, line_item_id, line, dest_url, label, status)
        values ('${crId}','${liId}','${line}',null,'sponsored','active');`);
  return { liId, crId, line };
}

// Remove an advertiser's active creatives + line_items from the serving pool ASAP (called in each
// serve-dependent test's finally), so a high-weight line pollutes the global rotation for the
// shortest possible window — the good-citizen bound the existing weighted-rotation tests observe.
function stopServing(advId) {
  try {
    psql(`set session_replication_role = replica;
      delete from public.creatives where line_item_id in (select id from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id='${advId}'));
      delete from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id='${advId}');
      reset session_replication_role;`);
  } catch { /* best-effort */ }
}

function getBalance(advId) {
  const row = psql(`select coalesce(balance_micros,0)||'|'||coalesce(reserved_micros,0) from public.advertiser_balances where advertiser_id='${advId}';`);
  const [b, r] = (row || '0|0').split('|');
  return { balance: Number(b), reserved: Number(r) };
}
const windowReserve = (wid) => Number(psql(`select coalesce(reserve_micros,0) from public.ad_windows where window_id='${wid}';`));
const windowState   = (wid) => psql(`select state from public.ad_windows where window_id='${wid}';`);

// Open windows until our unique line serves (returns its window_id) or give up after n tries.
async function openUntilServed(jwt, line, n = 30) {
  for (let i = 0; i < n; i++) {
    const w = await openWindow(jwt);
    if (w.ad && w.ad.line === line) return w.window_id;
  }
  return null;
}
// Collect the served lines over n opens (for absence assertions).
async function servedLines(jwt, n = 30) {
  const out = [];
  for (let i = 0; i < n; i++) { const w = await openWindow(jwt); out.push(w.ad && w.ad.line ? w.ad.line : null); }
  return out;
}

function teardown() {
  try {
    const a = advIds.map((x) => `'${x}'`).join(',');
    const p = pubIds.map((x) => `'${x}'`).join(',');
    const u = authIds.map((x) => `'${x}'`).join(',');
    const parts = ['set session_replication_role = replica;'];
    if (p) {
      parts.push(`delete from public.impressions where publisher_id in (${p});`);
      parts.push(`delete from public.clicks where publisher_id in (${p});`);
      parts.push(`delete from public.ad_windows where publisher_id in (${p});`);
      parts.push(`delete from public.serve_counters where publisher_id in (${p});`);
    }
    if (a) {
      parts.push(`delete from public.ledger_entries where advertiser_id in (${a});`);
      parts.push(`delete from public.advertiser_balance_ledger where advertiser_id in (${a});`);
      parts.push(`delete from public.advertiser_balances where advertiser_id in (${a});`);
      parts.push(`delete from public.creatives where line_item_id in (select id from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id in (${a})));`);
      parts.push(`delete from public.line_item_daily_stats where line_item_id in (select id from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id in (${a})));`);
      parts.push(`delete from public.line_items where campaign_id in (select id from public.campaigns where advertiser_id in (${a}));`);
      parts.push(`delete from public.campaigns where advertiser_id in (${a});`);
      parts.push(`delete from public.advertiser_users where advertiser_id in (${a});`);
      parts.push(`delete from public.advertisers where id in (${a});`);
    }
    if (p) parts.push(`delete from public.devices where publisher_id in (${p});`);
    if (p) parts.push(`delete from public.publishers where id in (${p});`);
    if (u) parts.push(`delete from auth.users where id in (${u});`);
    parts.push('reset session_replication_role;');
    psql(parts.join('\n'));
  } catch { /* best-effort */ }
}
if (!SKIP) process.on('exit', teardown);

// ---------------------------------------------------------------------------
// CS1..CS4 — the structural CPVA-only + min-bid CHECK (deterministic, psql only).
// ---------------------------------------------------------------------------
test('CS1: non-house PREPAY line_item with cpc>0 is rejected by the CHECK', { skip: SKIP }, () => {
  const { campId } = seedOrg({ billingMode: 'prepay', balance: 0 });
  const err = psqlError(`insert into public.line_items (campaign_id, cpva_bid_micros, cpc_bid_micros, status) values ('${campId}',${CPVA},100,'draft');`);
  assert.match(err ?? '', /line_items_selfserve_bids|violates check constraint/, 'cpc>0 on a prepay non-house line must be rejected');
});

test('CS2: non-house PREPAY line_item with a sub-floor cpva is rejected', { skip: SKIP }, () => {
  const { campId } = seedOrg({ billingMode: 'prepay', balance: 0 });
  const err = psqlError(`insert into public.line_items (campaign_id, cpva_bid_micros, cpc_bid_micros, status) values ('${campId}',${MIN_BID - 1},0,'draft');`);
  assert.match(err ?? '', /line_items_selfserve_bids|violates check constraint/, 'a cpva below the floor must be rejected');
});

test('CS3: non-house PREPAY line_item at/above floor with cpc=0 is accepted', { skip: SKIP }, () => {
  const { campId } = seedOrg({ billingMode: 'prepay', balance: 0 });
  const err = psqlError(`insert into public.line_items (campaign_id, cpva_bid_micros, cpc_bid_micros, status) values ('${campId}',${MIN_BID},0,'draft');`);
  assert.equal(err, null, 'a floor-clearing CPVA-only prepay line must be accepted');
});

test('CS4: POSTPAY line_item is UNCONSTRAINED by the self-serve CHECK (legacy CPC allowed)', { skip: SKIP }, () => {
  const { campId } = seedOrg({ billingMode: 'postpay' });   // no balance row (postpay)
  const err = psqlError(`insert into public.line_items (campaign_id, cpva_bid_micros, cpc_bid_micros, status) values ('${campId}',0,200,'draft');`);
  assert.equal(err, null, 'a postpay line with cpc>0 and cpva=0 must be allowed (legacy path unchanged)');
});

// ---------------------------------------------------------------------------
// RB1 — RESERVE BACKING: a served prepay creative stamps the window reserve + bumps reserved.
// ---------------------------------------------------------------------------
test('RB1: a served prepay creative stamps ad_windows.reserve_micros and bumps reserved', { skip: SKIP }, async () => {
  const { advId, campId } = seedOrg({ billingMode: 'prepay', balance: 100_000_000 });
  const { line } = seedServable(campId);
  const pub = seedPublisher();
  try {
    const wid = await openUntilServed(pub.jwt, line);
    assert.ok(wid, 'the funded prepay creative must serve within N opens (weighted dominance)');
    assert.equal(windowReserve(wid), ESTIMATE, 'ad_windows.reserve_micros stamped with the estimate = 5*cpva');
    assert.equal(getBalance(advId).reserved, ESTIMATE, 'advertiser_balances.reserved bumped by exactly the estimate (backed reserve)');
  } finally { stopServing(advId); }
});

// ---------------------------------------------------------------------------
// NF1 — NO-FILL on insufficient funds: an unfunded prepay creative never serves / never reserves.
// ---------------------------------------------------------------------------
test('NF1: a prepay advertiser whose AVAILABLE cannot cover the estimate never serves (true no-fill)', { skip: SKIP }, async () => {
  // AVAILABLE = balance - reserved = ESTIMATE - 1 < ESTIMATE → filtered out of the candidate pool
  // for EVERY publisher (so this line never competes — the test is inherently non-polluting).
  const { advId, campId } = seedOrg({ billingMode: 'prepay', balance: ESTIMATE - 1 });
  const { line } = seedServable(campId);
  const pub = seedPublisher();
  try {
    const lines = await servedLines(pub.jwt, 20);
    assert.ok(!lines.includes(line), 'an unfunded prepay creative must NEVER serve (availability pre-filter)');
    assert.equal(getBalance(advId).reserved, 0, 'no reserve is taken for a no-fill');
    assert.equal(psql(`select count(*) from public.impressions i join public.line_items li on li.id=i.line_item_id join public.campaigns c on c.id=li.campaign_id where c.advertiser_id='${advId}';`), '0', 'no impression booked for the unfunded advertiser');
  } finally { stopServing(advId); }
});

// ---------------------------------------------------------------------------
// NF2 — RESERVE-FAIL RACE: concurrent opens against a 1-estimate advertiser never over-reserve.
// The reserve exists to close the race where the availability PRE-filter passes but a concurrent
// burst drains AVAILABLE so app.advertiser_reserve returns false — window_open must then NULL the
// creative (a clean no-fill: no reserve, no stamped window), never bill an unfunded impression.
// ---------------------------------------------------------------------------
test('NF2: concurrent window_opens for a 1-estimate advertiser never over-reserve (reserve-fail → clean no-fill)', { skip: SKIP }, async () => {
  const { advId, campId } = seedOrg({ billingMode: 'prepay', balance: ESTIMATE });  // AVAILABLE = exactly ONE estimate
  const { line } = seedServable(campId);
  const pubs = [seedPublisher(), seedPublisher(), seedPublisher(), seedPublisher()];
  try {
    // Fire four concurrent opens. Whichever the weighted selection picks, the MONEY-SAFETY invariants
    // below hold under ANY interleaving (the guarded FOR-UPDATE reserve serializes the drain).
    await Promise.all(pubs.map((p) => openWindow(p.jwt)));
    const bal = getBalance(advId);
    assert.ok(bal.reserved <= ESTIMATE, `reserved must never exceed the one funded estimate (got ${bal.reserved})`);
    assert.ok(bal.reserved <= bal.balance, 'reserved never exceeds balance (available >= 0)');
    // At most floor(balance/estimate) = 1 window may hold a reserve; the rest reserve-fail to no-fill.
    const reservedWindows = Number(psql(`select count(*) from public.ad_windows w
      join public.line_items li on li.id = w.line_item_id
      join public.campaigns  c  on c.id  = li.campaign_id
      where c.advertiser_id='${advId}' and w.reserve_micros > 0;`));
    assert.ok(reservedWindows <= 1, `at most one window may hold a reserve (got ${reservedWindows})`);
    assert.ok(bal.reserved === 0 || bal.reserved === ESTIMATE,
      `reserved is 0 or EXACTLY one estimate — never a partial/over-hold (got ${bal.reserved})`);
  } finally { stopServing(advId); }
});

// ---------------------------------------------------------------------------
// SD1 — SELF-DEAL exclusion: an advertiser sharing the publisher's auth.uid() is never served to it.
// ---------------------------------------------------------------------------
test('SD1: an advertiser sharing an auth.uid() with the publisher is excluded; an unrelated one serves', { skip: SKIP }, async () => {
  // Publisher P whose auth.uid() ALSO owns advertiser A (the self-deal). Seeded directly (bypassing
  // the provisioning refusal) to exercise the serving-layer defense-in-depth.
  const authId = randomUUID(), pubId = randomUUID(), deviceId = randomUUID();
  seedUser(authId, `advserv-selfdeal-${authId.slice(0, 8)}@example.com`);
  psql(`insert into public.publishers (id, auth_user_id, handle, status) values ('${pubId}','${authId}','advserv-sd-${pubId.slice(0,8)}','active');`);
  psql(`insert into public.devices (id, publisher_id) values ('${deviceId}','${pubId}');`);
  pubIds.push(pubId);
  const jwt = mintDeviceJwt({ sub: authId, publisher_id: pubId, device_id: deviceId });

  const A = seedOrg({ billingMode: 'prepay', balance: 100_000_000 });
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role) values ('${authId}','${A.advId}','owner');`);
  const aLine = seedServable(A.campId).line;   // A's creative — must NEVER serve to P

  const B = seedOrg({ billingMode: 'prepay', balance: 100_000_000 });
  const bLine = seedServable(B.campId).line;   // B's creative — unrelated, MUST be servable to P
  try {
    const lines = await servedLines(jwt, 20);
    assert.ok(!lines.includes(aLine), 'the self-dealt advertiser A must NEVER serve to its own auth.uid() publisher');
    assert.ok(lines.includes(bLine), 'an UNRELATED advertiser B still serves to P (proves absence of A is the exclusion, not a dead stack)');
    assert.equal(getBalance(A.advId).reserved, 0, 'A took no reserve (never served)');
  } finally { stopServing(A.advId); stopServing(B.advId); }
});

// ---------------------------------------------------------------------------
// SN1 — SENTINEL unaffected: a NON-house zero-bid creative never reaches the sentinel/anon pool.
// ---------------------------------------------------------------------------
test('SN1: the sentinel path serves only is_house — a non-house zero-bid creative never leaks', {
  skip: SKIP ? SKIP : !SENTINEL_SEEDED ? 'sentinel not seeded (apply seed.prod.sql)' : false,
}, async () => {
  // A NON-house POSTPAY advertiser with an approved cpva=0/cpc=0 creative: under the OLD sentinel
  // gate (no is_house predicate) this would have served to the sentinel. The M9 fix excludes it.
  // budgetTotal=0 keeps it out of the real-publisher rotation (the sentinel path ignores budget),
  // so this test does not pollute the shared pool while still exercising the is_house gate.
  const { advId, campId } = seedOrg({ billingMode: 'postpay', isHouse: false });
  const { line } = seedServable(campId, { cpva: 0, cpc: 0, budgetTotal: 0 });   // non-house zero-bid
  try {
    const jwt = mintDeviceJwt(SENTINEL);
    const lines = await servedLines(jwt, 20);
    assert.ok(!lines.includes(line), 'a non-house zero-bid creative must NEVER serve to the sentinel (is_house gate)');
  } finally { stopServing(advId); }
});

// ---------------------------------------------------------------------------
// RG1 — REGRESSION: a POSTPAY creative still serves and carries reserve_micros = 0 (no reserve).
// ---------------------------------------------------------------------------
test('RG1: a postpay creative still serves and stamps reserve_micros = 0 (existing behavior preserved)', { skip: SKIP }, async () => {
  const { advId, campId } = seedOrg({ billingMode: 'postpay' });   // no balance row — postpay never reserves
  const { line } = seedServable(campId);
  const pub = seedPublisher();
  try {
    const wid = await openUntilServed(pub.jwt, line);
    assert.ok(wid, 'a postpay creative still serves (weighted rotation unchanged)');
    assert.equal(windowReserve(wid), 0, 'a postpay serve takes NO reserve — reserve_micros stays 0');
  } finally { stopServing(advId); }
});

// ---------------------------------------------------------------------------
// CT1 — close_window TRUE-UP: release estimate-gross, keep reserve_micros = gross (deterministic).
// ---------------------------------------------------------------------------
test('CT1: a credited prepay window releases estimate-gross and keeps reserve_micros = gross', { skip: SKIP }, () => {
  const { advId, campId } = seedOrg({ billingMode: 'prepay', balance: 100_000_000, reserved: ESTIMATE });
  const { liId, crId } = seedServable(campId, { status: 'draft' });   // draft => never in the serving pool (non-polluting)
  const pub = seedPublisher();

  // Seed an OPEN window that passes every close gate (beats>=3, activity_progress, elapsed within
  // tolerance but yielding att=4 -> gross = 4*cpva = 8000 < estimate 10000), reserve stamped = estimate.
  const wid = randomUUID();
  psql(`insert into public.ad_windows (window_id, publisher_id, device_id, line_item_id, creative_id,
      challenge, nonce, beats_count, activity_progress, started_at, dwell_ms, hb_interval_ms,
      clearing_price_micros, reserve_micros, state)
    values ('${wid}','${pub.pubId}','${pub.deviceId}','${liId}','${crId}','ch','no',5,true,
      now()-interval '4200 milliseconds',5000,1000,${CPVA},${ESTIMATE},'open');`);

  return rpc('close_window', { p_window_id: wid }, pub.jwt).then((res) => {
    assert.equal(res.credited, true, `window must credit (reason=${res.reason})`);
    assert.equal(res.attention_seconds, 4, 'att = round(4.2s) = 4 (capped at real elapsed)');
    const gross = 4 * CPVA;   // 8000
    assert.equal(res.gross_micros, gross, 'gross = att * clearing');
    assert.equal(windowReserve(wid), gross, 'reserve_micros trued to gross (the credited-undrawn hold)');
    assert.equal(getBalance(advId).reserved, gross, 'reserved released by estimate-gross (10000 -> 8000)');
    assert.equal(windowState(wid), 'credited', 'window credited');
  });
});

// ---------------------------------------------------------------------------
// SW1 — sweep_stale_windows releases a stranded prepay reserve on the hot path.
// ---------------------------------------------------------------------------
test('SW1: sweep_stale_windows abandons a stale prepay window and releases its reserve', { skip: SKIP }, () => {
  const { advId, campId } = seedOrg({ billingMode: 'prepay', balance: 100_000_000, reserved: ESTIMATE });
  const { liId, crId } = seedServable(campId, { status: 'draft' });   // draft => never in the serving pool (non-polluting)
  const pub = seedPublisher();

  // A never-closed OPEN window from 20 minutes ago (past the 10-minute sweep cutoff), holding a reserve.
  const wid = randomUUID();
  psql(`insert into public.ad_windows (window_id, publisher_id, device_id, line_item_id, creative_id,
      challenge, nonce, started_at, reserve_micros, state)
    values ('${wid}','${pub.pubId}','${pub.deviceId}','${liId}','${crId}','ch','no',
      now()-interval '20 minutes',${ESTIMATE},'open');`);

  psql(`select public.sweep_stale_windows(interval '10 minutes');`);

  assert.equal(windowState(wid), 'abandoned', 'the stale window is abandoned');
  assert.equal(windowReserve(wid), 0, 'its reserve_micros is zeroed');
  assert.equal(getBalance(advId).reserved, 0, 'the stranded reserve is released on the hot path (10000 -> 0)');
});
