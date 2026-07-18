// test/advertiser-selfserve-rpcs.integration.mjs — M9-T4: advertiser self-serve write boundary.
//
// 20260716190000_advertiser_selfserve_rpcs.sql ships the ONLY write path advertisers get after the
// booking-table DML was revoked (20260716150000): self-scoped SECURITY DEFINER RPCs. Because those
// RPCs run as owner and bypass the locked table RLS, the RPC body is the entire isolation boundary.
// This suite proves that boundary holds:
//
//   * app.assert_owns_campaign/line_item/creative(uuid) — every child-id write RPC RAISEs 28000 for a
//     FOREIGN id (cross-advertiser IDOR). One negative case PER write RPC (a missed assert fails CI).
//   * app.creative_content_guard — a BEFORE INSERT/UPDATE TRIGGER on public.creatives rejects
//     control/ESC/OSC-8/CR/LF bytes, line>120, label>30, non-https dest on EVERY write path:
//     self-serve RPC, direct service_role INSERT (== admin-booking POST), content-changing UPDATE
//     (== the still-unvalidated admin-booking activate path). It never rejects a safe activation.
//   * check_selfserve_line_item CHECK — CPVA-only (cpc=0) + cpva>=floor is STRUCTURAL for non-house
//     prepay line_items regardless of write path (RPC AND a direct service_role INSERT are rejected);
//     legacy postpay / CPC line_items are unaffected.
//   * self-scoped CRUD — create/edit/pause work only on the caller's own rows; a creative can never
//     reach 'active' via a self-serve path; a cpva-bid change resets active creatives to pending_review.
//   * anon holds NO EXECUTE on any new function.
//
// Setup uses psql (auth.users + service_role writes are off the Data API); RPCs go through PostgREST
// with a per-user HS256 session JWT. Self-skips if the stack, psql, or the 190000 migration is absent.
//
// WHAT IS TESTED:
//   W1  — create_campaign: draft campaign under the caller's OWN advertiser (id derived, not passed)
//   W2  — create_line_item: draft, cpc FORCED 0, targeting global; happy path
//   W3  — create_line_item: cpva below floor → rejected (RPC in-body)
//   W4  — CHECK is structural: a direct service_role INSERT of a non-house prepay sub-floor / cpc>0
//         line_item is rejected by line_items_selfserve_bids
//   W5  — legacy POSTPAY line_item with cpc>0 / cpva=0 is UNAFFECTED by the self-serve CHECK
//   W6  — IDOR: create_line_item under a FOREIGN campaign → rejected; no row created
//   W7  — submit_creative: clean copy → pending_review (never active)
//   W8  — IDOR: submit_creative under a FOREIGN line_item → rejected; foreign line_item untouched
//   W9  — content TRIGGER via the self-serve RPC: ESC/OSC-8 in line → rejected
//   W10 — content TRIGGER via a direct service_role INSERT (admin-booking POST equiv) → rejected
//   W11 — content TRIGGER via a content-changing UPDATE (admin-booking activate equiv) → rejected;
//         a status-only activation of SAFE content SUCCEEDS (no over-blocking)
//   W12 — validator boundaries: line>120 / label>30 / non-https dest → rejected
//   W13 — IDOR: edit_line_item / edit_creative / set_campaign_status / set_line_item_status on a
//         FOREIGN id → each rejected; foreign rows untouched
//   W14 — edit_line_item: forces cpc=0, enforces min-bid, and a cpva-bid change RESETS the owning
//         active creatives to pending_review (no silent re-price below floor / cpc after approval)
//   W15 — a creative can never be self-activated; edit_creative re-validates + resets to pending_review
//   W16 — set_campaign_status / set_line_item_status: active<->paused only; draft rejected
//   W17 — update_profile: changes only `name`; protected columns untouched
//   W18 — summaries: campaigns_summary + spend_summary are self-scoped, aggregate, CPVA-only
//         (no per-publisher rows, no foreign advertiser data, clawed_back/void excluded)
//   W19 — anon / unmapped session refused on the write RPCs
//   W20 — has_function_privilege('anon', fn, 'EXECUTE') = false for every new function

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL    = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

const ESC = '\x1b';   // 0x1b — the ANSI/OSC-8 escape intro; a control byte the guard must reject.

function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

// psql that MUST succeed (ON_ERROR_STOP => non-zero exit + throw on any SQL error).
function psql(sql) {
  return execFileSync('psql', [DB_URL, '-v', 'ON_ERROR_STOP=1', '-tAqc', sql],
    { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

// psql that is EXPECTED to be rejected by a trigger / CHECK / constraint. Returns true iff the DB
// rejected it (non-zero exit under ON_ERROR_STOP). Without ON_ERROR_STOP psql exits 0 on SQL error,
// so this flag is load-bearing.
function psqlRejected(sql) {
  try {
    execFileSync('psql', [DB_URL, '-v', 'ON_ERROR_STOP=1', '-tAqc', sql],
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    return false;
  } catch { return true; }
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
const HAS_RPCS = PSQL_OK &&
  psql(`select to_regprocedure('public.advertiser_create_campaign(text)') is not null;`) === 't';
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !HAS_RPCS ? '20260716190000 not applied — SKIPPING'
  : false;
if (SKIP) console.log(`[advertiser-selfserve-rpcs.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixtures — A (the actor, prepay), B (a bystander advertiser, foreign IDOR targets), P (a legacy
// postpay advertiser for the CHECK-unaffected case), PUBX (a publisher for spend impressions).
// Self-serve orgs are prepay, so A's/B's line_items must satisfy the CPVA-only+min-bid CHECK
// (cpc=0, cpva>=floor=1000). All seeded creatives use SAFE content (else the content trigger would
// reject the seed).
// ---------------------------------------------------------------------------
const FLOOR = 1000;   // app.advertiser_min_bid_micros() placeholder (170000)

const A = {
  authId: randomUUID(), advId: randomUUID(), campId: randomUUID(),
  liId: randomUUID(), crId: randomUUID(),                 // active li + active creative (toggle/spend/UPDATE-trigger)
  liReset: randomUUID(), crReset: randomUUID(),           // paused li + active creative (edit + reset-on-bid-change)
};
A.email = `adv-sr-a-${A.authId}@example.com`;
const A_JWT = mintJwt(A.authId);

const B = { authId: randomUUID(), advId: randomUUID(), campId: randomUUID(), liId: randomUUID(), crId: randomUUID() };
B.email = `adv-sr-b-${B.authId}@example.com`;
const B_JWT = mintJwt(B.authId);

const P = { advId: randomUUID(), campId: randomUUID() };   // legacy postpay (admin-booked; no session)

const PUBX = { authId: randomUUID(), pubId: randomUUID() };
PUBX.email = `adv-sr-pub-${PUBX.authId}@example.com`;
PUBX.handle = `adv-sr-pub-${PUBX.pubId.slice(0, 8)}`;

const FRESH = { authId: randomUUID() };                    // authenticated but mapped to no org
const FRESH_JWT = mintJwt(FRESH.authId);

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
  seedUser(PUBX.authId, PUBX.email);
  seedUser(FRESH.authId, FRESH.email);

  psql(`insert into public.advertisers (id, name, status, billing_mode, is_house)
    values ('${A.advId}', 'Adv A', 'active', 'prepay',  false),
           ('${B.advId}', 'Adv B', 'active', 'prepay',  false),
           ('${P.advId}', 'Adv P', 'active', 'postpay', false);`);
  psql(`insert into public.advertiser_users (auth_user_id, advertiser_id, role)
    values ('${A.authId}', '${A.advId}', 'owner'),
           ('${B.authId}', '${B.advId}', 'owner');`);

  psql(`insert into public.campaigns (id, advertiser_id, name, status)
    values ('${A.campId}', '${A.advId}', 'A camp', 'active'),
           ('${B.campId}', '${B.advId}', 'B camp', 'active'),
           ('${P.campId}', '${P.advId}', 'P camp', 'active');`);

  // A + B prepay line_items MUST satisfy the CHECK (cpc=0, cpva>=floor).
  psql(`insert into public.line_items (id, campaign_id, cpva_bid_micros, cpc_bid_micros, status)
    values ('${A.liId}',    '${A.campId}', 5000, 0, 'active'),
           ('${A.liReset}', '${A.campId}', 5000, 0, 'paused'),
           ('${B.liId}',    '${B.campId}', 5000, 0, 'paused');`);
  psql(`insert into public.creatives (id, line_item_id, line, dest_url, label, status)
    values ('${A.crId}',    '${A.liId}',    'Sponsored: Acme Cloud', 'https://acme.example', 'sponsored', 'active'),
           ('${A.crReset}', '${A.liReset}', 'Sponsored: Acme Reset', 'https://acme.example', 'sponsored', 'active'),
           ('${B.crId}',    '${B.liId}',    'Sponsored: Beta Corp',  'https://beta.example',  'sponsored', 'active');`);

  // Publisher + impressions for the spend summary (valid billable vs excluded states, isolation).
  psql(`insert into public.publishers (id, auth_user_id, handle, status)
    values ('${PUBX.pubId}', '${PUBX.authId}', '${PUBX.handle}', 'active');`);
  psql(`insert into public.impressions (window_id, publisher_id, line_item_id, creative_id, attention_seconds, gross_micros, state)
    values ('${randomUUID()}', '${PUBX.pubId}', '${A.liId}', '${A.crId}', 5, 25000, 'cleared'),
           ('${randomUUID()}', '${PUBX.pubId}', '${A.liId}', '${A.crId}', 3, 50000, 'clawed_back'),
           ('${randomUUID()}', '${PUBX.pubId}', '${B.liId}', '${B.crId}', 9, 99000, 'cleared');`);
}

function teardownFixture() {
  try {
    psql(`delete from public.impressions where publisher_id='${PUBX.pubId}';`);
    psql(`delete from public.publishers where id='${PUBX.pubId}';`);
    psql(`delete from public.advertiser_users where auth_user_id in ('${A.authId}','${B.authId}');`);
    psql(`delete from public.advertisers where id in ('${A.advId}','${B.advId}','${P.advId}');`);
    psql(`delete from auth.users where id in ('${A.authId}','${B.authId}','${PUBX.authId}','${FRESH.authId}');`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

// ---------------------------------------------------------------------------
// W1–W6: campaign + line_item creation, cpc=0 forcing, structural CHECK, IDOR.
// ---------------------------------------------------------------------------
test('W1: create_campaign — draft campaign under the caller\'s own advertiser', { skip: SKIP }, async () => {
  const res = await rpc('advertiser_create_campaign', { p_name: '  My Campaign  ' }, A_JWT);
  assert.ok(res.ok, `create_campaign failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.status, 'draft');
  const cid = res.data?.campaign_id;
  assert.ok(cid, 'must return a campaign_id');
  const row = psql(`select advertiser_id||'|'||name||'|'||status from public.campaigns where id='${cid}';`);
  assert.equal(row, `${A.advId}|My Campaign|draft`, 'campaign must belong to A, name trimmed, status draft');
});

test('W2: create_line_item — draft, cpc forced 0, targeting global', { skip: SKIP }, async () => {
  const res = await rpc('advertiser_create_line_item',
    { p_campaign_id: A.campId, p_cpva_bid_micros: 5000, p_weight: 3 }, A_JWT);
  assert.ok(res.ok, `create_line_item failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.status, 'draft');
  assert.equal(res.data?.cpc_bid_micros, 0);
  A.liCreated = res.data?.line_item_id;
  const row = psql(`select cpc_bid_micros||'|'||cpva_bid_micros||'|'||weight||'|'||targeting::text||'|'||status
                      from public.line_items where id='${A.liCreated}';`);
  assert.equal(row, '0|5000|3|{}|draft', 'cpc forced 0, cpva 5000, weight 3, targeting {}, status draft');
});

test('W3: create_line_item — cpva below the min-bid floor is rejected', { skip: SKIP }, async () => {
  const res = await rpc('advertiser_create_line_item',
    { p_campaign_id: A.campId, p_cpva_bid_micros: FLOOR - 500 }, A_JWT);
  assert.ok(!res.ok, `sub-floor bid must be rejected, got ${res.status}: ${JSON.stringify(res.data)}`);
});

test('W4: check_selfserve_line_item is STRUCTURAL — a direct service_role INSERT is rejected', { skip: SKIP }, async () => {
  // Sub-floor cpva on a non-house prepay advertiser: rejected by the CHECK, not just the RPC.
  const subFloor = psqlRejected(
    `insert into public.line_items (campaign_id, cpva_bid_micros, cpc_bid_micros, status)
       values ('${A.campId}', ${FLOOR - 1}, 0, 'draft');`);
  assert.ok(subFloor, 'a sub-floor prepay line_item must be rejected by line_items_selfserve_bids');

  // cpc>0 on a non-house prepay advertiser: rejected (CPVA-only is structural).
  const withCpc = psqlRejected(
    `insert into public.line_items (campaign_id, cpva_bid_micros, cpc_bid_micros, status)
       values ('${A.campId}', 5000, 100, 'draft');`);
  assert.ok(withCpc, 'a cpc>0 prepay line_item must be rejected by line_items_selfserve_bids');
});

test('W5: legacy POSTPAY line_item (cpc>0, cpva=0) is unaffected by the self-serve CHECK', { skip: SKIP }, async () => {
  const ok = !psqlRejected(
    `insert into public.line_items (campaign_id, cpva_bid_micros, cpc_bid_micros, status)
       values ('${P.campId}', 0, 100, 'draft');`);
  assert.ok(ok, 'a postpay advertiser cpc>0 / zero-cpva line_item must be allowed');
});

test('W6: IDOR — create_line_item under a FOREIGN campaign is rejected; no row created', { skip: SKIP }, async () => {
  const before = psql(`select count(*) from public.line_items where campaign_id='${B.campId}';`);
  const res = await rpc('advertiser_create_line_item',
    { p_campaign_id: B.campId, p_cpva_bid_micros: 5000 }, A_JWT);
  assert.ok(!res.ok, `A must not create a line_item under B's campaign, got ${res.status}: ${JSON.stringify(res.data)}`);
  const after = psql(`select count(*) from public.line_items where campaign_id='${B.campId}';`);
  assert.equal(after, before, 'no line_item may be created under B\'s campaign');
});

// ---------------------------------------------------------------------------
// W7–W12: creative submission, IDOR, the content TRIGGER on every write path, validator bounds.
// ---------------------------------------------------------------------------
test('W7: submit_creative — clean copy lands pending_review (never active)', { skip: SKIP }, async () => {
  const res = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'Sponsored: Acme launches v2', p_dest_url: 'https://acme.example/v2' }, A_JWT);
  assert.ok(res.ok, `submit_creative failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.status, 'pending_review', 'a self-served creative must be pending_review, never active');
  A.crSubmitted = res.data?.creative_id;
  assert.equal(psql(`select status from public.creatives where id='${A.crSubmitted}';`), 'pending_review');
});

test('W8: IDOR — submit_creative under a FOREIGN line_item is rejected; foreign untouched', { skip: SKIP }, async () => {
  const before = psql(`select count(*) from public.creatives where line_item_id='${B.liId}';`);
  const res = await rpc('advertiser_submit_creative',
    { p_line_item_id: B.liId, p_line: 'sneaky', p_dest_url: 'https://x.example' }, A_JWT);
  assert.ok(!res.ok, `A must not submit under B's line_item, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(psql(`select count(*) from public.creatives where line_item_id='${B.liId}';`), before,
    'no creative may be created under B\'s line_item');
});

test('W9: content TRIGGER (self-serve RPC) — ESC / OSC-8 bytes in line are rejected', { skip: SKIP }, async () => {
  const esc = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: `Sponsored${ESC}[31m malicious`, p_dest_url: 'https://x.example' }, A_JWT);
  assert.ok(!esc.ok, `an ESC byte must be rejected, got ${esc.status}`);

  const osc8 = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: `Click ${ESC}]8;;https://evil.example${ESC}\\here`, p_dest_url: 'https://x.example' }, A_JWT);
  assert.ok(!osc8.ok, `an OSC-8 hyperlink sequence must be rejected, got ${osc8.status}`);
});

test('W10: content TRIGGER (direct service_role INSERT == admin-booking POST) — rejected', { skip: SKIP }, async () => {
  // E'...\x1b...' puts a real ESC byte into the SQL literal; the BEFORE INSERT trigger must reject it,
  // proving admin-booking's zero-validation POST /creatives is now structurally covered.
  const rejected = psqlRejected(
    `insert into public.creatives (line_item_id, line, dest_url, label, status)
       values ('${A.liCreated}', E'evil\\x1b[2Jline', 'https://x.example', 'sponsored', 'pending_review');`);
  assert.ok(rejected, 'a service_role INSERT of a control-byte creative must be rejected by the trigger');

  // A non-https dest is also rejected on the direct path.
  const httpRejected = psqlRejected(
    `insert into public.creatives (line_item_id, line, dest_url, label, status)
       values ('${A.liCreated}', 'clean line', 'http://insecure.example', 'sponsored', 'pending_review');`);
  assert.ok(httpRejected, 'a non-https dest_url must be rejected by the trigger on the direct path');
});

test('W11: content TRIGGER (content-changing UPDATE == activate path) — rejected; safe activation OK', { skip: SKIP }, async () => {
  // A content-changing UPDATE introducing an ESC byte must be rejected (any writer, incl. a future
  // activate path that also touches content).
  const badUpd = psqlRejected(
    `update public.creatives set line = E'x\\x1b]8;;h' where id='${A.crId}';`);
  assert.ok(badUpd, 'an UPDATE introducing a control byte must be rejected');

  // A status-only activation of already-SAFE content must SUCCEED (the trigger must not over-block —
  // this is the admin-booking activate happy path at the DB layer).
  const okActivate = !psqlRejected(`update public.creatives set status='active' where id='${A.crSubmitted}';`);
  assert.ok(okActivate, 'activating a safe creative (status-only UPDATE) must succeed');
  // restore for later tests (leave it as a normal reviewable row)
  psql(`update public.creatives set status='pending_review' where id='${A.crSubmitted}';`);
});

test('W12: validator boundaries — line>120 / label>30 / non-https dest are rejected', { skip: SKIP }, async () => {
  const longLine = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'x'.repeat(121), p_dest_url: 'https://x.example' }, A_JWT);
  assert.ok(!longLine.ok, `line>120 must be rejected, got ${longLine.status}`);

  const longLabel = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'ok', p_label: 'y'.repeat(31), p_dest_url: 'https://x.example' }, A_JWT);
  assert.ok(!longLabel.ok, `label>30 must be rejected, got ${longLabel.status}`);

  const httpDest = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'ok', p_dest_url: 'http://insecure.example' }, A_JWT);
  assert.ok(!httpDest.ok, `non-https dest must be rejected, got ${httpDest.status}`);

  // A NULL dest_url (view-only creative) is allowed.
  const noDest = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'view-only ok' }, A_JWT);
  assert.ok(noDest.ok, `a null dest_url must be allowed, got ${noDest.status}: ${JSON.stringify(noDest.data)}`);
});

test('W13: dest_url is BYTE-SANITIZED too — CR/LF/ESC/OSC-8 after https:// are rejected (RPC + trigger)', { skip: SKIP }, async () => {
  // The must-fix: control bytes AFTER the https:// prefix would flow into the click Location header /
  // the OSC-8 fallback target. The validator + trigger must reject them, not just check the prefix.
  const crlf = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'ok', p_dest_url: 'https://ok.example/a\r\nSet-Cookie:x' }, A_JWT);
  assert.ok(!crlf.ok, `a CR/LF dest_url must be rejected, got ${crlf.status}`);

  const osc = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'ok', p_dest_url: `https://ok.example${ESC}]8;;x` }, A_JWT);
  assert.ok(!osc.ok, `an ESC/OSC-8 dest_url must be rejected, got ${osc.status}`);

  // The trigger (direct service_role path == admin-booking) rejects a control-byte dest too.
  const trig = psqlRejected(
    `insert into public.creatives (line_item_id, line, dest_url, label, status)
       values ('${A.liCreated}', 'clean', E'https://ok.example/a\\x0d\\x0ab', 'sponsored', 'pending_review');`);
  assert.ok(trig, 'a control-byte dest_url must be rejected by the content TRIGGER on the direct path');
});

test('W14: disclosure label is a STRUCTURAL allow-list — sponsored/ad/promoted only', { skip: SKIP }, async () => {
  // The must-fix: a deceptive/homoglyph label must never be submittable. Allowed labels pass.
  for (const good of ['ad', 'promoted']) {
    const ok = await rpc('advertiser_submit_creative',
      { p_line_item_id: A.liCreated, p_line: 'clean line', p_label: good, p_dest_url: 'https://ok.example' }, A_JWT);
    assert.ok(ok.ok, `label '${good}' must be accepted, got ${ok.status}: ${JSON.stringify(ok.data)}`);
  }
  for (const bad of ['tip', 'free', 'official']) {
    const no = await rpc('advertiser_submit_creative',
      { p_line_item_id: A.liCreated, p_line: 'clean line', p_label: bad, p_dest_url: 'https://ok.example' }, A_JWT);
    assert.ok(!no.ok, `a deceptive label '${bad}' must be rejected, got ${no.status}`);
  }
  // A Cyrillic-homoglyph 'ѕponsored' (U+0455) is NOT the ASCII allow-list value → rejected.
  const homoglyph = await rpc('advertiser_submit_creative',
    { p_line_item_id: A.liCreated, p_line: 'clean line', p_label: 'ѕponsored', p_dest_url: 'https://ok.example' }, A_JWT);
  assert.ok(!homoglyph.ok, `a homoglyph 'sponsored' must be rejected, got ${homoglyph.status}`);
});

// ---------------------------------------------------------------------------
// W13–W17: edits, status toggles, IDOR on every child-id write RPC, profile.
// ---------------------------------------------------------------------------
test('W13: IDOR — edit / status RPCs on a FOREIGN id are each rejected; foreign untouched', { skip: SKIP }, async () => {
  const editLi = await rpc('advertiser_edit_line_item', { p_id: B.liId, p_cpva_bid_micros: 9999 }, A_JWT);
  assert.ok(!editLi.ok, `edit_line_item on B's line_item must be rejected, got ${editLi.status}`);

  const editCr = await rpc('advertiser_edit_creative', { p_id: B.crId, p_line: 'hijack', p_dest_url: 'https://x.example' }, A_JWT);
  assert.ok(!editCr.ok, `edit_creative on B's creative must be rejected, got ${editCr.status}`);

  const setCamp = await rpc('advertiser_set_campaign_status', { p_id: B.campId, p_target: 'paused' }, A_JWT);
  assert.ok(!setCamp.ok, `set_campaign_status on B's campaign must be rejected, got ${setCamp.status}`);

  const setLi = await rpc('advertiser_set_line_item_status', { p_id: B.liId, p_target: 'active' }, A_JWT);
  assert.ok(!setLi.ok, `set_line_item_status on B's line_item must be rejected, got ${setLi.status}`);

  // B's rows are genuinely untouched.
  const b = psql(`select cpva_bid_micros||'|'||status from public.line_items where id='${B.liId}';`);
  assert.equal(b, '5000|paused', 'B\'s line_item must be unchanged');
  assert.equal(psql(`select status from public.campaigns where id='${B.campId}';`), 'active', 'B\'s campaign unchanged');
  assert.equal(psql(`select line from public.creatives where id='${B.crId}';`), 'Sponsored: Beta Corp', 'B\'s creative unchanged');
});

test('W14: edit_line_item — forces cpc=0, enforces min-bid, resets active creatives on a bid change', { skip: SKIP }, async () => {
  // sub-floor edit rejected
  const low = await rpc('advertiser_edit_line_item', { p_id: A.liReset, p_cpva_bid_micros: FLOOR - 1 }, A_JWT);
  assert.ok(!low.ok, `sub-floor edit must be rejected, got ${low.status}`);

  // A material bid change resets the owning ACTIVE creative to pending_review.
  assert.equal(psql(`select status from public.creatives where id='${A.crReset}';`), 'active', 'precondition: creative active');
  const ok = await rpc('advertiser_edit_line_item',
    { p_id: A.liReset, p_cpva_bid_micros: 7000, p_weight: 2 }, A_JWT);
  assert.ok(ok.ok, `edit_line_item failed: ${ok.status} ${JSON.stringify(ok.data)}`);
  assert.equal(ok.data?.creatives_reset, 1, 'the active creative must be reset');
  const row = psql(`select cpva_bid_micros||'|'||cpc_bid_micros from public.line_items where id='${A.liReset}';`);
  assert.equal(row, '7000|0', 'bid updated, cpc still forced 0');
  assert.equal(psql(`select status from public.creatives where id='${A.crReset}';`), 'pending_review',
    'the previously-active creative must be reset to pending_review on a bid change');

  // editing an ACTIVE line_item is refused (must be draft/paused).
  const active = await rpc('advertiser_edit_line_item', { p_id: A.liId, p_cpva_bid_micros: 6000 }, A_JWT);
  assert.ok(!active.ok, `editing an active line_item must be refused, got ${active.status}`);
});

test('W15: a creative can never be self-activated; edit_creative re-validates + resets pending_review', { skip: SKIP }, async () => {
  // No self-serve RPC sets a creative to active. edit_creative on a pending_review creative keeps it pending.
  const ok = await rpc('advertiser_edit_creative',
    { p_id: A.crSubmitted, p_line: 'Sponsored: Acme v3', p_dest_url: 'https://acme.example/v3' }, A_JWT);
  assert.ok(ok.ok, `edit_creative failed: ${ok.status} ${JSON.stringify(ok.data)}`);
  assert.equal(ok.data?.status, 'pending_review');
  assert.equal(psql(`select status from public.creatives where id='${A.crSubmitted}';`), 'pending_review');

  // edit_creative must also re-run content validation (ESC rejected).
  const bad = await rpc('advertiser_edit_creative',
    { p_id: A.crSubmitted, p_line: `bad${ESC}[0m`, p_dest_url: 'https://x.example' }, A_JWT);
  assert.ok(!bad.ok, `edit_creative must re-validate content, got ${bad.status}`);
});

test('W16: set_campaign_status / set_line_item_status — active<->paused only; draft rejected', { skip: SKIP }, async () => {
  // A.campId is active -> pause -> resume.
  assert.ok((await rpc('advertiser_set_campaign_status', { p_id: A.campId, p_target: 'paused' }, A_JWT)).ok);
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}';`), 'paused');
  assert.ok((await rpc('advertiser_set_campaign_status', { p_id: A.campId, p_target: 'active' }, A_JWT)).ok);
  assert.equal(psql(`select status from public.campaigns where id='${A.campId}';`), 'active');

  // A.liId is active -> pause -> resume.
  assert.ok((await rpc('advertiser_set_line_item_status', { p_id: A.liId, p_target: 'paused' }, A_JWT)).ok);
  assert.equal(psql(`select status from public.line_items where id='${A.liId}';`), 'paused');
  assert.ok((await rpc('advertiser_set_line_item_status', { p_id: A.liId, p_target: 'active' }, A_JWT)).ok);

  // A draft line_item cannot be self-toggled to active (activation is admin-approval-driven).
  const draftToggle = await rpc('advertiser_set_line_item_status', { p_id: A.liCreated, p_target: 'active' }, A_JWT);
  assert.ok(!draftToggle.ok, `a draft line_item must not be self-activated, got ${draftToggle.status}`);
  assert.equal(psql(`select status from public.line_items where id='${A.liCreated}';`), 'draft', 'draft line_item unchanged');

  // An invalid target is rejected.
  const bad = await rpc('advertiser_set_campaign_status', { p_id: A.campId, p_target: 'archived' }, A_JWT);
  assert.ok(!bad.ok, `an out-of-whitelist target must be rejected, got ${bad.status}`);
});

test('W17: update_profile — changes only name; protected columns untouched', { skip: SKIP }, async () => {
  const res = await rpc('advertiser_update_profile', { p_name: '  Acme Corporation  ' }, A_JWT);
  assert.ok(res.ok, `update_profile failed: ${res.status} ${JSON.stringify(res.data)}`);
  const row = psql(`select name||'|'||status||'|'||billing_mode||'|'||is_house from public.advertisers where id='${A.advId}';`);
  assert.equal(row, 'Acme Corporation|active|prepay|false', 'only name changes; status/billing_mode/is_house preserved');

  const empty = await rpc('advertiser_update_profile', { p_name: '   ' }, A_JWT);
  assert.ok(!empty.ok, `an empty name must be rejected, got ${empty.status}`);
});

// ---------------------------------------------------------------------------
// W18: self-scoped aggregate reads (CPVA-only, no per-publisher / ledger exposure, isolated).
// ---------------------------------------------------------------------------
test('W18: campaigns_summary + spend_summary are self-scoped, aggregate, CPVA-only', { skip: SKIP }, async () => {
  const camp = await rpc('advertiser_campaigns_summary', {}, A_JWT);
  assert.ok(camp.ok, `campaigns_summary failed: ${camp.status} ${JSON.stringify(camp.data)}`);
  const campIds = (camp.data?.campaigns ?? []).map((c) => c.campaign_id);
  assert.ok(campIds.includes(A.campId), 'A\'s campaign must appear');
  assert.ok(!campIds.includes(B.campId), 'B\'s campaign must NOT appear (isolation)');
  assert.equal(typeof camp.data?.totals?.campaigns, 'number');

  const spend = await rpc('advertiser_spend_summary', {}, A_JWT);
  assert.ok(spend.ok, `spend_summary failed: ${spend.status} ${JSON.stringify(spend.data)}`);
  const json = JSON.stringify(spend.data);
  assert.ok(!json.includes('publisher_id'), 'spend_summary must expose NO per-publisher rows');
  assert.ok(!json.includes(PUBX.pubId), 'spend_summary must not leak a publisher id');
  // Only the cleared impression (25000) counts; the clawed_back 50000 is excluded; B's 99000 is not A's.
  assert.equal(spend.data?.totals?.spend_micros, 25000, 'CPVA-only valid-billable spend (clawed_back excluded, B isolated)');
  assert.equal(spend.data?.totals?.attention_seconds, 5);
  const liRow = (spend.data?.line_items ?? []).find((r) => r.line_item_id === A.liId);
  assert.ok(liRow, 'A\'s line_item must appear in the spend rollup');
  assert.equal(liRow.spend_micros, 25000);
  assert.ok(!(spend.data?.line_items ?? []).some((r) => r.line_item_id === B.liId), 'B\'s line_item must not appear');
});

// ---------------------------------------------------------------------------
// W19–W20: authentication + the anon-EXECUTE lockdown.
// ---------------------------------------------------------------------------
test('W19: anon / an unmapped session are refused on the write RPCs', { skip: SKIP }, async () => {
  const anonCreate = await rpc('advertiser_create_campaign', { p_name: 'x' }, null);
  assert.ok(!anonCreate.ok, `anon must not call advertiser_create_campaign, got ${anonCreate.status}`);

  const freshCreate = await rpc('advertiser_create_campaign', { p_name: 'x' }, FRESH_JWT);
  assert.ok(!freshCreate.ok, `an authenticated session mapped to no org must be refused, got ${freshCreate.status}`);

  const freshLi = await rpc('advertiser_create_line_item', { p_campaign_id: A.campId, p_cpva_bid_micros: 5000 }, FRESH_JWT);
  assert.ok(!freshLi.ok, `an unmapped session must not create a line_item under A\'s campaign, got ${freshLi.status}`);
});

test('W20: anon holds NO EXECUTE on any new function', { skip: SKIP }, async () => {
  const fns = [
    'app.assert_owns_campaign(uuid)',
    'app.assert_owns_line_item(uuid)',
    'app.assert_owns_creative(uuid)',
    'app.validate_creative_content(text, text, text)',
    'app.creative_content_guard()',
    'public.advertiser_create_campaign(text)',
    'public.advertiser_create_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz)',
    'public.advertiser_edit_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz)',
    'public.advertiser_submit_creative(uuid, text, text, text)',
    'public.advertiser_edit_creative(uuid, text, text, text)',
    'public.advertiser_set_campaign_status(uuid, text)',
    'public.advertiser_set_line_item_status(uuid, text)',
    'public.advertiser_update_profile(text)',
    'public.advertiser_campaigns_summary()',
    'public.advertiser_spend_summary()',
  ];
  for (const fn of fns) {
    const has = psql(`select has_function_privilege('anon', '${fn}', 'EXECUTE');`);
    assert.equal(has, 'f', `anon must NOT hold EXECUTE on ${fn}`);
  }
});
