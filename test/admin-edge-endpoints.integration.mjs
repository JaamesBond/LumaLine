// test/admin-edge-endpoints.integration.mjs — M8: the aal2 money-admin gate on the money-mutating
// admin EDGE routes, plus the read-only/no-write posture of the surfaces the dashboard actually calls.
//
// The M8 hardening re-gates three money-mutating edge routes from requireAdmin (membership only,
// aal1-satisfiable) to requireMoneyAdmin (money_admin_check → app.is_money_admin(): app.money_admins
// membership AND jwt aal='aal2'):
//   * POST /billing/refund               (already re-gated; issues a real Stripe refund)
//   * POST /billing/charge               (real advertiser Stripe charges)
//   * POST /stripe-connect/payout/batch  (real EUR reserve→transfer→confirm to publisher banks)
// A stolen aal1 magic-link session — which still passes requireAdmin — must be REFUSED on all three.
// The pg_cron auto-payout path is UNAFFECTED (it presents the cron secret, not an admin bearer).
//
// The canonical dev admin (seed.sql ADMIN_USER_ID) is in BOTH app.admins and app.money_admins, so:
//   * an aal1 bearer for it passes requireAdmin but FAILS the money gate (aal enforcement),
//   * an aal2 bearer for it passes both.
// The gate runs BEFORE any Stripe call, so the 403 assertions need no Stripe; the "admitted" proofs
// use side-effect-free paths (POST /charge?dry_run=true returns before the lock/reserve).
//
// Self-skips unless the local stack + the served billing/stripe-connect functions are up.
//
// WHAT IS TESTED:
//   E1 — POST /billing/refund: aal1 admin → 403; NON-admin → 403; aal2 money-admin → ADMITTED (not 403)
//   E2 — POST /billing/charge?dry_run=true: aal1 admin → 403; NON-admin → 403; aal2 money-admin → 200
//   E3 — POST /stripe-connect/payout/batch: aal1 admin → 403; NON-admin → 403 (cron path untouched)
//   E4 — GET /monitor/status with an admin bearer makes NO writes (app.alert_events count unchanged)
//   E5 — GET /billing/reconcile + GET /stripe-connect/reconcile: a NON-admin bearer → 401/403
//   E6 — GREP: no admin dashboard code path calls POST /monitor/run, /billing/charge, or /payout/batch

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REST_BASE    = 'http://127.0.0.1:54321/rest/v1';
const FN_BASE      = 'http://127.0.0.1:54321/functions/v1';
const BILLING_BASE = `${FN_BASE}/billing`;
const CONNECT_BASE = `${FN_BASE}/stripe-connect`;
const MONITOR_BASE = `${FN_BASE}/monitor`;
const DB_URL       = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// The seeded dev admin — in app.admins AND (M8) app.money_admins via seed.sql.
const ADMIN_USER_ID     = 'a0000000-0000-4000-8000-000000000001';
const NON_ADMIN_USER_ID = '22222222-2222-2222-2222-222222222222';

function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

const MADMIN_JWT = mintJwt(ADMIN_USER_ID, { aal: 'aal2' }); // money-admin (member + aal2)
const AADMIN_JWT = mintJwt(ADMIN_USER_ID);                  // aal1 admin (member, aal1 session)
const NON_JWT    = mintJwt(NON_ADMIN_USER_ID);              // not an admin at all

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

async function req(url, { method = 'GET', jwt, body } = {}) {
  const headers = { apikey: ANON, 'content-type': 'application/json' };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  const resp = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { status: resp.status, ok: resp.ok, data };
}
async function served(base, path) {
  try { const r = await fetch(`${base}${path}`, { method: 'OPTIONS', signal: AbortSignal.timeout(2000) }); return r.status === 200; }
  catch { return false; }
}
async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
// money_admin_check exists ⇔ calling it (as anon, EXECUTE revoked) is 401/403, NOT 404 (missing fn).
async function foundationPresent() {
  try {
    const r = await fetch(`${REST_BASE}/rpc/money_admin_check`, { method: 'POST', headers: { apikey: ANON, 'content-type': 'application/json' }, body: '{}' });
    return r.status !== 404;
  } catch { return false; }
}

const STACK_UP    = await isStackUp();
const FOUND       = STACK_UP ? await foundationPresent() : false;
const BILLING_UP  = STACK_UP ? await served(BILLING_BASE, '/charge') : false;
const CONNECT_UP  = STACK_UP ? await served(CONNECT_BASE, '/payout/batch') : false;
const MONITOR_UP  = STACK_UP ? await served(MONITOR_BASE, '/status') : false;
const PSQL_OK     = STACK_UP ? psqlWorks() : false;

const SKIP_BILLING = !STACK_UP ? 'stack down — SKIPPING'
  : !FOUND ? 'money_admin_check missing (M8 foundation not applied) — SKIPPING'
  : !BILLING_UP ? 'billing fn not served — SKIPPING' : false;
const SKIP_CONNECT = !STACK_UP ? 'stack down — SKIPPING'
  : !FOUND ? 'money_admin_check missing — SKIPPING'
  : !CONNECT_UP ? 'stripe-connect fn not served — SKIPPING' : false;
const SKIP_MONITOR = !MONITOR_UP || !PSQL_OK ? 'monitor fn not served or psql unavailable — SKIPPING' : false;
if (SKIP_BILLING) console.log(`[admin-edge-endpoints.integration] billing: ${SKIP_BILLING}`);
if (SKIP_CONNECT) console.log(`[admin-edge-endpoints.integration] connect: ${SKIP_CONNECT}`);

// ---------------------------------------------------------------------------
test('E1: POST /billing/refund — aal1 admin & non-admin → 403; aal2 money-admin is ADMITTED past the gate', { skip: SKIP_BILLING }, async () => {
  const bodyReq = { review_id: randomUUID() }; // a well-formed but nonexistent review

  const aal1 = await req(`${BILLING_BASE}/refund`, { method: 'POST', jwt: AADMIN_JWT, body: bodyReq });
  assert.equal(aal1.status, 403, `aal1 admin must be refused by the money gate, got ${aal1.status}`);

  const non = await req(`${BILLING_BASE}/refund`, { method: 'POST', jwt: NON_JWT, body: bodyReq });
  assert.equal(non.status, 403, `non-admin must be 403, got ${non.status}`);

  // aal2 money-admin passes the gate → it proceeds and fails LATER (review not found = 404), never 403.
  const aal2 = await req(`${BILLING_BASE}/refund`, { method: 'POST', jwt: MADMIN_JWT, body: bodyReq });
  assert.notEqual(aal2.status, 403, `aal2 money-admin must be admitted past the gate, got ${aal2.status}: ${JSON.stringify(aal2.data)}`);
});

test('E2: POST /billing/charge?dry_run=true — aal1 admin & non-admin → 403; aal2 money-admin → 200', { skip: SKIP_BILLING }, async () => {
  const aal1 = await req(`${BILLING_BASE}/charge?dry_run=true`, { method: 'POST', jwt: AADMIN_JWT, body: {} });
  assert.equal(aal1.status, 403, `aal1 admin must be refused on /charge, got ${aal1.status}`);

  const non = await req(`${BILLING_BASE}/charge?dry_run=true`, { method: 'POST', jwt: NON_JWT, body: {} });
  assert.equal(non.status, 403, `non-admin must be 403 on /charge, got ${non.status}`);

  // dry_run is side-effect-free (returns before the single-flight lock / reserve) — a clean 200.
  const aal2 = await req(`${BILLING_BASE}/charge?dry_run=true`, { method: 'POST', jwt: MADMIN_JWT, body: {} });
  assert.equal(aal2.status, 200, `aal2 money-admin must be admitted on /charge, got ${aal2.status}: ${JSON.stringify(aal2.data)}`);
  assert.ok('charged' in (aal2.data ?? {}), 'dry-run /charge returns the billing shape');
});

test('E3: POST /stripe-connect/payout/batch — aal1 admin & non-admin bearer → 403 (cron path untouched)', { skip: SKIP_CONNECT }, async () => {
  // The security fix: an aal1 magic-link admin bearer can no longer trigger a real payout batch.
  // (The aal2-admitted path + the cron-secret path are covered by auto-payout / reserve-serialize
  // suites — we do NOT call /payout/batch with aal2 here to avoid its reserve side effect.)
  const aal1 = await req(`${CONNECT_BASE}/payout/batch?dry_run=true`, { method: 'POST', jwt: AADMIN_JWT, body: {} });
  assert.equal(aal1.status, 403, `aal1 admin bearer must be refused on /payout/batch, got ${aal1.status}`);

  const non = await req(`${CONNECT_BASE}/payout/batch?dry_run=true`, { method: 'POST', jwt: NON_JWT, body: {} });
  assert.equal(non.status, 403, `non-admin must be 403 on /payout/batch, got ${non.status}`);
});

test('E4: GET /monitor/status (admin bearer) writes NOTHING — app.alert_events count unchanged', { skip: SKIP_MONITOR }, async () => {
  const before = Number(psql('select count(*) from app.alert_events;'));
  const r = await req(`${MONITOR_BASE}/status`, { method: 'GET', jwt: AADMIN_JWT });
  assert.equal(r.status, 200, `admin GET /status should be 200, got ${r.status}: ${JSON.stringify(r.data)}`);
  assert.ok(Array.isArray(r.data?.events), 'status returns an events array');
  assert.equal(typeof r.data?.checks, 'object', 'status returns per-check state');
  const after = Number(psql('select count(*) from app.alert_events;'));
  assert.equal(after, before, 'GET /monitor/status must not write any alert_events row (read-only)');
});

test('E5: GET reconcile endpoints reject a non-admin bearer (401/403)', { skip: SKIP_BILLING || SKIP_CONNECT }, async () => {
  const from = '2026-01-01T00:00:00Z', to = '2026-01-02T00:00:00Z';
  const b = await req(`${BILLING_BASE}/reconcile?from=${from}&to=${to}`, { method: 'GET', jwt: NON_JWT });
  assert.ok(b.status === 401 || b.status === 403, `non-admin /billing/reconcile must be 401/403, got ${b.status}`);
  const c = await req(`${CONNECT_BASE}/reconcile?from=${from}&to=${to}`, { method: 'GET', jwt: NON_JWT });
  assert.ok(c.status === 401 || c.status === 403, `non-admin /stripe-connect/reconcile must be 401/403, got ${c.status}`);
});

// ---------------------------------------------------------------------------
// E6 — pure fs grep: the admin dashboard (separate web repo) must never CALL the forbidden money/
// side-effecting POST routes. Both comments ("NEVER POST /charge") AND user-facing runbook strings
// ("do not fire a manual /payout/batch") legitimately MENTION these paths, so a bare quoted-string
// match false-positives. We match only a forbidden path as the FIRST ARGUMENT of a fetch-style call
// (adminFnFetch/adminFnGet/fetch), which is what an actual invocation looks like. Self-skips if the
// web repo isn't checked out next to this one.
// ---------------------------------------------------------------------------
const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'luma-line-edf7d51e');
const ADMIN_SUBTREES = ['src/features/admin', 'src/routes/admin', 'src/integrations/lumaline'];
const FORBIDDEN_CALL =
  /(?:adminFnFetch|adminFnGet|fnFetch|fnGet|fetch)\s*\(\s*[`"'][^`"']*(?:monitor\/run|billing\/charge|payout\/batch)/;

function walk(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (/\.(ts|tsx|js|jsx|mjs)$/.test(e.name)) out.push(p);
  }
  return out;
}

const SKIP_GREP = !existsSync(WEB_ROOT) ? `web repo not found at ${WEB_ROOT} — SKIPPING` : false;
if (SKIP_GREP) console.log(`[admin-edge-endpoints.integration] grep: ${SKIP_GREP}`);

test('E6: no admin dashboard file CALLS POST /monitor/run, /billing/charge, or /payout/batch', { skip: SKIP_GREP }, () => {
  const offenders = [];
  for (const sub of ADMIN_SUBTREES) {
    const root = join(WEB_ROOT, sub);
    if (!existsSync(root)) continue;
    for (const file of walk(root)) {
      const content = readFileSync(file, 'utf8');
      for (const line of content.split('\n')) {
        if (FORBIDDEN_CALL.test(line)) offenders.push(`${file}: ${line.trim()}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `admin dashboard must not call forbidden POST routes:\n${offenders.join('\n')}`);
});
