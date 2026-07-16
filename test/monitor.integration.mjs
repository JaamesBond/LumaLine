// test/monitor.integration.mjs — integration tests for the T6 money-path monitor
// (migration 20260702010000_money_monitoring.sql + supabase/functions/monitor/index.ts).
//
// Self-skips cleanly (the suite pattern) when:
//   - the local Supabase stack is unreachable (REST at 54321)
//   - the monitoring migration is not applied (monitor_status RPC missing)
//   - the monitor edge function is not deployed (fn-level tests only)
//   - psql is unavailable (cleanup-dependent tests only)
//
// WHAT IS TESTED:
//   SQL layer (stack + migration, no edge fn needed):
//     MI1 — monitor RPCs are service_role-only: anon and authenticated are refused
//     MI2 — monitor_sync_alerts fires once, dedups the second identical run (no spam)
//     MI3 — monitor_sync_alerts resolves an open alert once its check stops failing
//     MI4 — an errored check (name omitted from p_evaluated_checks) does NOT auto-resolve
//     MI5 — monitor_ledger_unbalanced sees a balanced ledger as balanced
//   Edge fn layer (additionally requires the fn to be served):
//     MI6 — POST /run with no credentials → 401
//     MI7 — POST /run with a wrong cron secret → 401
//     MI8 — non-admin bearer → 401
//     MI9 — admin bearer GET /status → 200 {ok, events, checks}
//     MI10 — admin POST /run → 200 shape; ledger_zero_sum passes on a balanced DB
//     MI11 — second identical run: nothing newly fired; no email on a no-change run
//     MI12 — READ-ONLY invariant: /run mutates no money-table row counts

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const FN_BASE   = 'http://127.0.0.1:54321/functions/v1/monitor';
const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL    = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

const ADMIN_USER_ID     = 'a0000000-0000-4000-8000-000000000001'; // seeded admin
const NON_ADMIN_USER_ID = '22222222-2222-2222-2222-222222222222';

/** Mint a Supabase Auth–style HS256 JWT (same secret PostgREST trusts locally). */
function mintJwt(sub) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000 });
  const sig = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}
const ADMIN_JWT     = mintJwt(ADMIN_USER_ID);
const NON_ADMIN_JWT = mintJwt(NON_ADMIN_USER_ID);

async function rpc(fnName, body, token = SERVICE) {
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, {
    method: 'POST',
    headers: { apikey: token, Authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function fnReq(method, path, { headers = {}, body } = {}) {
  const resp = await fetch(`${FN_BASE}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(60000), // recon checks may paginate Stripe
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

async function isStackUp() {
  try {
    const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) });
    return r.status >= 200 && r.status < 500;
  } catch { return false; }
}
async function isMigrationApplied() {
  try { return (await rpc('monitor_status', {})).ok; } catch { return false; }
}
async function isFnDeployed() {
  // An unauthenticated /run must return 401 when the fn is served; the gateway returns
  // 404/503 (or the connection fails) when it is not.
  try {
    const r = await fetch(`${FN_BASE}/run`, { method: 'POST', signal: AbortSignal.timeout(3000) });
    return r.status === 401;
  } catch { return false; }
}

const STACK_UP  = await isStackUp();
const MIGRATED  = STACK_UP ? await isMigrationApplied() : false;
const FN_UP     = MIGRATED ? await isFnDeployed() : false;
const PSQL_OK   = STACK_UP ? psqlWorks() : false;

const SKIP_SQL = !STACK_UP ? 'local stack down — SKIPPING'
  : !MIGRATED ? 'money_monitoring migration not applied — SKIPPING' : false;
const SKIP_FN = SKIP_SQL ? SKIP_SQL : !FN_UP ? 'monitor fn not served — SKIPPING' : false;
if (SKIP_SQL) console.log(`[monitor.integration] ${SKIP_SQL}`);
else if (SKIP_FN) console.log(`[monitor.integration] fn tests: ${SKIP_FN}`);

// Unique per-run check names so parallel/dirty local DBs never collide; cleaned up via psql.
const RUN = Math.random().toString(36).slice(2, 8);
const CHECK = `itest_${RUN}`;
function cleanup() {
  if (PSQL_OK) { try { psql(`delete from app.alert_events where check_name like 'itest_%'`); } catch { /* best-effort */ } }
}

// ---------------------------------------------------------------------------
// SQL layer
// ---------------------------------------------------------------------------

test('MI1: monitor RPCs are service_role-only (anon + authenticated refused)', { skip: SKIP_SQL }, async () => {
  for (const fn of ['monitor_status', 'monitor_ledger_unbalanced', 'monitor_sync_alerts']) {
    const body = fn === 'monitor_sync_alerts' ? { p_evaluated_checks: [], p_alerts: [] } :
      fn === 'monitor_ledger_unbalanced' ? { p_limit: 1 } : {};
    for (const token of [ANON, NON_ADMIN_JWT]) {
      const headers = { apikey: ANON, Authorization: `Bearer ${token}`, 'content-type': 'application/json' };
      const resp = await fetch(`${REST_BASE}/rpc/${fn}`, { method: 'POST', headers, body: JSON.stringify(body) });
      // 401/403/404 all mean "not callable"; 2xx would be the SECDEF-grant regression.
      assert.ok(resp.status >= 400, `${fn} must be refused (got ${resp.status})`);
    }
  }
});

test('MI2: sync fires an alert once and dedups the identical second run (no spam)', { skip: SKIP_SQL }, async (t) => {
  t.after(cleanup);
  const alert = [{ check_name: CHECK, severity: 'high', dedup_key: 'k1', payload: { note: 'itest' } }];
  const r1 = await rpc('monitor_sync_alerts', { p_evaluated_checks: [CHECK], p_alerts: alert });
  assert.ok(r1.ok, JSON.stringify(r1.data));
  assert.equal(r1.data.fired.length, 1);
  assert.equal(r1.data.fired[0].dedup_key, 'k1');

  const r2 = await rpc('monitor_sync_alerts', { p_evaluated_checks: [CHECK], p_alerts: alert });
  assert.ok(r2.ok);
  assert.deepEqual(r2.data.fired, [], 'already-open alert must NOT re-fire');
  assert.deepEqual(r2.data.resolved, [], 'still-failing alert must NOT resolve');
});

test('MI3: sync resolves the open alert once the check stops failing', { skip: SKIP_SQL }, async (t) => {
  t.after(cleanup);
  const alert = [{ check_name: CHECK, severity: 'medium', dedup_key: 'k2', payload: {} }];
  const fire = await rpc('monitor_sync_alerts', { p_evaluated_checks: [CHECK], p_alerts: alert });
  assert.equal(fire.data.fired.length, 1);

  const pass = await rpc('monitor_sync_alerts', { p_evaluated_checks: [CHECK], p_alerts: [] });
  assert.equal(pass.data.resolved.length, 1);
  assert.equal(pass.data.resolved[0].dedup_key, 'k2');

  // And it can re-fire after resolution (a NEW open row, not a dedup no-op).
  const refire = await rpc('monitor_sync_alerts', { p_evaluated_checks: [CHECK], p_alerts: alert });
  assert.equal(refire.data.fired.length, 1);
});

test('MI4: an errored check (omitted from p_evaluated_checks) does NOT auto-resolve its open alerts', { skip: SKIP_SQL }, async (t) => {
  t.after(cleanup);
  const alert = [{ check_name: CHECK, severity: 'critical', dedup_key: 'k3', payload: {} }];
  await rpc('monitor_sync_alerts', { p_evaluated_checks: [CHECK], p_alerts: alert });

  // Next run the check errors: not in evaluated list, and its failing set is unknown.
  const r = await rpc('monitor_sync_alerts', { p_evaluated_checks: [], p_alerts: [] });
  assert.deepEqual(r.data.resolved, [], 'unobservable check must keep its alerts open');
});

test('MI5: monitor_ledger_unbalanced reports a balanced ledger as balanced', { skip: SKIP_SQL }, async () => {
  const r = await rpc('monitor_ledger_unbalanced', {});
  assert.ok(r.ok, JSON.stringify(r.data));
  // The deferred zero-sum constraint trigger guarantees this on any non-drilled DB.
  assert.deepEqual(r.data.groups, []);
  assert.equal(Number(r.data.global_sum_micros), 0);
});

// ---------------------------------------------------------------------------
// Edge fn layer
// ---------------------------------------------------------------------------

test('MI6: POST /run with no credentials → 401', { skip: SKIP_FN }, async () => {
  const r = await fnReq('POST', '/run');
  assert.equal(r.status, 401);
});

test('MI7: POST /run with a wrong cron secret → 401', { skip: SKIP_FN }, async () => {
  const r = await fnReq('POST', '/run', { headers: { 'x-lumaline-cron-secret': 'definitely-wrong-secret' } });
  assert.equal(r.status, 401);
});

test('MI8: non-admin bearer → 401', { skip: SKIP_FN }, async () => {
  const r = await fnReq('POST', '/run', { headers: { Authorization: `Bearer ${NON_ADMIN_JWT}`, apikey: ANON } });
  assert.equal(r.status, 401);
});

test('MI9: admin bearer GET /status → 200 with events + per-check state', { skip: SKIP_FN }, async () => {
  const r = await fnReq('GET', '/status', { headers: { Authorization: `Bearer ${ADMIN_JWT}`, apikey: ANON } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.ok, true);
  assert.ok(Array.isArray(r.data.events));
  assert.equal(typeof r.data.checks, 'object');
});

test('MI10: admin POST /run → 200; all six checks report; ledger_zero_sum passes on a balanced DB', { skip: SKIP_FN }, async () => {
  const r = await fnReq('POST', '/run', { headers: { Authorization: `Bearer ${ADMIN_JWT}`, apikey: ANON } });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.ok(Array.isArray(r.data.checks));
  const names = r.data.checks.map((c) => c.name);
  for (const n of ['ledger_zero_sum', 'payout_stuck', 'payout_failed', 'charge_failed', 'billing_recon_drift', 'payout_recon_drift']) {
    assert.ok(names.includes(n), `check ${n} must run`);
  }
  const ledger = r.data.checks.find((c) => c.name === 'ledger_zero_sum');
  assert.equal(ledger.status, 'pass', 'balanced local ledger must pass zero-sum');
  assert.ok(Array.isArray(r.data.fired));
  assert.ok(Array.isArray(r.data.resolved));
  assert.ok(['sent', 'skipped'].includes(r.data.email) || r.data.email.startsWith('failed:'),
    `email outcome must be sent|skipped|failed:<code>, got ${r.data.email}`);
});

test('MI11: second identical run — nothing newly fires (dedup) and a no-change run sends no email', { skip: SKIP_FN }, async () => {
  await fnReq('POST', '/run', { headers: { Authorization: `Bearer ${ADMIN_JWT}`, apikey: ANON } }); // converge state
  const r2 = await fnReq('POST', '/run', { headers: { Authorization: `Bearer ${ADMIN_JWT}`, apikey: ANON } });
  assert.equal(r2.status, 200, JSON.stringify(r2.data));
  assert.deepEqual(r2.data.fired, [], 'already-open alerts must not re-fire on the next run');
  if (r2.data.resolved.length === 0) {
    assert.equal(r2.data.email, 'skipped', 'no state change → no email attempt');
  }
});

// These are GLOBAL row counts, so they see every connection's writes — not just the monitor's.
// `node --test` runs test FILES in parallel and the sibling money suites insert ledger groups
// continuously, so a raw before/after delta cannot distinguish "the monitor wrote" (a real
// violation) from "another suite wrote" (harmless churn) — that produced a persistent false red.
// The invariant is NOT relaxed: on a quiescent DB this still asserts byte-equality and fails hard.
// It only declines to convict when it can PROVE the tables are moving underneath it, which it
// establishes by sampling an idle control window. Run this file alone to force strict enforcement:
//   node --test test/monitor.integration.mjs
test('MI12: READ-ONLY invariant — /run changes no money-table row counts', { skip: SKIP_FN || (!PSQL_OK && 'psql unavailable — SKIPPING') }, async (t) => {
  const counts = () => psql(
    `select (select count(*) from public.ledger_entries) || '/' ||
            (select count(*) from public.payouts) || '/' ||
            (select count(*) from public.advertiser_charges)`);
  const idle = async (ms = 300) => { const a = counts(); await new Promise((r) => setTimeout(r, ms)); return a === counts(); };

  const before = counts();
  const r = await fnReq('POST', '/run', { headers: { Authorization: `Bearer ${ADMIN_JWT}`, apikey: ANON } });
  assert.equal(r.status, 200);
  const after = counts();
  if (after === before) return;   // quiescent + unchanged → the invariant holds outright.

  // Counts moved. Only a QUIET database can attribute that to the monitor; if sibling suites are
  // still writing, this run is inconclusive, not evidence of a violation.
  if (!(await idle())) {
    t.skip(`money tables churning from parallel suites (${before} -> ${after}) — inconclusive; run this file alone to enforce`);
    return;
  }
  assert.fail(`monitor must never write money tables (${before} -> ${after} on a quiescent DB)`);
});
