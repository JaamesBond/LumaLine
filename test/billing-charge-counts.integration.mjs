// test/billing-charge-counts.integration.mjs — M3 carry-forward: the /charge response
// must split the conflated `charged` count into succeeded/skipped/failed/would_charge.
//
// Self-skips when the local stack or billing function is unreachable.
//
// WHAT IS TESTED (dry-run only — never touches Stripe):
//   T44 — /charge response exposes a numeric `counts` breakdown that sums to `processed`
//   T45 — `charged` equals counts.succeeded (no longer conflates skipped/failed)
//   T46 — below-minimum entries are bucketed as `skipped`, billable entries as `would_charge`

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';

const REST_BASE    = 'http://127.0.0.1:54321/rest/v1';
const BILLING_BASE = 'http://127.0.0.1:54321/functions/v1/billing';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

const ADMIN_USER_ID      = 'a0000000-0000-4000-8000-000000000001';
const PUB_A_PUBLISHER_ID = 'a1a1a1a1-0000-0000-0000-000000000001';
const DEV_LINE_ITEM_ID   = '11000000-0000-0000-0000-000000000001';

function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}
const ADMIN_JWT = mintJwt(ADMIN_USER_ID);

async function svcReq(method, resource, { body, query, prefer } = {}) {
  const resp = await fetch(`${REST_BASE}/${resource}${query ? `?${query}` : ''}`, {
    method,
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'content-type': 'application/json', Prefer: prefer ?? 'return=representation' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}
async function svcDelete(resource, query) {
  try { await fetch(`${REST_BASE}/${resource}?${query}`, { method: 'DELETE', headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, Prefer: 'return=minimal' } }); } catch { /* best-effort */ }
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
async function isBillingUp() {
  try { const r = await fetch(`${BILLING_BASE}/charge`, { method: 'OPTIONS', signal: AbortSignal.timeout(2000) }); return r.status === 200; } catch { return false; }
}
const STACK_UP   = await isStackUp();
const BILLING_UP = STACK_UP ? await isBillingUp() : false;
const SKIP = !STACK_UP ? `PostgREST unreachable — SKIPPING` : !BILLING_UP ? 'billing function not running — SKIPPING' : false;
if (SKIP) console.log(`[billing-charge-counts.integration] ${SKIP}`);

/** Insert a cleared billing entry (balanced 3-leg group) so it appears in uncharged_advertiser_billings. */
async function insertClearedBillingEntry(grossMicros) {
  const windowId = randomUUID(), impressionId = randomUUID(), groupId = randomUUID();
  const pubShare = Math.round(grossMicros * 0.6), platShare = grossMicros - pubShare;
  const imp = await svcReq('POST', 'impressions', {
    body: { id: impressionId, window_id: windowId, publisher_id: PUB_A_PUBLISHER_ID, line_item_id: DEV_LINE_ITEM_ID, attention_seconds: 5, gross_micros: grossMicros, state: 'cleared' },
  });
  if (!imp.ok) throw new Error(`impression insert failed: ${JSON.stringify(imp.data)}`);
  const led = await svcReq('POST', 'ledger_entries', {
    body: [
      { entry_group_id: groupId, event_type: 'cpva_accrual', account: 'advertiser_billing', amount_micros: grossMicros, state: 'cleared', source_type: 'impression', source_id: impressionId, publisher_id: null },
      { entry_group_id: groupId, event_type: 'cpva_accrual', account: 'publisher_earnings', amount_micros: -pubShare, state: 'cleared', source_type: 'impression', source_id: impressionId, publisher_id: PUB_A_PUBLISHER_ID },
      { entry_group_id: groupId, event_type: 'cpva_accrual', account: 'platform_revenue', amount_micros: -platShare, state: 'cleared', source_type: 'impression', source_id: impressionId, publisher_id: null },
    ],
  });
  if (!led.ok) { await svcDelete('impressions', `id=eq.${impressionId}`); throw new Error(`ledger insert failed: ${JSON.stringify(led.data)}`); }
  return { impressionId, groupId };
}
async function cleanup({ impressionId, groupId }) {
  await svcDelete('advertiser_charges', `entry_group_id=eq.${groupId}`);
  await svcDelete('ledger_entries', `entry_group_id=eq.${groupId}`);
  await svcDelete('impressions', `id=eq.${impressionId}`);
}

async function chargeDryRun() {
  const resp = await fetch(`${BILLING_BASE}/charge?dry_run=true`, {
    method: 'POST', headers: { Authorization: `Bearer ${ADMIN_JWT}`, 'content-type': 'application/json' },
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

test('T44: /charge response has a numeric counts breakdown that sums to processed', { skip: SKIP }, async () => {
  const res = await chargeDryRun();
  assert.ok(res.ok, `dry-run /charge failed: ${JSON.stringify(res.data)}`);
  const b = res.data;
  assert.ok(b.counts && typeof b.counts === 'object', 'response must include a counts object');
  for (const k of ['succeeded', 'skipped', 'failed', 'would_charge']) {
    assert.equal(typeof b.counts[k], 'number', `counts.${k} must be a number`);
  }
  assert.equal(typeof b.processed, 'number', 'processed must be a number');
  assert.equal(b.processed, b.results.length, 'processed must equal results.length');
  assert.equal(
    b.counts.succeeded + b.counts.skipped + b.counts.failed + b.counts.would_charge,
    b.processed,
    'counts must sum to processed',
  );
});

test('T45: charged equals counts.succeeded (no longer conflates skipped/failed)', { skip: SKIP }, async () => {
  const res = await chargeDryRun();
  assert.ok(res.ok);
  const b = res.data;
  assert.equal(b.charged, b.counts.succeeded, 'charged must equal counts.succeeded');
  // dry-run never charges and never fails.
  assert.equal(b.counts.succeeded, 0, 'dry-run must report 0 succeeded');
  assert.equal(b.counts.failed, 0, 'dry-run must report 0 failed');
});

test('T46: below-minimum is bucketed skipped; billable is bucketed would_charge', { skip: SKIP }, async () => {
  const belowMin = await insertClearedBillingEntry(100_000);   // 10 cents < 50 → skipped
  const billable = await insertClearedBillingEntry(1_000_000); // $1.00 → would_charge
  try {
    const res = await chargeDryRun();
    assert.ok(res.ok, `dry-run failed: ${JSON.stringify(res.data)}`);
    const b = res.data;
    assert.ok(b.counts.skipped >= 1, `expected >=1 skipped, got ${b.counts.skipped}`);
    assert.ok(b.counts.would_charge >= 1, `expected >=1 would_charge, got ${b.counts.would_charge}`);
  } finally {
    await cleanup(belowMin);
    await cleanup(billable);
  }
});
