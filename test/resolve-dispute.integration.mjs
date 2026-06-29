// test/resolve-dispute.integration.mjs — Integration tests for the M3 carry-forward
// resolve_dispute admin RPC (transitions a publisher dispute open -> resolved/rejected).
//
// Self-skips cleanly when:
//   - Local Supabase stack is unreachable (REST API at 54321)
//   - disputes table is absent (M2-T6 migration not applied)
//
// WHAT IS TESTED:
//   T39 — non-admin cannot call resolve_dispute (PostgREST 403/401/500)
//   T40 — admin resolve_dispute('resolved') flips status + records resolution/resolved_at/resolved_by
//   T41 — resolve_dispute is idempotent (second call on a non-open dispute returns already_resolved)
//   T42 — admin resolve_dispute('rejected') flips status to rejected
//   T43 — resolve_dispute rejects an invalid status (not 'resolved'/'rejected')

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';

const REST_BASE = 'http://127.0.0.1:54321/rest/v1';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

const ADMIN_USER_ID     = 'a0000000-0000-4000-8000-000000000001';
const NON_ADMIN_USER_ID = '22222222-2222-2222-2222-222222222222';
const PUB_A_PUBLISHER_ID = 'a1a1a1a1-0000-0000-0000-000000000001';

function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

const ADMIN_JWT     = mintJwt(ADMIN_USER_ID);
const NON_ADMIN_JWT = mintJwt(NON_ADMIN_USER_ID);

async function svcReq(method, resource, { body, query, prefer } = {}) {
  const url  = `${REST_BASE}/${resource}${query ? `?${query}` : ''}`;
  const resp = await fetch(url, {
    method,
    headers: {
      apikey:         SERVICE,
      Authorization:  `Bearer ${SERVICE}`,
      'content-type': 'application/json',
      Prefer:         prefer ?? 'return=representation',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function svcDelete(resource, query) {
  try {
    await fetch(`${REST_BASE}/${resource}?${query}`, {
      method:  'DELETE',
      headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, Prefer: 'return=minimal' },
    });
  } catch { /* best-effort */ }
}

async function rpcWithJwt(fnName, body, jwt) {
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, {
    method: 'POST',
    headers: {
      apikey:         ANON,
      Authorization:  `Bearer ${jwt}`,
      'content-type': 'application/json',
      accept:         'application/json',
    },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function isStackUp() {
  try {
    const res = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) });
    return res.status >= 200 && res.status < 500;
  } catch { return false; }
}

async function isDisputesTablePresent() {
  try {
    const res = await fetch(`${REST_BASE}/disputes?select=id&limit=1`, {
      headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` },
      signal:  AbortSignal.timeout(2000),
    });
    return res.status === 200;
  } catch { return false; }
}

const STACK_UP    = await isStackUp();
const DISPUTES_OK = STACK_UP ? await isDisputesTablePresent() : false;
const SKIP = !STACK_UP    ? `PostgREST unreachable at ${REST_BASE} — SKIPPING`
           : !DISPUTES_OK ? 'disputes table not found — apply M2-T6 migration'
           : false;
if (SKIP) console.log(`[resolve-dispute.integration] ${SKIP} — skipping all tests.`);

/** Insert an open dispute row (service role bypasses RLS). Returns dispute id. */
async function insertOpenDispute(description = 'test dispute') {
  const res = await svcReq('POST', 'disputes', {
    body: { publisher_id: PUB_A_PUBLISHER_ID, impression_id: null, description, status: 'open' },
  });
  if (!res.ok) throw new Error(`insertOpenDispute failed: ${JSON.stringify(res.data)}`);
  return res.data?.[0]?.id ?? res.data?.id;
}

test('T39: non-admin cannot call resolve_dispute (403/401/500)', { skip: SKIP }, async () => {
  const res = await rpcWithJwt('resolve_dispute',
    { p_dispute_id: randomUUID(), p_status: 'resolved', p_resolution: 'x' }, NON_ADMIN_JWT);
  assert.ok(res.status === 403 || res.status === 401 || res.status === 500,
    `Expected 403/401/500, got ${res.status}: ${JSON.stringify(res.data)}`);
});

test('T40: admin resolve_dispute(resolved) records resolution + resolved_at + resolved_by', { skip: SKIP }, async () => {
  const id = await insertOpenDispute('publisher believes the clawback was wrong');
  try {
    const res = await rpcWithJwt('resolve_dispute',
      { p_dispute_id: id, p_status: 'resolved', p_resolution: 'reviewed records — upheld publisher, restoring credit' }, ADMIN_JWT);
    assert.ok(res.ok, `resolve_dispute failed: ${JSON.stringify(res.data)}`);
    assert.equal(res.data?.ok, true);

    const row = await svcReq('GET', 'disputes', { query: `id=eq.${id}&select=*` });
    const d = row.data?.[0];
    assert.equal(d?.status, 'resolved', 'status must be resolved');
    assert.ok(d?.resolution, 'resolution must be set');
    assert.ok(d?.resolved_at, 'resolved_at must be set');
    assert.equal(d?.resolved_by, ADMIN_USER_ID, 'resolved_by must record the admin');
  } finally {
    await svcDelete('disputes', `id=eq.${id}`);
  }
});

test('T41: resolve_dispute is idempotent — second call returns already_resolved', { skip: SKIP }, async () => {
  const id = await insertOpenDispute('idempotency check');
  try {
    const first = await rpcWithJwt('resolve_dispute',
      { p_dispute_id: id, p_status: 'resolved', p_resolution: 'first' }, ADMIN_JWT);
    assert.equal(first.data?.ok, true);

    const second = await rpcWithJwt('resolve_dispute',
      { p_dispute_id: id, p_status: 'rejected', p_resolution: 'second' }, ADMIN_JWT);
    assert.equal(second.data?.ok, false, 'second call must be a no-op');
    assert.equal(second.data?.reason, 'already_resolved');

    // The original resolution must be preserved (not overwritten by the second call).
    const row = await svcReq('GET', 'disputes', { query: `id=eq.${id}&select=status,resolution` });
    assert.equal(row.data?.[0]?.status, 'resolved');
    assert.equal(row.data?.[0]?.resolution, 'first');
  } finally {
    await svcDelete('disputes', `id=eq.${id}`);
  }
});

test('T42: admin resolve_dispute(rejected) flips status to rejected', { skip: SKIP }, async () => {
  const id = await insertOpenDispute('to be rejected');
  try {
    const res = await rpcWithJwt('resolve_dispute',
      { p_dispute_id: id, p_status: 'rejected', p_resolution: 'records confirm valid clawback' }, ADMIN_JWT);
    assert.equal(res.data?.ok, true);
    const row = await svcReq('GET', 'disputes', { query: `id=eq.${id}&select=status` });
    assert.equal(row.data?.[0]?.status, 'rejected');
  } finally {
    await svcDelete('disputes', `id=eq.${id}`);
  }
});

test('T43: resolve_dispute rejects an invalid status', { skip: SKIP }, async () => {
  const id = await insertOpenDispute('invalid status check');
  try {
    const res = await rpcWithJwt('resolve_dispute',
      { p_dispute_id: id, p_status: 'bogus', p_resolution: 'x' }, ADMIN_JWT);
    // Either a PostgREST error status, or an ok:false business response — never a successful resolve.
    const succeeded = res.ok && res.data?.ok === true;
    assert.equal(succeeded, false, `invalid status must not resolve: ${JSON.stringify(res.data)}`);

    // Dispute must remain open.
    const row = await svcReq('GET', 'disputes', { query: `id=eq.${id}&select=status` });
    assert.equal(row.data?.[0]?.status, 'open', 'dispute must stay open on invalid status');
  } finally {
    await svcDelete('disputes', `id=eq.${id}`);
  }
});
