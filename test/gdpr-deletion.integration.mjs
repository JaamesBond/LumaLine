// test/gdpr-deletion.integration.mjs — M3-T5: GDPR publisher-deletion workflow.
//
// The right-to-erasure workflow must REMOVE a publisher's personal data (handle,
// email, Stripe account ref, devices, dispute free-text) while PRESERVING the
// financial ledger (impressions / ledger_entries / payouts stay intact and balanced)
// so accounting integrity and the zero-sum invariant survive a deletion.
//
// Setup + DB assertions use psql (auth.users is not reachable via PostgREST).
// Self-skips if the local stack or psql is unavailable.
//
// WHAT IS TESTED:
//   T47 — non-admin cannot call gdpr_delete_publisher (403/401/500)
//   T48 — admin deletion anonymizes the publishers row (handle/stripe scrubbed, deleted_at + suspended)
//   T49 — devices removed; dispute free-text scrubbed
//   T50 — ledger_entries for the publisher are UNCHANGED and still balanced (financial integrity)
//   T51 — auth.users email is scrubbed (PII removed)
//   T52 — deletion is idempotent (second call returns already_deleted)

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const REST_BASE = 'http://127.0.0.1:54321/rest/v1';
const DB_URL    = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';
const ADMIN_USER_ID     = 'a0000000-0000-4000-8000-000000000001';
const NON_ADMIN_USER_ID = '22222222-2222-2222-2222-222222222222';

function mintJwt(sub, extra = {}) {
  const enc     = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000, ...extra });
  const sig     = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}
const ADMIN_JWT     = mintJwt(ADMIN_USER_ID);
const NON_ADMIN_JWT = mintJwt(NON_ADMIN_USER_ID);

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

async function rpcWithJwt(fnName, body, jwt) {
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, {
    method: 'POST',
    headers: { apikey: ANON, Authorization: `Bearer ${jwt}`, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const STACK_UP  = await isStackUp();
const PSQL_OK   = STACK_UP ? psqlWorks() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING' : !PSQL_OK ? 'psql unavailable — SKIPPING' : false;
if (SKIP) console.log(`[gdpr-deletion.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Throwaway publisher fixture (created via psql; auth.users + full chain).
// ---------------------------------------------------------------------------
const F = {
  authId:    randomUUID(),
  pubId:     randomUUID(),
  deviceId:  randomUUID(),
  impId:     randomUUID(),
  windowId:  randomUUID(),
  groupId:   randomUUID(),
  disputeId: randomUUID(),
};
F.email  = `gdpr-${F.authId}@example.com`;
F.handle = `gdpr-${F.pubId.slice(0, 8)}`;
F.disputeText = 'my sensitive complaint with personal details';
const GROSS = 1_000_000, PUB_SHARE = 600_000, PLAT_SHARE = 400_000;

let ledgerBefore = null;

function seedFixture() {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${F.authId}', 'authenticated', 'authenticated',
      '${F.email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, status)
    values ('${F.pubId}', '${F.authId}', '${F.handle}', 'US', 'acct_test_${F.pubId.slice(0,8)}', 'active');`);
  psql(`insert into public.devices (id, publisher_id, label) values ('${F.deviceId}', '${F.pubId}', 'gdpr-test-device');`);
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state)
    values ('${F.impId}', '${F.windowId}', '${F.pubId}', 5, ${GROSS}, 'cleared');`);
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
      ('${F.groupId}','cpva_accrual','advertiser_billing', ${GROSS},     'cleared','impression','${F.impId}', null),
      ('${F.groupId}','cpva_accrual','publisher_earnings', ${-PUB_SHARE},'cleared','impression','${F.impId}', '${F.pubId}'),
      ('${F.groupId}','cpva_accrual','platform_revenue',   ${-PLAT_SHARE},'cleared','impression','${F.impId}', null);`);
  psql(`insert into public.disputes (id, publisher_id, impression_id, description, status)
    values ('${F.disputeId}', '${F.pubId}', '${F.impId}', '${F.disputeText}', 'open');`);
  ledgerBefore = psql(`select count(*)||'|'||coalesce(sum(amount_micros),0) from public.ledger_entries where entry_group_id='${F.groupId}';`);
}

function teardownFixture() {
  try {
    psql(`delete from public.ledger_entries where entry_group_id='${F.groupId}';`);
    psql(`delete from public.disputes where publisher_id='${F.pubId}';`);
    psql(`delete from public.impressions where id='${F.impId}';`);
    psql(`delete from public.devices where publisher_id='${F.pubId}';`);
    psql(`delete from public.publishers where id='${F.pubId}';`);
    psql(`delete from auth.users where id='${F.authId}';`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

test('T47: non-admin cannot call gdpr_delete_publisher (403/401/500)', { skip: SKIP }, async () => {
  const res = await rpcWithJwt('gdpr_delete_publisher', { p_publisher_id: randomUUID() }, NON_ADMIN_JWT);
  assert.ok(res.status === 403 || res.status === 401 || res.status === 500,
    `Expected 403/401/500, got ${res.status}: ${JSON.stringify(res.data)}`);
});

test('T48: admin deletion anonymizes the publishers row', { skip: SKIP }, async () => {
  const res = await rpcWithJwt('gdpr_delete_publisher', { p_publisher_id: F.pubId }, ADMIN_JWT);
  assert.ok(res.ok, `gdpr_delete_publisher failed: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);

  const row = psql(`select handle||'|'||coalesce(stripe_account_id,'NULL')||'|'||status||'|'||(deleted_at is not null) from public.publishers where id='${F.pubId}';`);
  const [handle, stripe, status, deletedSet] = row.split('|');
  assert.notEqual(handle, F.handle, 'handle must be scrubbed');
  assert.equal(stripe, 'NULL', 'stripe_account_id must be nulled');
  assert.equal(status, 'suspended', 'status must be suspended');
  assert.equal(deletedSet, 'true', 'deleted_at must be set');
});

test('T49: devices removed; dispute free-text scrubbed', { skip: SKIP }, async () => {
  const devCount = psql(`select count(*) from public.devices where publisher_id='${F.pubId}';`);
  assert.equal(devCount, '0', 'devices must be deleted');

  const desc = psql(`select description from public.disputes where id='${F.disputeId}';`);
  assert.notEqual(desc, F.disputeText, 'dispute description must be scrubbed');
  assert.ok(desc.length > 0, 'dispute row must still exist (audit), only the text scrubbed');
});

test('T50: ledger_entries unchanged and still balanced (financial integrity)', { skip: SKIP }, async () => {
  const after = psql(`select count(*)||'|'||coalesce(sum(amount_micros),0) from public.ledger_entries where entry_group_id='${F.groupId}';`);
  assert.equal(after, ledgerBefore, 'ledger rows + sum must be identical before/after deletion');
  const [count, sum] = after.split('|');
  assert.equal(count, '3', 'all 3 ledger legs preserved');
  assert.equal(sum, '0', 'ledger group must remain zero-sum balanced');

  // publisher_earnings leg must still attribute to this publisher_id (opaque key preserved).
  const earn = psql(`select amount_micros from public.ledger_entries where entry_group_id='${F.groupId}' and account='publisher_earnings';`);
  assert.equal(earn, String(-PUB_SHARE), 'publisher_earnings leg preserved intact');
});

test('T51: auth.users email is scrubbed (PII removed)', { skip: SKIP }, async () => {
  const email = psql(`select email from auth.users where id='${F.authId}';`);
  assert.notEqual(email, F.email, 'email must be scrubbed');
  assert.ok(/deleted/i.test(email) || email === '', `scrubbed email should be a tombstone, got: ${email}`);
});

test('T52: deletion is idempotent (second call returns already_deleted)', { skip: SKIP }, async () => {
  const res = await rpcWithJwt('gdpr_delete_publisher', { p_publisher_id: F.pubId }, ADMIN_JWT);
  assert.equal(res.data?.ok, false, 'second deletion must be a no-op');
  assert.equal(res.data?.reason, 'already_deleted');
});
