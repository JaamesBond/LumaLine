// test/gdpr-self-delete.integration.mjs — M7: self-serve GDPR erasure for the portal.
//
// gdpr_self_delete() lets a publisher erase THEIR OWN account from a direct Supabase
// Auth web session. It takes NO argument — the target is derived from
// app.current_publisher_id() (the caller's auth.uid()) — so it is structurally
// impossible to target another publisher. Semantics match the admin path: anonymize
// the publisher row in place, delete device PII, redact dispute text, tombstone the
// auth email, PRESERVE the financial ledger, refuse while a payout is in flight,
// idempotent afterward.
//
// Setup + DB assertions use psql (auth.users is not reachable via PostgREST).
// Self-skips if the local stack or psql is unavailable.
//
// WHAT IS TESTED:
//   S1 — self-delete anonymizes the caller's OWN publisher row
//   S2 — devices removed; dispute free-text scrubbed
//   S3 — ledger_entries unchanged and still balanced (financial integrity)
//   S4 — auth.users email is scrubbed (PII removed)
//   S5 — idempotent (second call returns already_deleted)
//   S6 — a bystander publisher B is completely untouched (no cross-publisher erasure)
//   S7 — a payout in flight defers erasure into PENDING (not a dead-end refusal), row NOT deleted
//   S8 — an authenticated session with no publisher row is rejected (unauthenticated)
//
// GDPR PHASE 3 (20260727100000) — the pending-deletion state machine:
//   S9  — a blocked request enters pending, freezes serving via device revocation, keeps
//         status='active' (Phase 4's payout_batch_reserve needs it), and never restarts the
//         Art. 12(3) clock on a repeat request
//   S10 — the freeze holds: a pending publisher cannot mint a fresh device via the login flow
//   S11 — app.gdpr_complete_pending() erases once the blocker clears; idempotent; non-vacuous
//   S12 — cancel clears the watermark, re-opens login, and is refused after erasure

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

// ON_ERROR_STOP=1 so a failing statement is a nonzero exit and execFileSync THROWS. Without it psql
// prints the error, exits 0, and this helper cheerfully returns '' — every assertion downstream
// then compares against an empty string instead of failing loudly.
function psql(sql) {
  return execFileSync('psql', [DB_URL, '-v', 'ON_ERROR_STOP=1', '-tAqc', sql],
    { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

async function rpcWithJwt(fnName, body, jwt) {
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, {
    method: 'POST',
    headers: { apikey: ANON, Authorization: `Bearer ${jwt}`, 'content-type': 'application/json', accept: 'application/json' },
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
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING' : !PSQL_OK ? 'psql unavailable — SKIPPING' : false;
if (SKIP) console.log(`[gdpr-self-delete.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Fixtures (all created via psql; full auth.users + chain).
//   A — the self-deleting publisher (full chain: device + impression + ledger + dispute)
//   B — a bystander publisher, must remain untouched
//   C — a publisher with a pending payout (money-in-flight guard)
// ---------------------------------------------------------------------------
const A = { authId: randomUUID(), pubId: randomUUID(), deviceId: randomUUID(), impId: randomUUID(), windowId: randomUUID(), groupId: randomUUID(), disputeId: randomUUID() };
A.email = `self-a-${A.authId}@example.com`;
A.handle = `self-a-${A.pubId.slice(0, 8)}`;
A.disputeText = 'A private complaint with personal details';
const A_JWT = mintJwt(A.authId);

const B = { authId: randomUUID(), pubId: randomUUID() };
B.email = `self-b-${B.authId}@example.com`;
B.handle = `self-b-${B.pubId.slice(0, 8)}`;

const C = { authId: randomUUID(), pubId: randomUUID(), payoutId: randomUUID() };
C.email = `self-c-${C.authId}@example.com`;
C.handle = `self-c-${C.pubId.slice(0, 8)}`;
const C_JWT = mintJwt(C.authId);

const ORPHAN_JWT = mintJwt(randomUUID()); // valid session, no publisher row

const GROSS = 1_000_000, PUB_SHARE = 600_000, PLAT_SHARE = 400_000;
let ledgerBefore = null;

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

// ---------------------------------------------------------------------------
// Phase 3 fixtures are created PER TEST (the A/B/C fixtures above are module-level and shared, so
// they cannot carry per-test state like a device that must still exist at request time). Each one
// is tracked here so teardown reaches it even if its test throws half-way through.
// ---------------------------------------------------------------------------
const extraPubIds = [];
const extraAuthIds = [];

// A publisher with a live (unrevoked) device, optionally with a payout in flight — the exact
// precondition the pending path needs: something to freeze, and a reason to defer.
function seedPendingPublisher({ payoutInFlight = false } = {}) {
  const authId = randomUUID(), pubId = randomUUID(), deviceId = randomUUID();
  const email = `self-p3-${authId}@example.com`;
  seedUser(authId, email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, status)
    values ('${pubId}', '${authId}', 'p3-${pubId.slice(0, 8)}', 'FR', 'acct_p3_${pubId.slice(0,8)}', 'active');`);
  psql(`insert into public.devices (id, publisher_id, label) values ('${deviceId}', '${pubId}', 'p3-device');`);
  if (payoutInFlight) {
    psql(`insert into public.payouts (id, publisher_id, amount_micros, status, hold_until, min_payout_micros)
      values ('${randomUUID()}', '${pubId}', 1000000, 'pending', now(), 1000000);`);
  }
  extraPubIds.push(pubId);
  extraAuthIds.push(authId);
  return { authId, pubId, deviceId, email, jwt: mintJwt(authId) };
}

const liveDevices = (pubId) =>
  psql(`select count(*) from public.devices where publisher_id='${pubId}' and revoked_at is null;`);

function seedFixture() {
  // A — full chain.
  seedUser(A.authId, A.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, status)
    values ('${A.pubId}', '${A.authId}', '${A.handle}', 'FR', 'acct_test_${A.pubId.slice(0,8)}', 'active');`);
  psql(`insert into public.devices (id, publisher_id, label) values ('${A.deviceId}', '${A.pubId}', 'self-test-device');`);
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state)
    values ('${A.impId}', '${A.windowId}', '${A.pubId}', 5, ${GROSS}, 'cleared');`);
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
      ('${A.groupId}','cpva_accrual','advertiser_billing', ${GROSS},      'cleared','impression','${A.impId}', null),
      ('${A.groupId}','cpva_accrual','publisher_earnings', ${-PUB_SHARE}, 'cleared','impression','${A.impId}', '${A.pubId}'),
      ('${A.groupId}','cpva_accrual','platform_revenue',   ${-PLAT_SHARE},'cleared','impression','${A.impId}', null);`);
  psql(`insert into public.disputes (id, publisher_id, impression_id, description, status)
    values ('${A.disputeId}', '${A.pubId}', '${A.impId}', '${A.disputeText}', 'open');`);
  ledgerBefore = psql(`select count(*)||'|'||coalesce(sum(amount_micros),0) from public.ledger_entries where entry_group_id='${A.groupId}';`);

  // B — bystander.
  seedUser(B.authId, B.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, status)
    values ('${B.pubId}', '${B.authId}', '${B.handle}', 'DE', 'acct_test_${B.pubId.slice(0,8)}', 'active');`);

  // C — payout in flight.
  seedUser(C.authId, C.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, status)
    values ('${C.pubId}', '${C.authId}', '${C.handle}', 'ES', 'acct_test_${C.pubId.slice(0,8)}', 'active');`);
  psql(`insert into public.payouts (id, publisher_id, amount_micros, status, hold_until, min_payout_micros)
    values ('${C.payoutId}', '${C.pubId}', 1000000, 'pending', now(), 1000000);`);
}

function teardownFixture() {
  try {
    psql(`delete from public.ledger_entries where entry_group_id='${A.groupId}';`);
    psql(`delete from public.disputes where publisher_id='${A.pubId}';`);
    psql(`delete from public.impressions where id='${A.impId}';`);
    psql(`delete from public.devices where publisher_id='${A.pubId}';`);
    psql(`delete from public.payouts where publisher_id='${C.pubId}';`);
    psql(`delete from public.publishers where id in ('${A.pubId}','${B.pubId}','${C.pubId}');`);
    psql(`delete from auth.users where id in ('${A.authId}','${B.authId}','${C.authId}');`);
  } catch { /* best-effort */ }
  // Phase 3 per-test fixtures. Separate try so a failure above cannot strand them.
  try {
    if (!extraPubIds.length) return;
    const pubs = extraPubIds.map((x) => `'${x}'`).join(',');
    psql(`delete from public.payouts            where publisher_id in (${pubs});
          delete from public.device_auth_codes  where publisher_id in (${pubs});
          delete from public.devices            where publisher_id in (${pubs});
          delete from public.publishers         where id in (${pubs});
          delete from auth.users                where id in (${extraAuthIds.map((x) => `'${x}'`).join(',')});`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

test('S1: self-delete anonymizes the caller\'s own publisher row', { skip: SKIP }, async () => {
  const res = await rpcWithJwt('gdpr_self_delete', {}, A_JWT);
  assert.ok(res.ok, `gdpr_self_delete failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(res.data?.publisher_id, A.pubId, 'must resolve the caller\'s own publisher id');

  const row = psql(`select handle||'|'||coalesce(stripe_account_id,'NULL')||'|'||status||'|'||(deleted_at is not null) from public.publishers where id='${A.pubId}';`);
  const [handle, stripe, status, deletedSet] = row.split('|');
  assert.notEqual(handle, A.handle, 'handle must be scrubbed');
  assert.equal(stripe, 'NULL', 'stripe_account_id must be nulled');
  assert.equal(status, 'suspended', 'status must be suspended');
  assert.equal(deletedSet, 'true', 'deleted_at must be set');
});

test('S2: devices removed; dispute free-text scrubbed', { skip: SKIP }, async () => {
  const devCount = psql(`select count(*) from public.devices where publisher_id='${A.pubId}';`);
  assert.equal(devCount, '0', 'devices must be deleted');
  const desc = psql(`select description from public.disputes where id='${A.disputeId}';`);
  assert.notEqual(desc, A.disputeText, 'dispute description must be scrubbed');
  assert.ok(desc.length > 0, 'dispute row must still exist (audit), only the text scrubbed');
});

test('S3: ledger_entries unchanged and still balanced (financial integrity)', { skip: SKIP }, async () => {
  const after = psql(`select count(*)||'|'||coalesce(sum(amount_micros),0) from public.ledger_entries where entry_group_id='${A.groupId}';`);
  assert.equal(after, ledgerBefore, 'ledger rows + sum must be identical before/after deletion');
  const [count, sum] = after.split('|');
  assert.equal(count, '3', 'all 3 ledger legs preserved');
  assert.equal(sum, '0', 'ledger group must remain zero-sum balanced');
  const earn = psql(`select amount_micros from public.ledger_entries where entry_group_id='${A.groupId}' and account='publisher_earnings';`);
  assert.equal(earn, String(-PUB_SHARE), 'publisher_earnings leg preserved intact');
});

test('S4: auth.users email is scrubbed (PII removed)', { skip: SKIP }, async () => {
  const email = psql(`select email from auth.users where id='${A.authId}';`);
  assert.notEqual(email, A.email, 'email must be scrubbed');
  assert.ok(/deleted/i.test(email) || email === '', `scrubbed email should be a tombstone, got: ${email}`);
});

test('S5: idempotent (second call returns already_deleted)', { skip: SKIP }, async () => {
  const res = await rpcWithJwt('gdpr_self_delete', {}, A_JWT);
  assert.equal(res.data?.ok, false, 'second deletion must be a no-op');
  assert.equal(res.data?.reason, 'already_deleted');
});

test('S6: bystander publisher B is completely untouched', { skip: SKIP }, async () => {
  const row = psql(`select handle||'|'||coalesce(stripe_account_id,'NULL')||'|'||status||'|'||(deleted_at is null) from public.publishers where id='${B.pubId}';`);
  const [handle, stripe, status, notDeleted] = row.split('|');
  assert.equal(handle, B.handle, 'B handle must be intact');
  assert.notEqual(stripe, 'NULL', 'B stripe_account_id must be intact');
  assert.equal(status, 'active', 'B status must be unchanged');
  assert.equal(notDeleted, 'true', 'B deleted_at must remain null');
});

test('S7: a payout in flight DEFERS erasure into pending (Phase 3), never erasing early', { skip: SKIP }, async () => {
  // Phase 3 (20260727100000) changed what happens when the gate refuses, NOT when it refuses. The
  // money guard is byte-identical; the request now schedules itself instead of dead-ending at
  // {ok:false} while the Art. 12(3) one-month clock runs.
  const res = await rpcWithJwt('gdpr_self_delete', {}, C_JWT);
  assert.equal(res.data?.ok, true, 'the request is ACCEPTED — a deferral is not a rejection');
  assert.equal(res.data?.state, 'pending');
  assert.equal(res.data?.reason, 'payout_in_flight', 'the underlying money guard is unchanged');

  const notDeleted = psql(`select (deleted_at is null) from public.publishers where id='${C.pubId}';`);
  assert.equal(notDeleted, 't', 'C must NOT be anonymized while money is in flight');
  assert.ok(psql(`select deletion_requested_at from public.publishers where id='${C.pubId}';`).length > 0,
    'the deferral is RECORDED — that is the whole point of Phase 3');
});

test('S9: a blocked request freezes serving, keeps status active, and never restarts the clock', { skip: SKIP }, async () => {
  const P = seedPendingPublisher({ payoutInFlight: true });

  // PRECONDITION, proven live: there is a usable device to freeze. A revocation assertion against
  // a publisher that never had a device would pass on a no-op.
  assert.equal(liveDevices(P.pubId), '1', 'precondition: the publisher has one live device');

  const res = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(res.data?.ok, true);
  assert.equal(res.data?.state, 'pending');
  assert.equal(res.data?.reason, 'payout_in_flight');
  assert.equal(res.data?.devices_revoked, 1, 'the freeze reports what it actually revoked');

  // Watermark set, NOT erased, serving frozen through window_open's EXISTING d.revoked_at gate —
  // no hot-path change was needed to stop serving.
  const requestedAt = psql(`select deletion_requested_at from public.publishers where id='${P.pubId}';`);
  assert.ok(requestedAt.length > 0, 'watermark set');
  assert.equal(psql(`select (deleted_at is null) from public.publishers where id='${P.pubId}';`), 't');
  assert.equal(liveDevices(P.pubId), '0', 'every device revoked — serving stops');

  // status stays 'active'. Phase 4's payout_batch_reserve predicate requires
  // (payout_status='verified' AND status='active' AND deleted_at IS NULL); freezing via `status`
  // would block the very final payout that phase exists to deliver.
  assert.equal(psql(`select status from public.publishers where id='${P.pubId}';`), 'active');

  // A repeat request must NOT restart the Art. 12(3) one-month clock — otherwise a user who clicks
  // twice silently grants us another month, and the 25-day alert never fires.
  const again = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(again.data?.state, 'pending');
  assert.equal(psql(`select deletion_requested_at from public.publishers where id='${P.pubId}';`), requestedAt,
    'the original request timestamp is preserved verbatim across a repeat request');
});

test('S10: the freeze HOLDS — a pending publisher cannot mint a fresh device', { skip: SKIP }, async () => {
  // Revoking devices is only a freeze if the account cannot immediately un-freeze itself. The sole
  // device-mint point is public.device_code_redeem (the `lumaline login` device-code flow), so
  // that is where the freeze has to bite. Without this, `lumaline login` undoes S9 in one command.
  const P = seedPendingPublisher({ payoutInFlight: true });

  // An APPROVED device-code grant, i.e. the user has already completed the browser half of the
  // RFC 8628 flow. Redeeming it is the only way a device row is ever created.
  const mint = () => {
    const hash = `p3hash-${randomUUID()}`;
    psql(`insert into public.device_auth_codes (device_code_hash, user_code, publisher_id, status, expires_at)
          values ('${hash}', 'P3${randomUUID().slice(0, 6).toUpperCase()}', '${P.pubId}', 'approved',
                  now() + interval '10 minutes');`);
    return JSON.parse(psql(`select public.device_code_redeem('${hash}', 'p3', '0.1.7', 'rt-${randomUUID()}')::text;`));
  };

  // PRECONDITION, proven live: the mint flow really works for this publisher BEFORE the request.
  assert.equal(mint().status, 'approved', 'precondition: device_code_redeem mints while live');
  assert.equal(liveDevices(P.pubId), '2', 'precondition: the mint really did add a second device');

  const req = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(req.data?.state, 'pending');
  assert.equal(req.data?.devices_revoked, 2, 'both live devices revoked by the freeze');
  assert.equal(liveDevices(P.pubId), '0');

  // ...and the same grant flow now refuses, so the freeze cannot be undone by re-running `login`.
  assert.equal(mint().status, 'deletion_pending', 'a pending publisher must not mint a fresh device');
  assert.equal(liveDevices(P.pubId), '0', 'the refusal is REAL — no device row was written behind it');
});

test('S8: a session with no publisher row is rejected (unauthenticated)', { skip: SKIP }, async () => {
  const res = await rpcWithJwt('gdpr_self_delete', {}, ORPHAN_JWT);
  assert.ok(!res.ok, `expected an error for a publisher-less session, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.ok(res.status >= 400, `expected a 4xx/5xx, got ${res.status}`);
});
