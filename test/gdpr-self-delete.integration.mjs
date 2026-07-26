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
//
// GDPR PHASE 4b (20260729110000) — an unpaid balance DEFERS erasure instead of destroying it:
//   S13 — a publisher who is OWED money is deferred (earnings_unpaid), not erased; the balance and
//         their payout eligibility both survive intact
//   S14 — once the balance is actually PAID, the cron erases them — and the money went to them
//   S15 — sub-cent dust does NOT deadlock erasure (Stripe cannot transfer it, so it cannot block)
//   S16 — a payout already in flight still reports its own, more specific reason (ordering)
//   S17 — THE WHOLE LOOP: close owing less than the EUR 1 minimum -> deferred -> the weekly batch
//         pays it in full under Phase 4's waiver -> the cron completes the erasure. This is the
//         sequence that makes publisher-tos.md 7.3 and the README true as written.

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
//
// `verified` + `owedMicros` are the Phase-4b additions: a publisher can only be DEFERRED for money
// they are owed if they actually have a matured balance, and the deferral can only ever CLEAR if
// they are payout-eligible. Both default off so every Phase-3 test above keeps its exact fixture.
function seedPendingPublisher({ payoutInFlight = false, verified = false, owedMicros = 0 } = {}) {
  const authId = randomUUID(), pubId = randomUUID(), deviceId = randomUUID();
  const email = `self-p3-${authId}@example.com`;
  seedUser(authId, email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, payout_status, status)
    values ('${pubId}', '${authId}', 'p3-${pubId.slice(0, 8)}', 'FR', 'acct_p3_${pubId.slice(0,8)}',
            '${verified ? 'verified' : 'none'}', 'active');`);
  psql(`insert into public.devices (id, publisher_id, label) values ('${deviceId}', '${pubId}', 'p3-device');`);
  if (payoutInFlight) {
    psql(`insert into public.payouts (id, publisher_id, amount_micros, status, hold_until, min_payout_micros)
      values ('${randomUUID()}', '${pubId}', 1000000, 'pending', now(), 1000000);`);
  }
  extraPubIds.push(pubId);
  extraAuthIds.push(authId);
  if (owedMicros > 0) addMaturedEarning(pubId, owedMicros);
  return { authId, pubId, deviceId, email, jwt: mintJwt(authId) };
}

/**
 * Book `pubMicros` of cleared CPVA earnings for `pubId`, backed by a REAL public.impressions row
 * aged well past the 7-day payout hold.
 *
 * The impression row is not decoration. app.publisher_payable_micros JOINs public.impressions on
 * le.source_id and gates on `imp.created_at <= now() - p_hold`, so a bare ledger_entries row leaves
 * the payable at ZERO — and every "the publisher is owed money" assertion downstream would then
 * pass vacuously against a fixture that owes nothing. Each test re-reads the payable back before
 * acting, so this can never silently degrade into that.
 */
function addMaturedEarning(pubId, pubMicros, ageDays = 30) {
  const impId = randomUUID(), winId = randomUUID(), grp = randomUUID();
  const gross = Math.round(pubMicros / 0.6);        // the 60/40 split; legs are booked explicitly
  const plat  = gross - pubMicros;
  psql(`insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, created_at)
    values ('${impId}', '${winId}', '${pubId}', 5, ${gross}, 'cleared', now() - interval '${ageDays} days');`);
  psql(`insert into public.ledger_entries (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
      ('${grp}','cpva_accrual','advertiser_billing', ${gross},      'cleared','impression','${impId}', null),
      ('${grp}','cpva_accrual','publisher_earnings', ${-pubMicros}, 'cleared','impression','${impId}', '${pubId}'),
      ('${grp}','cpva_accrual','platform_revenue',   ${-plat},      'cleared','impression','${impId}', null);`);
  return { impId, grp };
}

const liveDevices = (pubId) =>
  psql(`select count(*) from public.devices where publisher_id='${pubId}' and revoked_at is null;`);

/** What the publisher is owed right now, in micros, through the real payout-hold constant. */
const payable = (pubId) =>
  Number(psql(`select app.publisher_payable_micros('${pubId}'::uuid, app.payout_hold_interval());`));

const erased = (pubId) =>
  psql(`select (deleted_at is not null) from public.publishers where id='${pubId}';`);

/**
 * Is this publisher still reachable by the payout batch at all? This is the exact candidate
 * predicate from payout_batch_reserve. Erasure nulls stripe_account_id, zeroes payout_status,
 * suspends status and sets deleted_at — FOUR independent reasons this goes to 0 and never comes
 * back. That is precisely how an erased publisher's balance became unrecoverable, so it is the
 * assertion that actually pins the defect rather than a proxy for it.
 */
const payoutCandidate = (pubId) =>
  psql(`select count(*) from public.publishers where id='${pubId}'
          and payout_status='verified' and stripe_account_id is not null
          and status='active' and deleted_at is null;`);

const activePayouts = (pubId) =>
  psql(`select count(*) from public.payouts where publisher_id='${pubId}' and status in ('pending','in_transit');`);

/**
 * The EUR 1 payout minimum the CLI, the README and the ToS all promise.
 *
 * Every fixture below is deliberately owed LESS than EUR 25 — the minimum every other payout suite
 * in this repo runs its batches at (payout-rails' MIN, and payout_batch_reserve's own default,
 * which payout-reserve-serialize uses). A concurrent suite therefore cannot reserve one of these
 * publishers out from under a precondition. Do not raise these amounts past 25_000_000.
 */
const EUR1 = 1_000_000;

/** This publisher's active payout as 'amount|status', or null. */
function activePayout(pubId) {
  const row = psql(`select amount_micros||'|'||status from public.payouts
                     where publisher_id='${pubId}' and status in ('pending','in_transit') limit 1;`);
  return row === '' ? null : row;
}

/**
 * Run the REAL weekly batch and keep only THIS publisher's outcome.
 *
 * public.payout_batch_reserve is global — it has no publisher argument — and `node --test` runs
 * test FILES in parallel. An unrestrained call here therefore reserves OTHER suites' fixtures
 * mid-test and breaks them: payout-rails P2 builds a 30M balance one 600k earning at a time, and a
 * batch firing halfway through reserves it for whatever it has accumulated so far.
 *
 * So the batch runs inside ONE transaction that discards, before committing, every reservation it
 * created for a publisher outside this fixture. Those rows are created and dropped inside the same
 * transaction, so no other session ever observes them. What commits is exactly what the real
 * function, with the real predicate, decided about `pubId` — nothing here stubs or shortcuts the
 * decision under test.
 *
 * The batch's own `reserved`/`skipped` list is still not a reliable per-publisher signal (a
 * concurrent suite may have reserved this publisher microseconds earlier, which reads as
 * `already_reserved`), so callers assert on the committed OUTCOME instead. The raw result is
 * returned alongside purely for failure messages.
 */
function reserveFor(pubId, minMicros = EUR1) {
  const res = JSON.parse(psql(`
    begin;
    create temp table _p4b_pre on commit drop as select id from public.payouts;
    create temp table _p4b_out on commit drop as
      select public.payout_batch_reserve(app.payout_hold_interval(), ${minMicros}, 10000000000, 500) as r;
    delete from public.payouts
     where publisher_id <> '${pubId}'::uuid and id not in (select id from _p4b_pre);
    select r::text from _p4b_out;
    commit;`));
  return { res, payout: activePayout(pubId) };
}

/** Settle whatever the batch reserved for this publisher, exactly as the Stripe webhook would. */
function settlePayout(pubId) {
  const payoutId = psql(`select id from public.payouts where publisher_id='${pubId}' and status='pending' limit 1;`);
  assert.notEqual(payoutId, '', 'precondition: a pending payout to settle');
  const res = JSON.parse(psql(`select public.payout_confirm('${payoutId}', 'tr_p4b_${payoutId.slice(0, 8)}')::text;`));
  assert.equal(res.ok, true, `payout_confirm failed: ${JSON.stringify(res)}`);
  return payoutId;
}

const sweep = () => JSON.parse(psql('select app.gdpr_complete_pending()::text'));

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
  // Phase 3/4b per-test fixtures. Separate try so a failure above cannot strand them.
  try {
    if (!extraPubIds.length) return;
    const pubs = extraPubIds.map((x) => `'${x}'`).join(',');
    // Ledger first, BY GROUP: a payout group's platform_cash leg carries publisher_id = NULL, so
    // deleting on publisher_id alone would leave half of every settled payout behind and unbalance
    // the global ledger for any suite that checks zero-sum after this one.
    psql(`delete from public.ledger_entries where entry_group_id in (
            select entry_group_id from public.ledger_entries where publisher_id in (${pubs}));
          delete from public.impressions        where publisher_id in (${pubs});
          delete from public.payouts            where publisher_id in (${pubs});
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

test('S11: app.gdpr_complete_pending() erases a publisher once the payout settles', { skip: SKIP }, async () => {
  const P = seedPendingPublisher({ payoutInFlight: true });
  const req = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(req.data?.state, 'pending', `precondition: the request must defer, got ${JSON.stringify(req.data)}`);

  // STILL BLOCKED — the cron re-runs the SAME money gate. Without this half, the "it erased"
  // assertion below would pass equally well against a cron that ignores the gate entirely.
  const sweep = () => JSON.parse(psql('select app.gdpr_complete_pending()::text'));
  sweep();
  assert.equal(psql(`select (deleted_at is null) from public.publishers where id='${P.pubId}';`), 't',
    'a payout still in flight must keep the deletion pending');

  // The payout settles -> the next pass completes it via the UNCHANGED erasure body.
  psql(`update public.payouts set status='paid' where publisher_id='${P.pubId}';`);
  const out = sweep();
  assert.ok(out.publishers_erased >= 1, `expected at least one erasure, got ${JSON.stringify(out)}`);
  assert.equal(psql(`select (deleted_at is not null) from public.publishers where id='${P.pubId}';`), 't');
  assert.match(psql(`select handle from public.publishers where id='${P.pubId}';`), /^deleted-/,
    'the real erasure body ran — the handle is anonymized, not merely flagged');
  assert.match(psql(`select email from auth.users where id='${P.authId}';`), /deleted/i,
    'and the auth email is tombstoned, exactly as on the direct path');
  assert.equal(psql(`select coalesce(deletion_requested_at::text,'NULL') from public.publishers where id='${P.pubId}';`),
    'NULL', 'the watermark is cleared on completion');

  // Idempotent: a further pass neither errors nor re-touches the row.
  const erasedAt = psql(`select deleted_at from public.publishers where id='${P.pubId}';`);
  sweep();
  assert.equal(psql(`select deleted_at from public.publishers where id='${P.pubId}';`), erasedAt);
});

test('S12: cancel clears the watermark and re-opens login, but does NOT un-revoke devices', { skip: SKIP }, async () => {
  const P = seedPendingPublisher({ payoutInFlight: true });
  const req = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(req.data?.state, 'pending', `precondition: ${JSON.stringify(req.data)}`);
  assert.equal(liveDevices(P.pubId), '0', 'precondition: the freeze revoked the device');

  const res = await rpcWithJwt('gdpr_cancel_deletion', {}, P.jwt);
  assert.ok(res.ok, `cancel failed: ${res.status} ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(res.data?.state, 'cancelled');
  assert.equal(psql(`select coalesce(deletion_requested_at::text,'NULL') from public.publishers where id='${P.pubId}';`),
    'NULL', 'the cron must never pick this row up again');
  assert.equal(psql(`select (deleted_at is null) from public.publishers where id='${P.pubId}';`), 't');

  // Devices stay revoked BY DESIGN: a revoked credential is a revoked credential, and silently
  // reviving one the user had cause to consider destroyed is the wrong default. The payload has to
  // say so, or the CLI cannot tell the user what to do next.
  assert.equal(liveDevices(P.pubId), '0', 'cancel must not un-revoke devices');
  assert.ok(Number(res.data?.devices_still_revoked) >= 1, 'the payload reports the revoked devices');
  assert.match(String(res.data?.next_step ?? ''), /login/i, 'and tells the client how to recover');

  // ...and the way back IS open again: the mint gate is lifted, so the user can re-authenticate.
  const hash = `p3cancel-${randomUUID()}`;
  psql(`insert into public.device_auth_codes (device_code_hash, user_code, publisher_id, status, expires_at)
        values ('${hash}', 'P3C${randomUUID().slice(0, 6).toUpperCase()}', '${P.pubId}', 'approved',
                now() + interval '10 minutes');`);
  const minted = JSON.parse(psql(`select public.device_code_redeem('${hash}', 'p3', '0.1.7', 'rt-${randomUUID()}')::text;`));
  assert.equal(minted.status, 'approved', 'login works again after cancel');
  assert.equal(liveDevices(P.pubId), '1', 'and the fresh device is live');

  // Nothing pending any more.
  const twice = await rpcWithJwt('gdpr_cancel_deletion', {}, P.jwt);
  assert.equal(twice.data?.ok, false);
  assert.equal(twice.data?.reason, 'not_pending');

  // And the cron must never come back for it, even once every blocker has cleared. A cancel the
  // hourly pass then overrides is the worst outcome in this phase: an irreversible erasure of an
  // account its owner just saved. (The cron also re-reads each row FOR UPDATE, covering the
  // concurrent case this single-session assertion cannot reach.)
  psql(`update public.payouts set status='paid' where publisher_id='${P.pubId}';`);
  psql('select app.gdpr_complete_pending();');
  assert.equal(psql(`select (deleted_at is null) from public.publishers where id='${P.pubId}';`), 't',
    'a cancelled deletion must never be completed by the cron');

  // Cancel dies at erasure: A (module fixture) was erased back in S1.
  const late = await rpcWithJwt('gdpr_cancel_deletion', {}, A_JWT);
  assert.equal(late.data?.ok, false);
  assert.equal(late.data?.reason, 'already_deleted', 'erasure is terminal — cancel cannot undo it');
});

// --- GDPR Phase 4b: an unpaid balance defers erasure instead of destroying it ----------
//
// 20260729110000_defer_erasure_while_owed.sql adds ONE refusal to app.gdpr_erase_publisher —
// `earnings_unpaid`, when the publisher is owed at least one whole cent — and adds that reason to
// app.gdpr_deferrable_reason's allow-list so it schedules rather than dead-ends.
//
// THE GAP THESE CLOSE. Every pre-existing Phase-4 test set publishers.deletion_requested_at BY
// HAND, which is exactly why the suite was green while the product path was broken: nothing
// exercised what public.gdpr_self_delete() actually does to a publisher who is owed money. All five
// below drive closure through the REAL RPC, over a REAL matured balance, and each re-reads its own
// precondition live before acting — a fixture with no impressions row would make
// app.publisher_payable_micros return 0 and turn every one of these green against a broken build.

test('S13: a publisher who is OWED money is DEFERRED, not erased', { skip: SKIP }, async () => {
  const P = seedPendingPublisher({ verified: true, owedMicros: 5_000_000 });   // EUR 5 — under the EUR 25 every other suite's batch uses

  // PRECONDITIONS, proven live. The second is the one that matters: before this migration, an
  // in-flight payout was the ONLY thing that could stop an erasure, so a publisher with nothing in
  // flight is precisely the case that used to be erased over.
  assert.equal(payable(P.pubId), 5_000_000, 'precondition: a real, matured, unpaid balance');
  assert.equal(activePayouts(P.pubId), '0', 'precondition: NOTHING in flight — the only pre-4b guard');
  assert.equal(payoutCandidate(P.pubId), '1', 'precondition: the batch can still reach them');

  const res = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(res.data?.ok, true, `a deferral is an ACCEPTED request, not a rejection: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.state, 'pending');
  assert.equal(res.data?.reason, 'earnings_unpaid');

  // NOT erased, and the money is untouched to the micro.
  assert.equal(erased(P.pubId), 'f', 'a publisher who is owed money must not be erased');
  assert.equal(payable(P.pubId), 5_000_000, 'the full balance survives the request');
  assert.ok(psql(`select deletion_requested_at from public.publishers where id='${P.pubId}';`).length > 0,
    'the request is RECORDED — it is deferred, not refused');

  // ...and, decisively, they are STILL reachable by the payout batch. This is the assertion the
  // defect fails: erasure nulls the Stripe account, zeroes payout_status and suspends the row, so
  // an erased publisher can never be a candidate again and the balance is gone for good.
  assert.equal(payoutCandidate(P.pubId), '1', 'the money can still be paid — nothing was destroyed');

  // The freeze still applies (Phase 3), and status stays 'active' so the payout can actually run.
  assert.equal(liveDevices(P.pubId), '0', 'serving is frozen');
  assert.equal(psql(`select status from public.publishers where id='${P.pubId}';`), 'active',
    'status must stay active — payout_batch_reserve requires it');
});

test('S14: once the balance is actually PAID, the cron erases them', { skip: SKIP }, async () => {
  const P = seedPendingPublisher({ verified: true, owedMicros: 5_000_000 });
  assert.equal(payable(P.pubId), 5_000_000, 'precondition: a real matured balance');

  const req = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(req.data?.reason, 'earnings_unpaid', `precondition: deferred for the balance: ${JSON.stringify(req.data)}`);

  // STILL BLOCKED while the money is unpaid. Without this half, the erasure below would pass
  // equally well against a cron that ignores the gate entirely and erases on the first pass.
  sweep();
  assert.equal(erased(P.pubId), 'f', 'an unpaid balance must keep the deletion pending');
  assert.equal(payable(P.pubId), 5_000_000, 'and must not be quietly written off to unblock it');

  // The weekly batch pays them. This balance is well ABOVE the EUR 1 minimum, so no Phase 4 waiver
  // is involved — the ordinary payout path is enough to clear an ordinary deferral.
  const { res: batch, payout } = reserveFor(P.pubId);
  assert.equal(payout, '5000000|pending', `the batch must reserve the full balance: ${JSON.stringify(batch)}`);
  const payoutId = settlePayout(P.pubId);

  // THE MONEY WENT TO THEM. A guard that unblocked erasure by zeroing the balance instead of paying
  // it would satisfy "payable is 0" just as well, so assert the transfer and its ledger, not just
  // the absence of a balance.
  assert.equal(psql(`select status||'|'||amount_micros from public.payouts where id='${payoutId}';`),
    'paid|5000000', 'the full balance was actually transferred');
  assert.equal(psql(`select coalesce(sum(amount_micros),0) from public.ledger_entries
                       where source_type='payout' and source_id='${payoutId}' and account='publisher_earnings';`),
    '5000000', 'the payout is booked against publisher_earnings, in full');
  assert.equal(psql(`select coalesce(sum(amount_micros),0) from public.ledger_entries
                       where source_type='payout' and source_id='${payoutId}';`),
    '0', 'and the payout ledger group is zero-sum balanced');
  assert.equal(payable(P.pubId), 0, 'nothing is owed any more');

  // Now — and only now — the gate passes and the hourly cron completes the erasure.
  const out = sweep();
  assert.ok(out.publishers_erased >= 1, `expected an erasure once paid, got ${JSON.stringify(out)}`);
  assert.equal(erased(P.pubId), 't');
  assert.match(psql(`select handle from public.publishers where id='${P.pubId}';`), /^deleted-/,
    'the real erasure body ran — anonymized, not merely flagged');
  assert.equal(psql(`select coalesce(deletion_requested_at::text,'NULL') from public.publishers where id='${P.pubId}';`),
    'NULL', 'the watermark is cleared on completion');

  // The ledger still records that they were paid — erasure preserves the financial trail.
  assert.equal(psql(`select status from public.payouts where id='${payoutId}';`), 'paid',
    'the payout record survives the erasure');
});

test('S15: sub-cent dust does NOT deadlock erasure', { skip: SKIP }, async () => {
  // Below one whole cent, Stripe cannot transfer the money and payout_batch_reserve floors it to
  // zero, so a guard that refused here would freeze the account FOREVER for an amount that can
  // never be paid — trading a strand for a deadlock. The floor exists to make that impossible.
  const P = seedPendingPublisher({ verified: true, owedMicros: 5_000 });   // EUR 0.005

  assert.equal(payable(P.pubId), 5_000, 'precondition: real, non-zero, but sub-cent');
  assert.ok(payable(P.pubId) < 10_000, 'precondition: genuinely below the one-cent floor');
  // The batch agrees it is unpayable — run ITS whole-cent floor over this balance and it comes out
  // at zero, so there is no minimum at which payout_batch_reserve would ever transfer this. The
  // guard and the batch use the same number, so the two sets line up exactly. (Computed rather than
  // reserved: an actual batch at a 1-cent minimum would reserve every eligible publisher in the
  // database, including other suites' fixtures.)
  assert.equal(psql(`select (app.publisher_payable_micros('${P.pubId}'::uuid, app.payout_hold_interval()) / 10000) * 10000;`),
    '0', 'precondition: the payout batch floors this to zero whole cents — it can never be paid');

  const res = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(res.data?.ok, true, `dust must not block erasure: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.state, 'erased', 'erasure completes immediately, on the spot');
  assert.equal(erased(P.pubId), 't');
  assert.match(psql(`select handle from public.publishers where id='${P.pubId}';`), /^deleted-/);
});

test('S16: a payout already in flight still reports its own, more specific reason', { skip: SKIP }, async () => {
  // Both guards fire for this publisher — a pending payout books NO ledger, so the balance is still
  // fully payable while the transfer is in flight. Ordering is what decides which reason a human
  // reads, and payout_in_flight names the actual blocker.
  const P = seedPendingPublisher({ verified: true, owedMicros: 5_000_000, payoutInFlight: true });

  assert.equal(activePayouts(P.pubId), '1', 'precondition: a payout really is in flight');
  assert.ok(payable(P.pubId) >= 10_000, 'precondition: the earnings_unpaid guard would ALSO fire here');

  const res = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(res.data?.state, 'pending');
  assert.equal(res.data?.reason, 'payout_in_flight',
    'the in-flight check runs first — its reason is the more specific one');
  assert.notEqual(res.data?.reason, 'earnings_unpaid', 'the new guard must not shadow it');
  assert.equal(erased(P.pubId), 'f');
});

test('S17: THE WHOLE LOOP — close below the minimum, get paid in full, then be erased', { skip: SKIP }, async () => {
  // This is the sequence the two published promises describe:
  //   docs/legal/publisher-tos.md 7.3 — "A balance you have carried forward is never forfeited by
  //                                     leaving"
  //   README.md                       — "whatever you've earned is paid out in full … We never keep
  //                                     your earnings"
  // Before Phase 4b it was false at the first step: this publisher was erased on the spot and the
  // EUR 0.40 was kept. Every link is exercised here through its real entry point.
  const P = seedPendingPublisher({ verified: true, owedMicros: 400_000 });   // EUR 0.40

  assert.equal(payable(P.pubId), 400_000, 'precondition: a real, matured balance');
  assert.ok(payable(P.pubId) < EUR1, 'precondition: BELOW the EUR 1 minimum the ToS and CLI promise');

  // A publisher who has NOT asked to close is left alone by the batch at this balance — so the
  // reservation below is attributable to the closure waiver and to nothing else.
  const open = seedPendingPublisher({ verified: true, owedMicros: 400_000 });
  assert.equal(reserveFor(open.pubId).payout, null,
    'control: an open account below the minimum still carries the balance forward');

  // 1. Close. Deferred, not erased — the money is not destroyed.
  const req = await rpcWithJwt('gdpr_self_delete', {}, P.jwt);
  assert.equal(req.data?.ok, true);
  assert.equal(req.data?.state, 'pending');
  assert.equal(req.data?.reason, 'earnings_unpaid');
  assert.equal(erased(P.pubId), 'f', 'not erased while owed');
  assert.equal(payable(P.pubId), 400_000, 'and not a micro of it lost');

  // 2. The weekly batch runs at the SAME EUR 1 minimum that just skipped the control publisher.
  //    Phase 4 waives it for a closing account, so this sub-minimum balance is reserved in full.
  const { res: batch, payout } = reserveFor(P.pubId);
  assert.equal(payout, '400000|pending', `Phase 4's waiver must pay a closing account in full: ${JSON.stringify(batch)}`);
  assert.equal(activePayout(open.pubId), null, 'and must NOT change anything for anyone else');

  // 3. The transfer settles — paid IN FULL, exactly what was earned.
  const payoutId = settlePayout(P.pubId);
  assert.equal(psql(`select amount_micros from public.payouts where id='${payoutId}';`), '400000',
    'paid in full: the whole balance, not a rounded-down fraction of it');
  assert.equal(payable(P.pubId), 0);

  // 4. The hourly cron re-runs the gate, it now passes, and the erasure completes.
  const out = sweep();
  assert.ok(out.publishers_erased >= 1, `the cron must complete it once paid: ${JSON.stringify(out)}`);
  assert.equal(erased(P.pubId), 't', 'the erasure request is honoured — deferred, never dropped');
  assert.match(psql(`select email from auth.users where id='${P.authId}';`), /deleted/i,
    'and it is a REAL erasure: the auth email is tombstoned');

  // The control publisher is untouched throughout: still open, still owed, still carrying forward.
  assert.equal(erased(open.pubId), 'f');
  assert.equal(payable(open.pubId), 400_000, 'a bystander below the minimum keeps their balance');
});
