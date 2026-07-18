// test/admin-gate-hardening.integration.mjs — M8-T3: harden the live money/destructive gates.
//
// 20260716120000_harden_money_rpc_gates.sql re-gates two ALREADY-DEPLOYED admin RPCs from
// app.is_admin() (membership only, aal1-satisfiable) to app.is_money_admin() (app.money_admins
// membership AND jwt aal='aal2' — 20260716100000), and makes each write ONE append-only row to
// app.admin_action_log. The reversal/erasure bodies are otherwise byte-identical.
//
// The gate is is_money_admin() = member(app.money_admins) AND jwt_claim('aal')='aal2'. The two
// ANDed conditions are exercised independently:
//   * a money-tier member with an aal1 session (no aal claim) is REFUSED  → aal enforcement
//   * an aal2 admin who is NOT a money-tier member is REFUSED             → money-tier enforcement
//   * an aal2 money-tier member is ALLOWED                                → the only path that acts
//
// Sessions are minted HS256 JWTs (sub = auth_user_id, plus a simulated `aal` claim that flows
// through PostgREST into request.jwt.claims, read by app.jwt_claim — the same mechanism the
// device JWT's publisher_id claim uses). Fixtures + audit-log assertions go through psql because
// app.admins / app.money_admins / app.admin_action_log live in the private `app` schema, off the
// Data API. Self-skips if the local stack or psql is unavailable.
//
// WHAT IS TESTED:
//   H1 — money_admin_check() over the Data API: only the aal2 money-tier member is true
//   H2 — approve_clawback REFUSED for a money-tier member on an aal1 session (aal enforcement)
//   H3 — approve_clawback REFUSED for an aal2 admin who is NOT a money-tier member (tier)
//   H4 — approve_clawback REFUSED for a non-admin session; H5 — REFUSED for anon
//   H6 — approve_clawback ALLOWED for the aal2 money-admin: review approved + EXACTLY ONE audit row
//   H7 — reject_clawback STILL works for a triage (is_admin, non-money) admin and writes NO audit row
//   H8 — reject_clawback REFUSED for a non-admin (is_admin unmet)
//   H9/H10/H11 — gdpr_delete_publisher REFUSED for aal1-money / aal2-non-money / anon; target untouched
//   H12 — gdpr_delete_publisher ALLOWED for the aal2 money-admin: erased + EXACTLY ONE audit row
//   H13 — app.admin_action_log is append-only: a direct UPDATE and DELETE both RAISE

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
// psql that is EXPECTED to fail (e.g. append-only trigger); returns the stderr text or '' on success.
function psqlExpectError(sql) {
  try { psql(sql); return ''; } catch (e) { return String(e.stderr || e.message || e); }
}

async function rpc(fnName, body, jwt) {
  const headers = { apikey: ANON, 'content-type': 'application/json', accept: 'application/json' };
  if (jwt) headers.Authorization = `Bearer ${jwt}`;
  const resp = await fetch(`${REST_BASE}/rpc/${fnName}`, { method: 'POST', headers, body: JSON.stringify(body ?? {}) });
  let data = null; try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

async function isStackUp() {
  try { const r = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) }); return r.status >= 200 && r.status < 500; } catch { return false; }
}
function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }
// The gate reduces to app.is_money_admin(), created in 20260716100000. Skip loudly if absent.
function foundationPresent() {
  try { return psql("select to_regprocedure('app.is_money_admin()') is not null;") === 't'; } catch { return false; }
}

const STACK_UP = await isStackUp();
const PSQL_OK  = STACK_UP ? psqlWorks() : false;
const FOUND    = PSQL_OK ? foundationPresent() : false;
const SKIP = !STACK_UP ? 'PostgREST unreachable — SKIPPING'
  : !PSQL_OK ? 'psql unavailable — SKIPPING'
  : !FOUND   ? 'app.is_money_admin() missing (foundation migration not applied) — SKIPPING'
  : false;
if (SKIP) console.log(`[admin-gate-hardening.integration] ${SKIP}`);

// ---------------------------------------------------------------------------
// Personas — the is_money_admin() truth table (member AND aal2):
//   MADMIN     — app.admins + app.money_admins, aal2  → the ONLY persona that may act
//   TRIAGE     — app.admins ONLY,               aal2  → refused on money (not a money member)
//   MONEY_AAL1 — app.admins + app.money_admins, aal1  → refused on money (session is aal1)
//   NONADMIN   — in no allow-list,              aal2  → refused everywhere (not an admin at all)
// ---------------------------------------------------------------------------
const MADMIN     = { authId: randomUUID() };
const TRIAGE     = { authId: randomUUID() };
const MONEY_AAL1 = { authId: randomUUID() };
MADMIN.email     = `gate-madmin-${MADMIN.authId}@example.com`;
TRIAGE.email     = `gate-triage-${TRIAGE.authId}@example.com`;
MONEY_AAL1.email = `gate-m1-${MONEY_AAL1.authId}@example.com`;

const MADMIN_JWT     = mintJwt(MADMIN.authId,     { aal: 'aal2' });
const TRIAGE_JWT     = mintJwt(TRIAGE.authId,     { aal: 'aal2' });
const MONEY_AAL1_JWT = mintJwt(MONEY_AAL1.authId);                 // no aal claim → COALESCE default 'aal1'
const NONADMIN_JWT   = mintJwt(randomUUID(),      { aal: 'aal2' }); // aal2 but not an admin

const REASON = 'M8-gate-test rationale';

// Fixtures: one risk_flag (FK target) + pending reviews with impression_id NULL so approve_clawback
// takes its no-op path (no ledger machinery). Two publishers for the GDPR path.
const RF        = randomUUID();
const REV_OK     = randomUUID(); // MADMIN approves this one (H6)
const REV_REFUSE = randomUUID(); // shared by every refusal test (gate RAISEs → never mutated)
const REV_REJECT = randomUUID(); // TRIAGE rejects this one (H7)
const VICTIM    = { authId: randomUUID(), pubId: randomUUID() }; // MADMIN erases this one (H12)
const BYSTANDER = { authId: randomUUID(), pubId: randomUUID() }; // targeted by refused GDPR calls, must survive
VICTIM.email    = `gate-victim-${VICTIM.authId}@example.com`;
BYSTANDER.email = `gate-bystander-${BYSTANDER.authId}@example.com`;
VICTIM.handle    = `gate-victim-${VICTIM.pubId.slice(0, 8)}`;
BYSTANDER.handle = `gate-bystander-${BYSTANDER.pubId.slice(0, 8)}`;

function seedUser(id, email) {
  psql(`insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change)
    values ('00000000-0000-0000-0000-000000000000', '${id}', 'authenticated', 'authenticated',
      '${email}', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');`);
}

function seedFixture() {
  // Admin identities.
  seedUser(MADMIN.authId, MADMIN.email);
  seedUser(TRIAGE.authId, TRIAGE.email);
  seedUser(MONEY_AAL1.authId, MONEY_AAL1.email);
  psql(`insert into app.admins (auth_user_id) values ('${MADMIN.authId}'), ('${TRIAGE.authId}'), ('${MONEY_AAL1.authId}');`);
  psql(`insert into app.money_admins (auth_user_id) values ('${MADMIN.authId}'), ('${MONEY_AAL1.authId}');`);

  // Review fixtures (impression_id NULL → approve_clawback no-op path; no ledger needed).
  psql(`insert into public.risk_flags (id, impression_id, window_id, reason) values ('${RF}', null, '${randomUUID()}', 'gate-test');`);
  psql(`insert into public.clawback_reviews (id, risk_flag_id, impression_id, status) values
      ('${REV_OK}',     '${RF}', null, 'pending'),
      ('${REV_REFUSE}', '${RF}', null, 'pending'),
      ('${REV_REJECT}', '${RF}', null, 'pending');`);

  // GDPR targets.
  seedUser(VICTIM.authId, VICTIM.email);
  seedUser(BYSTANDER.authId, BYSTANDER.email);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, status)
    values ('${VICTIM.pubId}', '${VICTIM.authId}', '${VICTIM.handle}', 'FR', 'acct_test_${VICTIM.pubId.slice(0,8)}', 'active');`);
  psql(`insert into public.publishers (id, auth_user_id, handle, country, stripe_account_id, status)
    values ('${BYSTANDER.pubId}', '${BYSTANDER.authId}', '${BYSTANDER.handle}', 'DE', 'acct_test_${BYSTANDER.pubId.slice(0,8)}', 'active');`);
}

function teardownFixture() {
  try {
    const actors = [MADMIN.authId, TRIAGE.authId, MONEY_AAL1.authId, VICTIM.authId, BYSTANDER.authId];
    psql(`delete from app.admin_action_log where actor in (${actors.map((a) => `'${a}'`).join(',')});`);
    psql(`delete from public.clawback_reviews where id in ('${REV_OK}','${REV_REFUSE}','${REV_REJECT}');`);
    psql(`delete from public.risk_flags where id='${RF}';`);
    psql(`delete from app.money_admins where auth_user_id in ('${MADMIN.authId}','${MONEY_AAL1.authId}');`);
    psql(`delete from app.admins where auth_user_id in ('${MADMIN.authId}','${TRIAGE.authId}','${MONEY_AAL1.authId}');`);
    psql(`delete from public.devices where publisher_id in ('${VICTIM.pubId}','${BYSTANDER.pubId}');`);
    psql(`delete from public.publishers where id in ('${VICTIM.pubId}','${BYSTANDER.pubId}');`);
    psql(`delete from auth.users where id in (${actors.map((a) => `'${a}'`).join(',')});`);
  } catch { /* best-effort */ }
}

if (!SKIP) {
  seedFixture();
  process.on('exit', teardownFixture);
}

function auditCount(actorId, action) {
  return Number(psql(`select count(*) from app.admin_action_log where actor='${actorId}' and action='${action}';`));
}

test('H1: money_admin_check() is true only for the aal2 money-tier member', { skip: SKIP }, async () => {
  assert.equal((await rpc('money_admin_check', {}, MADMIN_JWT)).data, true, 'aal2 money-admin → true');
  assert.equal((await rpc('money_admin_check', {}, TRIAGE_JWT)).data, false, 'aal2 non-money admin → false (tier)');
  assert.equal((await rpc('money_admin_check', {}, MONEY_AAL1_JWT)).data, false, 'aal1 money member → false (aal)');
  assert.equal((await rpc('money_admin_check', {}, NONADMIN_JWT)).data, false, 'non-admin → false');
  const anon = await rpc('money_admin_check', {}, null); // no bearer = anon
  assert.ok(!anon.ok, 'anon EXECUTE on money_admin_check must be revoked');
});

test('H2: approve_clawback REFUSED for a money member on an aal1 session (aal enforcement)', { skip: SKIP }, async () => {
  const res = await rpc('approve_clawback', { p_review_id: REV_REFUSE, p_reason: REASON }, MONEY_AAL1_JWT);
  assert.ok(!res.ok, `aal1 money member must be refused, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.ok(res.status >= 400, `expected 4xx, got ${res.status}`);
  assert.equal(psql(`select status from public.clawback_reviews where id='${REV_REFUSE}';`), 'pending', 'review must be unchanged');
  assert.equal(auditCount(MONEY_AAL1.authId, 'approve_clawback'), 0, 'a refused call writes NO audit row');
});

test('H3: approve_clawback REFUSED for an aal2 admin who is not a money member (tier enforcement)', { skip: SKIP }, async () => {
  const res = await rpc('approve_clawback', { p_review_id: REV_REFUSE, p_reason: REASON }, TRIAGE_JWT);
  assert.ok(!res.ok, `aal2 non-money admin must be refused, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(psql(`select status from public.clawback_reviews where id='${REV_REFUSE}';`), 'pending', 'review must be unchanged');
  assert.equal(auditCount(TRIAGE.authId, 'approve_clawback'), 0, 'a refused call writes NO audit row');
});

test('H4: approve_clawback REFUSED for a non-admin session', { skip: SKIP }, async () => {
  const res = await rpc('approve_clawback', { p_review_id: REV_REFUSE, p_reason: REASON }, NONADMIN_JWT);
  assert.ok(!res.ok, `non-admin must be refused, got ${res.status}: ${JSON.stringify(res.data)}`);
});

test('H5: approve_clawback REFUSED for anon (EXECUTE revoked)', { skip: SKIP }, async () => {
  const res = await rpc('approve_clawback', { p_review_id: REV_REFUSE, p_reason: REASON }, null);
  assert.ok(!res.ok, `anon must be refused, got ${res.status}: ${JSON.stringify(res.data)}`);
});

test('H6: approve_clawback ALLOWED for the aal2 money-admin + writes exactly one audit row', { skip: SKIP }, async () => {
  const res = await rpc('approve_clawback', { p_review_id: REV_OK, p_reason: REASON }, MADMIN_JWT);
  assert.ok(res.ok, `aal2 money-admin must be allowed, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(res.data?.reason, 'no_op_no_impression', 'no-impression review is a clean no-op reversal');

  const row = psql(`select status||'|'||coalesce(reviewed_by::text,'') from public.clawback_reviews where id='${REV_OK}';`);
  const [status, reviewedBy] = row.split('|');
  assert.equal(status, 'approved', 'review advanced to approved');
  assert.equal(reviewedBy, MADMIN.authId, 'reviewed_by attributes to the acting money-admin');

  const audit = psql(`select count(*)||'|'||coalesce(max(actor_aal),'')||'|'||coalesce(max(target_type),'')||'|'||coalesce(max(target_id::text),'')||'|'||coalesce(max(payload->>'reason'),'')
    from app.admin_action_log where actor='${MADMIN.authId}' and action='approve_clawback';`);
  const [count, aal, ttype, tid, reason] = audit.split('|');
  assert.equal(count, '1', 'exactly one audit row for the approve');
  assert.equal(aal, 'aal2', 'actor_aal recorded from the JWT');
  assert.equal(ttype, 'clawback_review', 'target_type recorded');
  assert.equal(tid, REV_OK, 'target_id is the review id');
  assert.equal(reason, REASON, 'reason captured in the payload');
});

test('H7: reject_clawback STILL works for a triage (non-money) admin and writes NO audit row', { skip: SKIP }, async () => {
  const res = await rpc('reject_clawback', { p_review_id: REV_REJECT, p_reason: REASON }, TRIAGE_JWT);
  assert.ok(res.ok, `is_admin() (aal1-class) gate must still admit reject_clawback, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(psql(`select status from public.clawback_reviews where id='${REV_REJECT}';`), 'rejected', 'review rejected');
  // reject_clawback was intentionally NOT re-gated and NOT instrumented → no audit rows for TRIAGE.
  assert.equal(Number(psql(`select count(*) from app.admin_action_log where actor='${TRIAGE.authId}';`)), 0,
    'the non-money path stays on is_admin() and writes nothing to the audit log');
});

test('H8: reject_clawback REFUSED for a non-admin', { skip: SKIP }, async () => {
  const res = await rpc('reject_clawback', { p_review_id: REV_REFUSE, p_reason: REASON }, NONADMIN_JWT);
  assert.ok(!res.ok, `non-admin must be refused by reject_clawback too, got ${res.status}`);
  assert.equal(psql(`select status from public.clawback_reviews where id='${REV_REFUSE}';`), 'pending', 'review unchanged');
});

test('H9: gdpr_delete_publisher REFUSED for a money member on an aal1 session; target untouched', { skip: SKIP }, async () => {
  const res = await rpc('gdpr_delete_publisher', { p_publisher_id: BYSTANDER.pubId }, MONEY_AAL1_JWT);
  assert.ok(!res.ok, `aal1 money member must be refused, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(psql(`select (deleted_at is null) from public.publishers where id='${BYSTANDER.pubId}';`), 't', 'bystander must not be erased');
  assert.equal(auditCount(MONEY_AAL1.authId, 'gdpr_delete_publisher'), 0, 'refused call writes no audit row');
});

test('H10: gdpr_delete_publisher REFUSED for an aal2 non-money admin; target untouched', { skip: SKIP }, async () => {
  const res = await rpc('gdpr_delete_publisher', { p_publisher_id: BYSTANDER.pubId }, TRIAGE_JWT);
  assert.ok(!res.ok, `aal2 non-money admin must be refused, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(psql(`select (deleted_at is null) from public.publishers where id='${BYSTANDER.pubId}';`), 't', 'bystander must not be erased');
});

test('H11: gdpr_delete_publisher REFUSED for anon', { skip: SKIP }, async () => {
  const res = await rpc('gdpr_delete_publisher', { p_publisher_id: BYSTANDER.pubId }, null);
  assert.ok(!res.ok, `anon must be refused, got ${res.status}`);
  assert.equal(psql(`select (deleted_at is null) from public.publishers where id='${BYSTANDER.pubId}';`), 't', 'bystander still intact');
});

test('H12: gdpr_delete_publisher ALLOWED for the aal2 money-admin + writes exactly one audit row', { skip: SKIP }, async () => {
  const res = await rpc('gdpr_delete_publisher', { p_publisher_id: VICTIM.pubId }, MADMIN_JWT);
  assert.ok(res.ok, `aal2 money-admin must be allowed, got ${res.status}: ${JSON.stringify(res.data)}`);
  assert.equal(res.data?.ok, true);
  assert.equal(res.data?.publisher_id, VICTIM.pubId, 'erased the requested publisher');

  const row = psql(`select status||'|'||(deleted_at is not null)||'|'||(handle <> '${VICTIM.handle}') from public.publishers where id='${VICTIM.pubId}';`);
  const [status, deletedSet, handleScrubbed] = row.split('|');
  assert.equal(status, 'suspended', 'victim suspended');
  // `(deleted_at is not null)` / `(handle <> …)` are concatenated with `||`, so Postgres renders
  // the boolean as 'true'/'false' (booltext), NOT the standalone 't'/'f' (boolout).
  assert.equal(deletedSet, 'true', 'deleted_at set');
  assert.equal(handleScrubbed, 'true', 'handle anonymized');

  const audit = psql(`select count(*)||'|'||coalesce(max(actor_aal),'')||'|'||coalesce(max(target_type),'')||'|'||coalesce(max(target_id::text),'')
    from app.admin_action_log where actor='${MADMIN.authId}' and action='gdpr_delete_publisher';`);
  const [count, aal, ttype, tid] = audit.split('|');
  assert.equal(count, '1', 'exactly one audit row for the erase');
  assert.equal(aal, 'aal2', 'actor_aal recorded from the JWT');
  assert.equal(ttype, 'publisher', 'target_type recorded');
  assert.equal(tid, VICTIM.pubId, 'target_id is the erased publisher id');
});

test('H13: app.admin_action_log is append-only — UPDATE and DELETE both RAISE', { skip: SKIP }, async () => {
  // There is at least one row from H6/H12; if those skipped for any reason, seed one via the RPC path.
  const anyRow = psql(`select id from app.admin_action_log where actor='${MADMIN.authId}' limit 1;`);
  assert.ok(anyRow, 'expected an audit row to exist from the allowed actions');

  const updErr = psqlExpectError(`update app.admin_action_log set action='tampered' where id='${anyRow}';`);
  assert.match(updErr, /append-only/i, `UPDATE must be blocked by the immutability trigger, got: ${updErr || 'no error'}`);

  const delErr = psqlExpectError(`delete from app.admin_action_log where id='${anyRow}';`);
  assert.match(delErr, /append-only/i, `DELETE must be blocked by the immutability trigger, got: ${delErr || 'no error'}`);

  // TRUNCATE would wipe the whole trail without firing a row-level trigger — the statement-level
  // BEFORE TRUNCATE guard must block it too (the "immutable even to the owner" claim).
  const truncErr = psqlExpectError(`truncate app.admin_action_log;`);
  assert.match(truncErr, /append-only/i, `TRUNCATE must be blocked by the statement-level guard, got: ${truncErr || 'no error'}`);

  // The row is still there, unmodified (the blocked UPDATE/TRUNCATE never took effect).
  assert.notEqual(psql(`select action from app.admin_action_log where id='${anyRow}';`), 'tampered',
    'the blocked UPDATE must not have mutated the row');
  assert.ok(psql(`select id from app.admin_action_log where id='${anyRow}';`), 'the row survives the blocked TRUNCATE');
});
