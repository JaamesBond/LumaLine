// EXHAUSTIVE integration test for the refresh-token rotation GRACE WINDOW
// (migration 20260704120000_refresh_token_grace_window.sql — device_refresh two-arm + device_revoke).
//
// Goal: pin EVERY scenario of the crash-mid-rotation recovery fix so no future edge case regresses.
// Drives the SECURITY DEFINER RPCs through PostgREST exactly as the auth-device edge fn does.
// SKIPs cleanly when the local stack is down (offline unit suite stays green).
//
// Coverage map:
//   Arm 1 (normal)   : rotates, arms prev + prev_rotated_at, returns FULL identity; fresh device (prev NULL) works.
//   Arm 2 (grace)    : immediately-previous token recovers within T; returns FULL identity (credit binding);
//                      NON-re-arming (prev/timer untouched); repeatable until T (repeated-kill recovery).
//   Chains           : grace-then-normal re-anchors + drops the original; 2nd normal rotation re-arms the timer.
//   Arm precedence   : a row where prev == current resolves as Arm-1 NORMAL (re-arm), never grace.
//   Time bound       : within T ok; past T invalid; exact 29s/31s boundary; a grace use never slides the timer.
//   Only-immediate   : a token TWO rotations back is invalid.
//   Revocation       : revoked device rejects BOTH arms; device_revoke NULLs prev; ownership-scoped; idempotent;
//                      concurrent grace-refresh vs revoke never bypasses logout.
//   NULL-safety      : NULL args invalid; a non-null token never matches a NULL prev; prev w/o timer invalid.
//   Concurrency      : 2-way and N-way racing redemptions all resolve ok, exactly one current survives, no torn write.
//   Data exposure    : anon and a FOREIGN publisher can never read a device's (prev_)refresh_token_hash.
//   Degenerate       : new == current does not corrupt state.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createHash, randomBytes } from 'node:crypto';

const BASE = 'http://127.0.0.1:54321/rest/v1';
const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';
const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// Seeded publishers (supabase/seed.sql). A owns the test devices; B is the foreign publisher.
const A = { auth: '11111111-1111-1111-1111-111111111111', pub: 'a1a1a1a1-0000-0000-0000-000000000001' };
const B = { auth: '22222222-2222-2222-2222-222222222222', pub: 'b1b1b1b1-0000-0000-0000-000000000002' };
const GRACE_S = 30; // must match c_grace in the migration

const H = () => createHash('sha256').update(randomBytes(24)).digest('hex'); // a fresh unique token hash
const created = []; // device ids to clean up

function mintJwt(claims) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', iat: 1700000000, exp: 2000000000, ...claims });
  const sig = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}

async function rpc(name, body, jwt = SERVICE) {
  const res = await fetch(`${BASE}/rpc/${name}`, {
    method: 'POST',
    headers: { apikey: ANON, Authorization: `Bearer ${jwt}`, 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`rpc ${name} -> HTTP ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}
const refresh = (cur, next) => rpc('device_refresh', { p_refresh_token_hash: cur, p_new_refresh_token_hash: next });

async function mkDevice({ current, prev = null, prevRotatedAt = null }) {
  const res = await fetch(`${BASE}/devices`, {
    method: 'POST',
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'content-type': 'application/json', Prefer: 'return=representation' },
    body: JSON.stringify({
      publisher_id: A.pub, refresh_token_hash: current,
      prev_refresh_token_hash: prev, prev_rotated_at: prevRotatedAt,
      label: 'grace-itest', client_version: 't', attested: false,
    }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`insert device -> HTTP ${res.status}: ${text}`);
  const id = JSON.parse(text)[0].id;
  created.push(id);
  return id;
}
async function getDevice(id, jwt = SERVICE) {
  const res = await fetch(`${BASE}/devices?id=eq.${id}&select=refresh_token_hash,prev_refresh_token_hash,prev_rotated_at,revoked_at`, {
    headers: { apikey: jwt === ANON ? ANON : SERVICE, ...(jwt ? { Authorization: `Bearer ${jwt}` } : {}) },
  });
  return { status: res.status, rows: res.ok ? JSON.parse(await res.text()) : [] };
}
async function patchDevice(id, fields) {
  const res = await fetch(`${BASE}/devices?id=eq.${id}`, {
    method: 'PATCH',
    headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}`, 'content-type': 'application/json' },
    body: JSON.stringify(fields),
  });
  if (!res.ok) throw new Error(`patch device -> HTTP ${res.status}: ${await res.text()}`);
}
const dev = async (id) => (await getDevice(id)).rows[0];
// Age prev_rotated_at by `seconds` relative to its SERVER-set value (no client/server clock skew).
async function agePrev(id, seconds) {
  const d = await dev(id);
  const aged = new Date(Date.parse(d.prev_rotated_at) - seconds * 1000).toISOString();
  await patchDevice(id, { prev_rotated_at: aged });
}

async function isReachable() {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 1500);
  try {
    const res = await fetch(`${BASE}/`, { headers: { apikey: ANON }, signal: ctrl.signal });
    return res.status >= 200 && res.status < 500;
  } catch { return false; } finally { clearTimeout(t); }
}

const UP = await isReachable();
if (!UP) console.log(`[device-refresh-grace] PostgREST unreachable at ${BASE} — SKIPPING.`);

test('device_refresh grace window — exhaustive', { skip: UP ? false : `PostgREST unreachable at ${BASE}` }, async (t) => {
  try {
    // ---- Arm 1: NORMAL rotation ------------------------------------------------------------
    await t.test('normal rotation: rotates current, arms prev + timer, returns FULL identity', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      const r = await refresh(R0, R1);
      assert.equal(r.status, 'ok');
      assert.equal(r.publisher_id, A.pub, 'identity: publisher');
      assert.equal(r.device_id, id, 'identity: device');
      assert.equal(r.auth_user_id, A.auth, 'identity: auth_user_id (RLS/credit binding)');
      assert.ok(r.handle, 'identity: handle');
      const d = await dev(id);
      assert.equal(d.refresh_token_hash, R1, 'current rotated to the successor');
      assert.equal(d.prev_refresh_token_hash, R0, 'prev armed to the just-superseded token');
      assert.ok(d.prev_rotated_at, 'timer armed');
    });

    // ---- Arm 2: GRACE recovery -------------------------------------------------------------
    await t.test('grace: the immediately-previous token recovers within T, returns FULL identity; NON-re-arming', async () => {
      const R0 = H(), R1 = H(), R2 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);                       // current=R1, prev=R0
      const armed = (await dev(id)).prev_rotated_at;
      const g = await refresh(R0, R2);             // present the PREV token (crash-mid-rotation retry)
      assert.equal(g.status, 'ok', 'previous token recovers within grace');
      assert.equal(g.publisher_id, A.pub, 'grace arm returns publisher (Rank-4: credit binding)');
      assert.equal(g.device_id, id, 'grace arm returns device');
      assert.equal(g.auth_user_id, A.auth, 'grace arm returns auth_user_id (must credit the RIGHT publisher)');
      assert.ok(g.handle, 'grace arm returns handle');
      const d = await dev(id);
      assert.equal(d.refresh_token_hash, R2, 'current advanced to the recovery successor');
      assert.equal(d.prev_refresh_token_hash, R0, 'prev UNCHANGED by a grace use');
      assert.equal(d.prev_rotated_at, armed, 'timer NOT re-armed by a grace use');
    });

    await t.test('grace is repeatable (repeated-kill recovery) until a normal rotation moves prev', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);                       // prev=R0
      for (let i = 0; i < 3; i++) {
        const g = await refresh(R0, H());          // each retry presents the same prev
        assert.equal(g.status, 'ok', `grace retry ${i} ok (non-re-arming, retryable)`);
        assert.equal((await dev(id)).prev_refresh_token_hash, R0, 'prev stays pinned across retries');
      }
    });

    // ---- Chains ----------------------------------------------------------------------------
    await t.test('grace-then-normal re-anchors the chain and drops the original token', async () => {
      const R0 = H(), R1 = H(), R2 = H(), R3 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);                       // normal: prev=R0, current=R1
      const g = await refresh(R0, R2);             // grace: current=R2, prev still R0
      assert.equal(g.status, 'ok');
      assert.equal((await dev(id)).prev_refresh_token_hash, R0, 'grace left prev on R0');
      const n = await refresh(R2, R3);             // normal resume: prev=R2, current=R3
      assert.equal(n.status, 'ok');
      const d = await dev(id);
      assert.equal(d.refresh_token_hash, R3);
      assert.equal(d.prev_refresh_token_hash, R2, 'prev re-anchored to R2');
      assert.equal((await refresh(R0, H())).status, 'invalid', 'the original R0 grace window is now closed');
    });

    await t.test('a second normal rotation RE-ARMS the timer (prev_rotated_at advances)', async () => {
      const R0 = H(), R1 = H(), R2 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);
      const t1 = (await dev(id)).prev_rotated_at;
      await refresh(R1, R2);                        // second normal rotation
      const d = await dev(id);
      assert.equal(d.prev_refresh_token_hash, R1, 'prev moved to R1');
      assert.ok(Date.parse(d.prev_rotated_at) > Date.parse(t1), 'timer re-armed to a later instant (not frozen)');
    });

    // ---- Arm precedence --------------------------------------------------------------------
    await t.test('when prev == current, Arm-1 NORMAL wins precedence (re-arm), not grace', async () => {
      const R0 = H(), R1 = H();
      const recent = new Date().toISOString();
      const id = await mkDevice({ current: R0, prev: R0, prevRotatedAt: recent });
      const r = await refresh(R0, R1);
      assert.equal(r.status, 'ok');
      const d = await dev(id);
      assert.equal(d.refresh_token_hash, R1, 'rotated (arm-1)');
      assert.equal(d.prev_refresh_token_hash, R0, 'prev set to the superseded current (arm-1 behavior)');
      assert.ok(Date.parse(d.prev_rotated_at) > Date.parse(recent), 'timer re-armed => arm-1 ran, not the non-re-arming grace');
    });

    // ---- Time bound ------------------------------------------------------------------------
    await t.test('grace expires: previous token past T is invalid', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);
      await agePrev(id, GRACE_S + 30);             // ~60s in the past (> T)
      assert.equal((await refresh(R0, H())).status, 'invalid');
    });

    await t.test('within T (well inside) still recovers', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);
      await agePrev(id, 15);                        // 15s old — inside T=30
      assert.equal((await refresh(R0, H())).status, 'ok');
    });

    await t.test('exact boundary: 29s inside => ok, 31s outside => invalid (pins T + the strict `>`)', async () => {
      // sub-second RPC latency keeps 29/31 on their correct sides of the 30s cutoff.
      const a0 = H(), a1 = H();
      const idA = await mkDevice({ current: a0 });
      await refresh(a0, a1);
      await agePrev(idA, 29);
      assert.equal((await refresh(a0, H())).status, 'ok', '29s < 30s grace => recovers');
      const b0 = H(), b1 = H();
      const idB = await mkDevice({ current: b0 });
      await refresh(b0, b1);
      await agePrev(idB, 31);
      assert.equal((await refresh(b0, H())).status, 'invalid', '31s > 30s grace => rejected');
    });

    await t.test('a grace use does NOT slide the timer (window stays anchored to the normal rotation)', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);
      await agePrev(id, 10);                        // 10s old
      const before = (await dev(id)).prev_rotated_at;
      await refresh(R0, H());                        // grace use
      assert.equal((await dev(id)).prev_rotated_at, before, 'grace did not extend the window');
      await agePrev(id, 40);                         // now ~50s old total (past T)
      assert.equal((await refresh(R0, H())).status, 'invalid', 'window still expires on schedule despite the grace use');
    });

    // ---- Only the IMMEDIATELY-previous token -----------------------------------------------
    await t.test('a token TWO rotations back is invalid (only the immediate previous is honored)', async () => {
      const R0 = H(), R1 = H(), R2 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);                       // prev=R0, current=R1
      await refresh(R1, R2);                       // NORMAL: prev=R1, current=R2 (R0 now two-back)
      assert.equal((await refresh(R0, H())).status, 'invalid', 'the two-back token is not honored');
      const d = await dev(id);
      assert.equal(d.prev_refresh_token_hash, R1, 'prev is the immediately-previous (R1)');
      assert.equal(d.refresh_token_hash, R2);
    });

    // ---- Rejections / NULL-safety ----------------------------------------------------------
    await t.test('unknown token is invalid', async () => {
      await mkDevice({ current: H() });
      assert.equal((await refresh(H(), H())).status, 'invalid');
    });

    await t.test('NULL arguments are invalid', async () => {
      const R0 = H();
      await mkDevice({ current: R0 });
      assert.equal((await refresh(null, H())).status, 'invalid', 'null current');
      assert.equal((await refresh(R0, null)).status, 'invalid', 'null successor');
    });

    await t.test('a non-null token never matches a NULL prev', async () => {
      const id = await mkDevice({ current: H() });  // prev_refresh_token_hash = NULL
      assert.equal((await refresh(H(), H())).status, 'invalid');
      assert.equal((await dev(id)).prev_refresh_token_hash, null, 'prev stays NULL');
    });

    await t.test('defensive: prev set but prev_rotated_at NULL is not honored', async () => {
      const R0 = H(), Rp = H();
      await mkDevice({ current: R0, prev: Rp, prevRotatedAt: null });
      assert.equal((await refresh(Rp, H())).status, 'invalid', 'no timer => grace arm rejects');
    });

    // ---- Revocation ------------------------------------------------------------------------
    await t.test('revoked device rejects the CURRENT token', async () => {
      const R0 = H();
      const id = await mkDevice({ current: R0 });
      await patchDevice(id, { revoked_at: new Date().toISOString() });
      assert.equal((await refresh(R0, H())).status, 'invalid');
    });

    await t.test('revoked device rejects the PREVIOUS token (grace arm is revoked-gated)', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);
      await patchDevice(id, { revoked_at: new Date().toISOString() });
      assert.equal((await refresh(R0, H())).status, 'invalid');
    });

    await t.test('device_revoke NULLs prev (no grace bypass of logout)', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);
      const rev = await rpc('device_revoke', { p_device_id: id }, mintJwt({ sub: A.auth }));
      assert.equal(rev.ok, true);
      const d = await dev(id);
      assert.ok(d.revoked_at, 'revoked_at set');
      assert.equal(d.refresh_token_hash, null, 'current cleared');
      assert.equal(d.prev_refresh_token_hash, null, 'prev cleared — grace window closed');
      assert.equal((await refresh(R0, H())).status, 'invalid', 'no post-revoke grace refresh');
    });

    await t.test('device_revoke is idempotent (twice => ok, revoked_at unchanged)', async () => {
      const id = await mkDevice({ current: H() });
      const r1 = await rpc('device_revoke', { p_device_id: id }, mintJwt({ sub: A.auth }));
      const at = (await dev(id)).revoked_at;
      const r2 = await rpc('device_revoke', { p_device_id: id }, mintJwt({ sub: A.auth }));
      assert.equal(r1.ok, true); assert.equal(r2.ok, true, 'second revoke still ok');
      assert.equal((await dev(id)).revoked_at, at, 'coalesce preserved the original revoked_at');
    });

    await t.test("device_revoke stays ownership-scoped (B cannot clear A's prev)", async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);
      const rev = await rpc('device_revoke', { p_device_id: id }, mintJwt({ sub: B.auth }));
      assert.equal(rev.ok, false, "B's revoke does not touch A's device");
      assert.equal((await dev(id)).prev_refresh_token_hash, R0, "A's prev untouched by B");
    });

    await t.test('concurrent grace-refresh vs device_revoke never bypasses logout (either order)', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);                        // prev=R0 armed, within grace
      await Promise.all([
        refresh(R0, H()).catch(() => {}),
        rpc('device_revoke', { p_device_id: id }, mintJwt({ sub: A.auth })).catch(() => {}),
      ]);
      const d = await dev(id);
      assert.ok(d.revoked_at, 'device ends revoked regardless of race winner');
      assert.equal(d.prev_refresh_token_hash, null, 'prev NULLed');
      assert.equal((await refresh(R0, H())).status, 'invalid', 'no residual grace after the race');
    });

    // ---- Concurrency -----------------------------------------------------------------------
    await t.test('2-way race on the current token: both resolve ok (arm1 + arm2), no torn write', async () => {
      const R0 = H(), A1 = H(), B1 = H();
      const id = await mkDevice({ current: R0 });
      const [ra, rb] = await Promise.all([refresh(R0, A1), refresh(R0, B1)]);
      assert.deepEqual([ra.status, rb.status].sort(), ['ok', 'ok'], 'both concurrent refreshes succeed');
      const d = await dev(id);
      assert.ok([A1, B1].includes(d.refresh_token_hash), 'current is one of the successors (row-lock serialized)');
      assert.equal(d.prev_refresh_token_hash, R0, 'prev is the shared origin token');
    });

    await t.test('N-way (5) race on the current token: all ok, exactly one current survives', async () => {
      const R0 = H();
      const nexts = Array.from({ length: 5 }, () => H());
      const id = await mkDevice({ current: R0 });
      const res = await Promise.all(nexts.map((n) => refresh(R0, n)));
      assert.ok(res.every((r) => r.status === 'ok'), 'all 5 concurrent redemptions ok');
      const d = await dev(id);
      assert.ok(nexts.includes(d.refresh_token_hash), 'exactly one of the 5 successors is current');
      assert.equal(d.prev_refresh_token_hash, R0, 'prev bounded to the single origin');
    });

    // ---- Data exposure ---------------------------------------------------------------------
    await t.test('anon and a FOREIGN publisher can never read a device hash column', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      await refresh(R0, R1);                        // arm prev so both hash columns are populated
      const anonRead = await getDevice(id, ANON);   // apikey=ANON, bearer=ANON (role anon)
      assert.ok(anonRead.rows.length === 0, `anon sees no device rows (got ${anonRead.rows.length}, status ${anonRead.status})`);
      const bRead = await fetch(`${BASE}/devices?id=eq.${id}&select=refresh_token_hash,prev_refresh_token_hash`, {
        headers: { apikey: ANON, Authorization: `Bearer ${mintJwt({ sub: B.auth })}` },
      });
      const bRows = bRead.ok ? JSON.parse(await bRead.text()) : [];
      assert.equal(bRows.length, 0, "foreign publisher B sees none of A's device rows (RLS devices_select_own)");
    });

    // ---- Degenerate ------------------------------------------------------------------------
    await t.test('degenerate new == current does not corrupt state', async () => {
      const R0 = H(), R1 = H();
      const id = await mkDevice({ current: R0 });
      const r = await refresh(R0, R0);              // rotate onto the same hash
      assert.equal(r.status, 'ok');
      const d = await dev(id);
      assert.equal(d.refresh_token_hash, R0, 'current still R0');
      assert.equal(d.prev_refresh_token_hash, R0, 'prev = R0 (superseded == successor here)');
      assert.equal((await refresh(R0, R1)).status, 'ok', 'subsequent normal rotation still works');
      assert.equal((await dev(id)).refresh_token_hash, R1);
    });
  } finally {
    if (created.length) {
      await fetch(`${BASE}/devices?id=in.(${created.join(',')})`, {
        method: 'DELETE', headers: { apikey: SERVICE, Authorization: `Bearer ${SERVICE}` },
      }).catch(() => {});
    }
  }
});
