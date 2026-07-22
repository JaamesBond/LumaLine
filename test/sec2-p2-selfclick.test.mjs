// test/sec2-p2-selfclick.test.mjs — SECURITY-AUDIT PASS-2 (Cluster P2: publisher self-click CPC farming).
//
// Residual (SELF-CLICK HIGH): lumaline-feed embeds the raw click token inside the SIGNED adData, so a
// serving publisher extracts it and self-clicks — either via the public /click redirect or DIRECTLY via
// /rest/v1/rpc/click_resolve (which was granted to `authenticated`). click_resolve booked a provisional
// CPC for any window in state open|credited within the 600s TTL, with NO binding between who served the
// ad and who clicked it. scan_ivt only ever scanned impressions, never clicks.
//
// Closure (validated by adversarial trace of migrations 20260722150000 + 20260722160000):
//   1. click_resolve gains p_clicker_ip_hash; a click whose salted clicker-IP hash == the serving
//      window's ad_windows.ip_hash is the SAME machine (honest single-user terminal) => recorded VOID,
//      never billed. (same-IP self-click gate)
//   2. EXECUTE on click_resolve is revoked from anon + authenticated, granted to service_role ONLY —
//      the direct /rest/v1/rpc/click_resolve self-click path is gone; only the `click` edge fn (which
//      always derives the trusted clicker IP) can call it.
//   3. scan_click_ivt mirrors scan_ivt for the click side (per serving-device / publisher / serving-IP
//      velocity), flagging high-volume cross-IP self-clicks into the existing clear_events withhold path.
//
// This file exercises the pure decision tables the SQL enforces (mirrored below, node: builtins only,
// no DB) AND asserts the migrations actually contain the gate + the service-role-only grant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MIG = join(ROOT, 'supabase/migrations');

const CLICK_TTL_S = 600;

// Pure reference of public.click_resolve's billability gate (20260722150000 lines 54-70). SELF-CLICK
// INVARIANT: clicker salted-IP hash == serving-window salted-IP hash => same machine => VOID, never CPC.
function resolveClickBillability({
  windowState, startedAtEpochS, nowEpochS, ttlS = CLICK_TTL_S,
  clickerIpHash = null, windowIpHash = null,
}) {
  const selfClick = clickerIpHash != null && windowIpHash != null && clickerIpHash === windowIpHash;
  const creditable = windowState === 'open' || windowState === 'credited';
  const withinTtl = (nowEpochS - startedAtEpochS) <= ttlS;
  const billable = !selfClick && creditable && withinTtl;
  return { billable, state: billable ? 'provisional' : 'void', selfClick };
}

// Pure reference of public.scan_click_ivt's reason CASE (20260722160000 lines 63-67): first breach wins.
function clickIvtReason({
  devCnt, pubCnt, srvIpCnt = 0,
  devMax = 8, pubMax = 20, srvIpMax = 12, srvIp = null,
}) {
  if (devCnt > devMax) return 'ivt:click:dev';
  if (pubCnt > pubMax) return 'ivt:click:pub';
  if (srvIp != null && srvIpCnt > srvIpMax) return 'ivt:click:srvip';
  return null;
}

// ---- 1. same-IP self-click void (the core P2 closure) -------------------------------------------

test('P2 EXPLOIT CLOSED: a same-IP self-click on an open window is VOID, never billed', () => {
  const r = resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 1,
    clickerIpHash: 'AAAA', windowIpHash: 'AAAA',   // serving machine == clicking machine
  });
  assert.equal(r.selfClick, true);
  assert.equal(r.billable, false);
  assert.equal(r.state, 'void');
});

test('P2: same-IP self-click is void even for a credited window within TTL', () => {
  const r = resolveClickBillability({
    windowState: 'credited', startedAtEpochS: 100, nowEpochS: 200,
    clickerIpHash: 'HASH', windowIpHash: 'HASH',
  });
  assert.equal(r.billable, false);
  assert.equal(r.state, 'void');
});

test('P2: a genuine cross-IP click on a creditable window within TTL stays billable', () => {
  const r = resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 1,
    clickerIpHash: 'BBBB', windowIpHash: 'AAAA',
  });
  assert.equal(r.selfClick, false);
  assert.equal(r.billable, true);
  assert.equal(r.state, 'provisional');
});

test('P2: gate is INERT when either hash is null (no salt) — never a FALSE self-click void', () => {
  assert.equal(resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 1 }).billable, true);   // both null
  assert.equal(resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 1, clickerIpHash: 'X' }).billable, true); // window null
  assert.equal(resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 1, windowIpHash: 'X' }).billable, true);  // clicker null
});

test('P2: expired or non-creditable windows void regardless of IP', () => {
  assert.equal(resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 601, clickerIpHash: 'B', windowIpHash: 'A' }).billable, false);
  assert.equal(resolveClickBillability({
    windowState: 'abandoned', startedAtEpochS: 0, nowEpochS: 1, clickerIpHash: 'B', windowIpHash: 'A' }).billable, false);
  assert.equal(resolveClickBillability({
    windowState: 'void', startedAtEpochS: 0, nowEpochS: 1, clickerIpHash: 'B', windowIpHash: 'A' }).billable, false);
});

test('P2: TTL boundary — exactly 600s is still billable, 600s+epsilon is void', () => {
  assert.equal(resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 600, clickerIpHash: 'B', windowIpHash: 'A' }).billable, true);
  assert.equal(resolveClickBillability({
    windowState: 'open', startedAtEpochS: 0, nowEpochS: 601, clickerIpHash: 'B', windowIpHash: 'A' }).billable, false);
});

// ---- 2. click-IVT velocity thresholds (cross-IP low-and-slow bound) ------------------------------

test('P2: click-IVT flags per serving-device / publisher / serving-IP velocity; first breach wins', () => {
  assert.equal(clickIvtReason({ devCnt: 9, pubCnt: 1 }), 'ivt:click:dev');            // 9 > 8
  assert.equal(clickIvtReason({ devCnt: 8, pubCnt: 21 }), 'ivt:click:pub');           // dev at limit, pub 21 > 20
  assert.equal(clickIvtReason({ devCnt: 1, pubCnt: 1, srvIp: 'X', srvIpCnt: 13 }), 'ivt:click:srvip'); // 13 > 12
  assert.equal(clickIvtReason({ devCnt: 8, pubCnt: 20, srvIp: 'X', srvIpCnt: 12 }), null); // all at limit => none
});

test('P2: click-IVT srv-IP dimension is inert when the serving IP hash is null (no salt)', () => {
  assert.equal(clickIvtReason({ devCnt: 1, pubCnt: 1, srvIp: null, srvIpCnt: 9999 }), null);
});

test('P2: device breach takes precedence over publisher + srv-IP breaches (CASE order)', () => {
  assert.equal(clickIvtReason({ devCnt: 100, pubCnt: 100, srvIp: 'X', srvIpCnt: 100 }), 'ivt:click:dev');
});

// ---- 3. adversarial-trace guards over the two migrations -----------------------------------------

test('P2 TRACE: click_resolve migration enforces the same-IP self-click void gate', () => {
  const sql = readFileSync(join(MIG, '20260722150000_click_resolve_selfclick_ip_gate.sql'), 'utf8');
  assert.match(sql, /p_clicker_ip_hash/, 'click_resolve must accept the clicker IP hash');
  // v_selfclick := clicker hash present AND window hash present AND equal.
  assert.match(sql, /v_selfclick[\s\S]*p_clicker_ip_hash\s+is\s+not\s+null[\s\S]*w\.ip_hash\s+is\s+not\s+null[\s\S]*p_clicker_ip_hash\s*=\s*w\.ip_hash/i);
  // billable requires NOT self-click.
  assert.match(sql, /v_billable\s*:=\s*\(not v_selfclick\)/i);
});

test('P2 TRACE: click_resolve EXECUTE revoked from anon+authenticated, granted to service_role ONLY', () => {
  const sql = readFileSync(join(MIG, '20260722150000_click_resolve_selfclick_ip_gate.sql'), 'utf8');
  assert.match(sql, /revoke all on function public\.click_resolve\(text, text\) from public, anon, authenticated/i);
  assert.match(sql, /grant\s+execute on function public\.click_resolve\(text, text\) to service_role/i);
  // Migration-tail assertion fails the migration if anon OR authenticated retains EXECUTE.
  assert.match(sql, /has_function_privilege\('anon',\s*'public\.click_resolve\(text, text\)'/i);
  assert.match(sql, /has_function_privilege\('authenticated',\s*'public\.click_resolve\(text, text\)'/i);
});

test('P2 TRACE: scan_click_ivt exists, is service_role-only, and mirrors the three velocity reasons', () => {
  const sql = readFileSync(join(MIG, '20260722160000_scan_click_ivt.sql'), 'utf8');
  assert.match(sql, /create or replace function public\.scan_click_ivt/i);
  assert.match(sql, /'ivt:click:dev'/);
  assert.match(sql, /'ivt:click:pub'/);
  assert.match(sql, /'ivt:click:srvip'/);
  assert.match(sql, /revoke execute on function public\.scan_click_ivt\([^)]*\) from public, anon, authenticated/i);
  assert.match(sql, /grant\s+execute on function public\.scan_click_ivt\([^)]*\) to service_role/i);
  assert.match(sql, /has_function_privilege\('anon',\s*'public\.scan_click_ivt/i);
});

test('P2 TRACE: the click edge fn derives the clicker IP hash and passes it to click_resolve', () => {
  const click = readFileSync(join(ROOT, 'supabase/functions/click/index.ts'), 'utf8');
  assert.match(click, /saltedIpHash/, 'click fn must compute the clicker salted IP hash');
  assert.match(click, /p_clicker_ip_hash/, 'click fn must pass the clicker IP hash to click_resolve');
});
