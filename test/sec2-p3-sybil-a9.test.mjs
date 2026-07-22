// test/sec2-p3-sybil-a9.test.mjs — SECURITY-AUDIT PASS-2 (Cluster P3: Sybil throttles, fleet anomaly
// monitor, A9 chargeback → advertiser dispute hold).
//
// Residuals closed:
//   SYBIL HIGH — no global/per-IP signup or device-creation throttle; scan_ivt thresholds are per-entity
//     so low-and-slow Sybil stayed under, and scan_selfdeal_risk whitelisted free-email providers so a
//     pure-Sybil publisher farm with no advertiser link was never flagged.
//   A9 MED — a postpay chargeback only paused line_items, which the advertiser self-serve RPC
//     advertiser_set_line_item_status could flip straight back to active; window_open's serve path checked
//     only a.status='active', with no advertiser-level suspension / dispute gate.
//
// Closure (validated by adversarial trace of 20260722170000 / 180000 / 190000 / 200000 + the wired
//   monitor-logic.mjs fleet_velocity check):
//   - signup_throttle_hit: durable per-trusted-IP + GLOBAL fixed-window counter, FAIL-CLOSED on empty
//     scope; ensure_publisher adds a global new-publisher-per-minute cap on the CREATE path only.
//   - scan_publisher_sybil: flags >= N distinct publishers sharing one salted ad_windows.ip_hash
//     (NO free-email whitelist), HOLD-ONLY (never auto-clawback).
//   - monitor_fleet_velocity + evalFleetVelocity: aggregate fleet counters surface distributed
//     low-and-slow Sybil for human review.
//   - advertiser dispute_hold_at: window_open excludes a held advertiser, both self-serve status RPCs
//     refuse to resume while held, and only an aal2 money-admin can clear it.
//
// Pure decision tables are mirrored below (node: builtins only, no DB) + adversarial-trace guards.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { evalFleetVelocity, FLEET_VELOCITY_BASELINES, CHECK_NAMES }
  from '../supabase/functions/_shared/monitor-logic.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MIG = join(ROOT, 'supabase/migrations');

// ---- 1. signup / device-creation throttle counter (mirrors public.signup_throttle_hit) -----------

// Pure reference of the fixed-window counter: fail-CLOSED on empty/null scope; bump per (scope, minute);
// still-in-budget == count <= greatest(max, 1). One instance == one (scope, window_start) bucket.
function makeSignupThrottle() {
  const buckets = new Map(); // key `${scope}|${minute}` -> count
  return function hit(scope, max, minute = 0) {
    if (scope == null || scope.length === 0) return false; // fail-closed: unscoped creation denied
    const key = `${scope}|${minute}`;
    const n = (buckets.get(key) ?? 0) + 1;
    buckets.set(key, n);
    return n <= Math.max(max, 1);
  };
}

test('P3 SYBIL: device-code throttle admits up to max hits per minute then denies (per-IP scope)', () => {
  const hit = makeSignupThrottle();
  assert.equal(hit('devcode_ip:HASH', 3), true);   // 1
  assert.equal(hit('devcode_ip:HASH', 3), true);   // 2
  assert.equal(hit('devcode_ip:HASH', 3), true);   // 3
  assert.equal(hit('devcode_ip:HASH', 3), false);  // 4 -> over budget
});

test('P3 SYBIL: throttle FAILS CLOSED on a null/empty scope (a creation event must be scoped)', () => {
  const hit = makeSignupThrottle();
  assert.equal(hit(null, 100), false);
  assert.equal(hit('', 100), false);
});

test('P3 SYBIL: throttle scopes are independent (per-IP vs global vs a different IP)', () => {
  const hit = makeSignupThrottle();
  assert.equal(hit('devcode_ip:A', 1), true);
  assert.equal(hit('devcode_ip:A', 1), false);     // A exhausted
  assert.equal(hit('devcode_ip:B', 1), true);      // B independent
  assert.equal(hit('devcode_global', 1), true);    // global independent
});

test('P3 SYBIL: a new minute resets the fixed window', () => {
  const hit = makeSignupThrottle();
  assert.equal(hit('devcode_ip:A', 1, 0), true);
  assert.equal(hit('devcode_ip:A', 1, 0), false);
  assert.equal(hit('devcode_ip:A', 1, 1), true);   // next minute bucket
});

test('P3 SYBIL: max is floored at 1 (greatest(p_max,1)) — a 0/negative cap still admits one', () => {
  const hit = makeSignupThrottle();
  assert.equal(hit('s', 0), true);
  assert.equal(hit('s', 0), false);
});

// ---- 2. fleet-velocity anomaly evaluator (REAL export from monitor-logic.mjs) --------------------

test('P3 FLEET: fleet_velocity is a registered monitor check name', () => {
  assert.ok(CHECK_NAMES.includes('fleet_velocity'));
});

test('P3 FLEET: within baseline => pass, no alerts', () => {
  const r = evalFleetVelocity({ provisional_impressions_1h: 10, new_publishers_1h: 1, new_devices_1h: 1 });
  assert.equal(r.name, 'fleet_velocity');
  assert.equal(r.status, 'pass');
  assert.deepEqual(r.alerts, []);
});

test('P3 FLEET: a metric strictly over baseline => fail, one HIGH alert, dedup per metric', () => {
  const counters = {
    provisional_impressions_1h: FLEET_VELOCITY_BASELINES.provisional_impressions_1h + 1,
    new_publishers_1h: 0, new_devices_1h: 0,
  };
  const r = evalFleetVelocity(counters);
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts.length, 1);
  assert.equal(r.alerts[0].severity, 'high');
  assert.equal(r.alerts[0].dedup_key, 'fleet:provisional_impressions_1h');
  assert.equal(r.alerts[0].payload.value, counters.provisional_impressions_1h);
});

test('P3 FLEET: multiple breaches => one alert each with distinct dedup keys', () => {
  const r = evalFleetVelocity({ provisional_impressions_1h: 1e9, new_publishers_1h: 1e6, new_devices_1h: 1e6 });
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts.length, 3);
  assert.deepEqual(new Set(r.alerts.map((a) => a.dedup_key)),
    new Set(['fleet:provisional_impressions_1h', 'fleet:new_publishers_1h', 'fleet:new_devices_1h']));
});

test('P3 FLEET: boundary — value == baseline does NOT fire (strictly greater)', () => {
  const r = evalFleetVelocity({
    provisional_impressions_1h: FLEET_VELOCITY_BASELINES.provisional_impressions_1h,
    new_publishers_1h: FLEET_VELOCITY_BASELINES.new_publishers_1h,
    new_devices_1h: FLEET_VELOCITY_BASELINES.new_devices_1h,
  });
  assert.equal(r.status, 'pass');
});

test('P3 FLEET: fail-loud on unreadable counters or a non-numeric metric', () => {
  assert.equal(evalFleetVelocity(null).status, 'error');
  assert.equal(evalFleetVelocity('nope').status, 'error');
  assert.equal(evalFleetVelocity(
    { provisional_impressions_1h: 'abc', new_publishers_1h: 0, new_devices_1h: 0 }).status, 'error');
});

test('P3 FLEET: PostgREST bigint-as-string counters coerce numerically', () => {
  const over = String(FLEET_VELOCITY_BASELINES.new_publishers_1h + 5);
  const r = evalFleetVelocity({ provisional_impressions_1h: 0, new_publishers_1h: over, new_devices_1h: 0 });
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].dedup_key, 'fleet:new_publishers_1h');
});

// ---- 3. A9 advertiser dispute-hold discriminator -------------------------------------------------

// Pure reference of the A9 gates: a held advertiser (dispute_hold_at != null) is excluded from the
// window_open real-publisher serve path, cannot be RESUMED via the self-serve status RPCs, and only an
// aal2 money-admin can clear the hold.
function advertiserServable({ status, disputeHoldAt }) {
  return status === 'active' && disputeHoldAt == null;   // window_open real-path predicate
}
function selfServeResumeAllowed({ target, disputeHoldAt }) {
  if (target !== 'active') return true;                  // pausing is always allowed
  return disputeHoldAt == null;                          // resume blocked while held
}
function adminClearAllowed({ isMoneyAdmin }) {
  return isMoneyAdmin === true;                          // aal2 + app.money_admins only
}

test('P3 A9 EXPLOIT CLOSED: a dispute-held advertiser is NOT servable even while status=active', () => {
  assert.equal(advertiserServable({ status: 'active', disputeHoldAt: null }), true);
  assert.equal(advertiserServable({ status: 'active', disputeHoldAt: '2026-07-22T00:00:00Z' }), false);
});

test('P3 A9: self-serve cannot RESUME a held advertiser (the paused->active flip is blocked)', () => {
  // This is the exact bypass: pausing is fine, resuming while held is refused.
  assert.equal(selfServeResumeAllowed({ target: 'paused', disputeHoldAt: '2026-07-22T00:00:00Z' }), true);
  assert.equal(selfServeResumeAllowed({ target: 'active', disputeHoldAt: '2026-07-22T00:00:00Z' }), false);
  assert.equal(selfServeResumeAllowed({ target: 'active', disputeHoldAt: null }), true);
});

test('P3 A9: only an aal2 money-admin can clear the hold (self-serve/aal1 cannot)', () => {
  assert.equal(adminClearAllowed({ isMoneyAdmin: true }), true);
  assert.equal(adminClearAllowed({ isMoneyAdmin: false }), false);
});

test('P3 A9: end-to-end discriminator — held blocks serve+resume until an admin clears, then both work', () => {
  let hold = '2026-07-22T00:00:00Z';
  assert.equal(advertiserServable({ status: 'active', disputeHoldAt: hold }), false);
  assert.equal(selfServeResumeAllowed({ target: 'active', disputeHoldAt: hold }), false);
  assert.equal(adminClearAllowed({ isMoneyAdmin: false }), false);   // aal1 admin can't
  assert.equal(adminClearAllowed({ isMoneyAdmin: true }), true);     // aal2 money-admin clears
  hold = null;                                                        // cleared
  assert.equal(advertiserServable({ status: 'active', disputeHoldAt: hold }), true);
  assert.equal(selfServeResumeAllowed({ target: 'active', disputeHoldAt: hold }), true);
});

// ---- 4. adversarial-trace guards over the P3 migrations ------------------------------------------

test('P3 TRACE: signup throttle migration is fail-closed + service-role-only + anon-asserted', () => {
  const sql = readFileSync(join(MIG, '20260722170000_sybil_signup_device_throttle.sql'), 'utf8');
  assert.match(sql, /if p_scope is null or length\(p_scope\) = 0 then\s*\n\s*return false/i, 'fail-closed on empty scope');
  assert.match(sql, /count <= greatest\(p_max, 1\)/i);
  assert.match(sql, /revoke execute on function public\.signup_throttle_hit\(text, integer\) from public, anon, authenticated/i);
  assert.match(sql, /grant\s+execute on function public\.signup_throttle_hit\(text, integer\) to service_role/i);
  // ensure_publisher global new-publisher cap on the CREATE path.
  assert.match(sql, /MAX_NEW_PUB_PER_MIN/);
  assert.match(sql, /v_recent >= MAX_NEW_PUB_PER_MIN/i);
  assert.match(sql, /has_function_privilege\('anon'/i);
});

test('P3 TRACE: publisher-Sybil fleet scan is hold-only (never auto-clawback) + no free-email whitelist', () => {
  const sql = readFileSync(join(MIG, '20260722180000_publisher_sybil_fleet_scan.sql'), 'utf8');
  assert.match(sql, /scan_publisher_sybil/);
  assert.match(sql, /count\(distinct publisher_id\) >= p_min_pub/i, 'clusters distinct publishers on one ip_hash');
  assert.match(sql, /'sybil:shared_ip'/, 'records a payout hold reason');
  assert.match(sql, /publisher_payout_holds/i);
  // HOLD-ONLY: no ledger reversal / clawback insert in this scan.
  assert.doesNotMatch(sql, /insert into public\.ledger_entries/i, 'fleet scan must NOT auto-book a clawback');
  assert.match(sql, /revoke all on function app\.scan_publisher_sybil\([^)]*\) from public, anon, authenticated/i);
});

test('P3 TRACE: fleet-velocity monitor RPC is read-only (STABLE) + service-role-only', () => {
  const sql = readFileSync(join(MIG, '20260722190000_fleet_velocity_monitor.sql'), 'utf8');
  assert.match(sql, /create or replace function public\.monitor_fleet_velocity/i);
  assert.match(sql, /\bstable\b/i, 'monitor RPC must be STABLE (read-only money invariant)');
  assert.doesNotMatch(sql, /\binsert into\b|\bupdate public\.|\bdelete from\b/i, 'monitor RPC must not write');
  assert.match(sql, /revoke all on function public\.monitor_fleet_velocity\(\) from public, anon, authenticated/i);
});

test('P3 TRACE: A9 migration gates window_open serve path + blocks self-serve resume + money-admin clear', () => {
  const sql = readFileSync(join(MIG, '20260722200000_a9_advertiser_dispute_hold.sql'), 'utf8');
  // dispute_hold_at column + window_open serve-gate predicate.
  assert.match(sql, /add column if not exists dispute_hold_at timestamptz/i);
  assert.match(sql, /a\.dispute_hold_at is null/i, 'window_open real-path excludes a held advertiser');
  // book_postpay_chargeback sets the hold.
  assert.match(sql, /update public\.advertisers set dispute_hold_at = now\(\)/i);
  // Both self-serve status RPCs refuse resume while held.
  const resumeBlocks = sql.match(/dispute_hold_at IS NOT NULL/gi) ?? [];
  assert.ok(resumeBlocks.length >= 2, 'both line_item + campaign status RPCs must block resume while held');
  // admin clear requires money-admin (aal2); self-serve cannot.
  assert.match(sql, /admin_clear_advertiser_dispute_hold/);
  assert.match(sql, /if not \(select app\.is_money_admin\(\)\) then/i);
  // Money/PII migration tail: anon holds no EXECUTE on the recreated money RPCs.
  assert.match(sql, /has_function_privilege\('anon'/i);
  assert.match(sql, /public\.window_open\(text, text, text\)/);
});
