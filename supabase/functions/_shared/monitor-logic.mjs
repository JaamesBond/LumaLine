// Pure decision logic for the T6 money-path monitor (edge fn: ../monitor/index.ts).
//
// Deliberately ZERO runtime deps and NO Deno/Stripe globals so this can be imported by
// both the Deno edge function (../_shared/monitor-logic.mjs) and `node --test`
// (test/monitor-logic.test.mjs) — same precedent as payout-logic.mjs / webhook-secrets.mjs.
// (timingSafeEqualStrings uses globalThis.crypto.subtle, present in both Node >= 18 and Deno.)
//
// Every check evaluator is a PURE function over already-fetched rows: the edge function
// does the I/O (service-role PostgREST + Stripe list calls), these functions decide.
// A check result has the uniform shape:
//   { name, status: 'pass'|'fail'|'error', detail, alerts: [{check_name, severity, dedup_key, payload}] }
//
// DRILL INVARIANT: nothing here special-cases synthetic/injected data. A ledger group
// marked T6-DRILL in its memo/metadata is detected exactly like a real imbalance.
//
// FAIL-LOUD INVARIANT: unparseable/unexpected inputs are treated as failures, never
// silently ignored — monitoring must never report green because it could not read.

export const CHECK_NAMES = [
  'ledger_zero_sum',
  'payout_stuck',
  'payout_failed',
  'charge_failed',
  'billing_stalled',
  'billing_recon_drift',
  'payout_recon_drift',
  'reversed_charge_unrefunded',
];

// Payouts: terminal = paid/failed/canceled (payout_status_kind enum). A payout sitting
// in any other state ('pending', 'in_transit') for longer than this is stuck.
export const NON_TERMINAL_PAYOUT_STATUSES = ['pending', 'in_transit'];
export const PAYOUT_STUCK_MAX_AGE_MS = 6 * 60 * 60 * 1000; // 6h

// Recon checks scope to a trailing window ending now (cheap, bounded).
export const RECON_WINDOW_DAYS = 35;

// Visibility window for failed payouts / failed charges.
export const FAILURE_LOOKBACK_MS = 24 * 60 * 60 * 1000; // 24h

// reversed_charge_unrefunded grace (Phase-2 backstop for the reversal↔refund coupling):
// an approved clawback whose advertiser refund is chained in the same UI flow should be
// queued within minutes. Past this grace, an approved review that still has a succeeded,
// un-refunded charge is a books-vs-cash divergence heading for permanent billing recon
// drift — so it fires. The hourly monitor cron means a normally-chained refund (which
// flips refund_queued=true) never lingers long enough to trip this.
export const REVERSED_CHARGE_UNREFUNDED_GRACE_MS = 60 * 60 * 1000; // 1h

/**
 * Coerce a micros value (PostgREST may serialize bigint sums as number or string).
 * Non-numeric input returns NaN so callers can fail loud instead of treating it as 0.
 * @param {unknown} v
 * @returns {number}
 */
export function toMicros(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string' && v.trim() !== '') return Number(v);
  if (v === null || v === undefined) return NaN;
  return NaN;
}

function pass(name, detail) {
  return { name, status: 'pass', detail, alerts: [] };
}
function fail(name, detail, alerts) {
  return { name, status: 'fail', detail, alerts };
}

/**
 * A check that could not be evaluated (Stripe unreachable, DB query failed, …).
 * Reports status 'error' and fires a HIGH alert — monitoring fails loud, not green.
 * Note the message may contain infra error text but never secret values.
 * @param {string} name
 * @param {string} message
 */
export function errorCheck(name, message) {
  const msg = String(message ?? 'unknown error').slice(0, 500);
  return {
    name,
    status: 'error',
    detail: msg,
    alerts: [{ check_name: name, severity: 'high', dedup_key: 'check_error', payload: { error: msg } }],
  };
}

/**
 * CHECK a. ledger_zero_sum (CRITICAL) — any entry_group_id whose legs do not sum to 0,
 * or a non-zero global sum. Input comes from public.monitor_ledger_unbalanced():
 *   { groups: [{entry_group_id, sum_micros}], global_sum_micros }
 * where groups already contains ONLY the unbalanced ones (SQL HAVING sum<>0).
 * ANY non-zero (including fractional or unparseable) fires — no tolerance.
 * @param {{groups?: Array<{entry_group_id?: string, sum_micros?: unknown}>, global_sum_micros?: unknown}} input
 */
export function evalLedgerZeroSum(input) {
  const name = 'ledger_zero_sum';
  const groups = Array.isArray(input?.groups) ? input.groups : [];
  const alerts = [];
  for (const g of groups) {
    const sum = toMicros(g?.sum_micros);
    if (sum === 0) continue; // defensive: SQL should only send non-zero groups
    alerts.push({
      check_name: name,
      severity: 'critical',
      dedup_key: `grp:${g?.entry_group_id ?? 'unknown'}`,
      payload: { entry_group_id: g?.entry_group_id ?? null, sum_micros: g?.sum_micros ?? null },
    });
  }
  const globalSum = toMicros(input?.global_sum_micros);
  if (!(globalSum === 0)) { // NaN (unreadable) also fires — fail loud
    alerts.push({
      check_name: name,
      severity: 'critical',
      dedup_key: 'global',
      payload: { global_sum_micros: input?.global_sum_micros ?? null },
    });
  }
  if (alerts.length === 0) return pass(name, 'all entry groups balance; global sum = 0');
  return fail(name, `${alerts.length} imbalance(s): ${groups.length} group(s), global_sum=${String(input?.global_sum_micros)}`, alerts);
}

/**
 * CHECK b. payout_stuck (HIGH) — payouts in a NON-TERMINAL status ('pending','in_transit')
 * strictly older than PAYOUT_STUCK_MAX_AGE_MS. Terminal (paid/failed/canceled) never fires.
 * Boundary: age === threshold does NOT fire; age > threshold does. Dedup per payout id.
 * @param {Array<{id?: string, status?: string, created_at?: string}>} payouts
 * @param {number} nowMs
 * @param {number} [thresholdMs]
 */
export function evalPayoutStuck(payouts, nowMs, thresholdMs = PAYOUT_STUCK_MAX_AGE_MS) {
  const name = 'payout_stuck';
  const alerts = [];
  for (const p of Array.isArray(payouts) ? payouts : []) {
    if (!NON_TERMINAL_PAYOUT_STATUSES.includes(String(p?.status))) continue;
    const createdMs = Date.parse(String(p?.created_at ?? ''));
    // Unparseable created_at -> treat as stuck (fail loud, never silently green).
    const ageMs = Number.isFinite(createdMs) ? nowMs - createdMs : Infinity;
    if (ageMs > thresholdMs) {
      alerts.push({
        check_name: name,
        severity: 'high',
        dedup_key: `payout:${p?.id ?? 'unknown'}`,
        payload: {
          payout_id: p?.id ?? null,
          status: p?.status ?? null,
          created_at: p?.created_at ?? null,
          age_ms: Number.isFinite(ageMs) ? ageMs : null,
        },
      });
    }
  }
  if (alerts.length === 0) return pass(name, 'no non-terminal payout older than threshold');
  return fail(name, `${alerts.length} payout(s) stuck non-terminal > ${thresholdMs}ms`, alerts);
}

/**
 * CHECK c. payout_failed (HIGH) — payouts with status='failed' (query pre-scopes to the
 * last 24h by created_at; the payouts schema has no failed_at timestamp). Pure visibility:
 * one alert per payout id; the alert auto-resolves once the row ages out of the window.
 * @param {Array<{id?: string, failure_reason?: string, created_at?: string}>} payouts
 */
export function evalPayoutFailed(payouts) {
  const name = 'payout_failed';
  const alerts = (Array.isArray(payouts) ? payouts : []).map((p) => ({
    check_name: name,
    severity: 'high',
    dedup_key: `payout:${p?.id ?? 'unknown'}`,
    payload: {
      payout_id: p?.id ?? null,
      failure_reason: p?.failure_reason ?? null,
      created_at: p?.created_at ?? null,
    },
  }));
  if (alerts.length === 0) return pass(name, 'no failed payouts in window');
  return fail(name, `${alerts.length} failed payout(s) in window`, alerts);
}

/**
 * CHECK d. charge_failed (HIGH) — advertiser_charges with status='failed' in the last 24h,
 * plus line_items paused by billing. "Paused by billing" semantics (billing/index.ts): on a
 * card decline the billing fn PATCHes ALL of that advertiser's active/draft line_items to
 * status='paused' — so the caller passes paused line_items scoped to advertisers that have
 * a failed charge in the window. Dedup: per charge id, and per paused line_item id.
 * @param {{failedCharges?: Array<{id?: string, advertiser_id?: string, failure_reason?: string, amount_cents?: number, created_at?: string}>,
 *          pausedLineItems?: Array<{id?: string, campaign_id?: string, advertiser_id?: string}>}} input
 */
export function evalChargeFailed(input) {
  const name = 'charge_failed';
  const charges = Array.isArray(input?.failedCharges) ? input.failedCharges : [];
  const paused = Array.isArray(input?.pausedLineItems) ? input.pausedLineItems : [];
  const alerts = [];
  for (const c of charges) {
    alerts.push({
      check_name: name,
      severity: 'high',
      dedup_key: `charge:${c?.id ?? 'unknown'}`,
      payload: {
        charge_id: c?.id ?? null,
        advertiser_id: c?.advertiser_id ?? null,
        failure_reason: c?.failure_reason ?? null,
        amount_cents: c?.amount_cents ?? null,
        created_at: c?.created_at ?? null,
      },
    });
  }
  for (const li of paused) {
    alerts.push({
      check_name: name,
      severity: 'high',
      dedup_key: `paused_li:${li?.id ?? 'unknown'}`,
      payload: {
        line_item_id: li?.id ?? null,
        campaign_id: li?.campaign_id ?? null,
        advertiser_id: li?.advertiser_id ?? null,
        reason: 'paused_after_charge_failure',
      },
    });
  }
  if (alerts.length === 0) return pass(name, 'no failed charges in window; no billing-paused line items');
  return fail(name, `${charges.length} failed charge(s), ${paused.length} billing-paused line item(s)`, alerts);
}

/**
 * Stripe-side total for billing recon — mirrors billing/index.ts /reconcile EXACTLY:
 * count ONLY PaymentIntents with metadata.source==='lumaline' AND status==='succeeded'
 * (a declined PI has amount set but must not inflate the total), pi.amount is cents,
 * 1 cent = 10,000 micros.
 * @param {Array<{amount?: number, status?: string, metadata?: {source?: string}}>} paymentIntents
 * @returns {{ totalMicros: number, count: number }}
 */
export function sumLumalinePaymentIntents(paymentIntents) {
  let totalMicros = 0;
  let count = 0;
  for (const pi of Array.isArray(paymentIntents) ? paymentIntents : []) {
    if (pi?.metadata?.source === 'lumaline' && pi?.status === 'succeeded') {
      totalMicros += (Number(pi.amount) || 0) * 10000;
      count++;
    }
  }
  return { totalMicros, count };
}

/**
 * CHECKS e/f. Recon drift (CRITICAL) — DB-side micros total vs Stripe-side micros total.
 * Tolerance mirrors the /reconcile endpoints exactly: ok ⇔ discrepancy === 0 micros.
 * (Known structural drift — e.g. cleared sub-Stripe-minimum entries — fires by design;
 * that is what /reconcile itself reports as not-ok.) Unreadable totals fire too.
 *
 * Dedup key is BUCKETED by sign + order of magnitude ('drift:+5' = positive drift in
 * [1e5, 1e6) micros), NOT a constant: with a constant key, a small structural drift
 * held one alert open and the partial-unique dedup then swallowed any LARGER new drift
 * for the rest of the window — a €500 discrepancy hiding behind a €0.30 one, invisible
 * to ops. A magnitude jump now lands in a new bucket → new alert + email; the old
 * bucket's alert auto-resolves (its dedup key leaves the failing set). Within-bucket
 * growth (< 10×) does not re-fire — accepted noise floor.
 * @param {string} name 'billing_recon_drift' | 'payout_recon_drift'
 * @param {unknown} dbTotalMicros
 * @param {unknown} stripeTotalMicros
 * @param {Record<string, unknown>} [extra] merged into the payload (period, counts)
 */
export function evalReconDrift(name, dbTotalMicros, stripeTotalMicros, extra = {}) {
  const db = toMicros(dbTotalMicros);
  const stripe = toMicros(stripeTotalMicros);
  if (!Number.isFinite(db) || !Number.isFinite(stripe)) {
    return errorCheck(name, `unreadable recon totals: db=${String(dbTotalMicros)} stripe=${String(stripeTotalMicros)}`);
  }
  const discrepancy = db - stripe;
  if (discrepancy === 0) return pass(name, `db == stripe == ${db} micros`);
  const sign = discrepancy > 0 ? '+' : '-';
  const magnitude = Math.floor(Math.log10(Math.abs(discrepancy)));
  return fail(name, `drift ${discrepancy} micros (db=${db}, stripe=${stripe})`, [{
    check_name: name,
    severity: 'critical',
    dedup_key: `drift:${sign}${magnitude}`,
    payload: {
      db_total_micros: db,
      stripe_total_micros: stripe,
      discrepancy_micros: discrepancy,
      ...extra,
    },
  }]);
}

/**
 * CHECK. billing_stalled (HIGH, stateful) — advertisers with BOTH currently-paused
 * line_items AND uncharged cleared billing groups. This is the state the live-mode
 * no_payment_method path produces (billing pauses the items and deliberately writes NO
 * advertiser_charges row so the group stays retryable): revenue collection has stopped
 * while debt accrues. charge_failed cannot see it (no failed-charge row exists), and its
 * 24h window ages out anyway; this check keys on CURRENT state, so the alert stays open
 * until the groups are actually charged or the items unpaused — never a false
 * "resolved" from mere passage of time. A manually-paused advertiser with no uncharged
 * debt does NOT fire.
 * @param {{unchargedRows?: Array<{advertiser_id?: string, advertiser_name?: string, amount_micros?: unknown}>,
 *          pausedLineItems?: Array<{id?: string, advertiser_id?: string}>}} input
 */
export function evalBillingStalled(input) {
  const name = 'billing_stalled';
  const uncharged = Array.isArray(input?.unchargedRows) ? input.unchargedRows : [];
  const paused = Array.isArray(input?.pausedLineItems) ? input.pausedLineItems : [];

  const pausedByAdv = new Map();
  for (const li of paused) {
    const adv = li?.advertiser_id;
    if (!adv) continue;
    pausedByAdv.set(adv, (pausedByAdv.get(adv) ?? 0) + 1);
  }

  const debtByAdv = new Map();
  for (const row of uncharged) {
    const adv = row?.advertiser_id;
    if (!adv || !pausedByAdv.has(adv)) continue;
    const cur = debtByAdv.get(adv) ?? { name: row?.advertiser_name ?? null, groups: 0, micros: 0 };
    cur.groups += 1;
    const m = toMicros(row?.amount_micros);
    // Unreadable micros still count the group (fail loud); the sum just omits it.
    if (Number.isFinite(m)) cur.micros += m;
    debtByAdv.set(adv, cur);
  }

  const alerts = [...debtByAdv.entries()].map(([adv, d]) => ({
    check_name: name,
    severity: 'high',
    dedup_key: `adv:${adv}`,
    payload: {
      advertiser_id: adv,
      advertiser_name: d.name,
      paused_line_items: pausedByAdv.get(adv) ?? 0,
      uncharged_groups: d.groups,
      uncharged_micros: d.micros,
    },
  }));
  if (alerts.length === 0) return pass(name, 'no advertiser is paused with uncharged cleared debt');
  return fail(name, `${alerts.length} advertiser(s) paused with uncharged cleared debt`, alerts);
}

/**
 * CHECK. reversed_charge_unrefunded (HIGH, stateful) — Phase-2 durable backstop for the
 * reversal↔refund coupling. A manual/approved clawback (admin_open_clawback / approve_clawback)
 * reverses the advertiser_billing ledger leg synchronously, but the Stripe cash refund is a
 * SEPARATE POST /billing/refund step chained in the dashboard UI. If that step is skipped or
 * fails, the books say 'reversed' while the advertiser keeps the cash — and billing_recon_drift
 * eventually goes permanently red. This check fires FIRST, before the drift is baked in: any
 * APPROVED clawback_reviews row that (a) still has refund_queued=false and (b) has a matching
 * succeeded advertiser_charge for its impression, older than the grace, alerts per review id.
 *
 * NO FALSE POSITIVE by construction: a refunded review (refund_queued=true), a non-approved
 * review (pending/rejected), a review with no impression_id (NULL-impression / CPC — the refund
 * path can't act on it anyway), or a review whose impression carries no succeeded charge (e.g. a
 * sub-50c leg never charged) never fires. Keys on CURRENT state, so the alert auto-resolves the
 * moment the refund is queued — never a false 'resolved' from mere passage of time.
 *
 * The edge fn does the I/O: it pre-fetches approved+refund_queued=false reviews (impression_id
 * NOT NULL) and the succeeded charges for those impressions; this function joins + ages them.
 * @param {{reviews?: Array<{id?: string, impression_id?: string, reviewed_at?: string, refund_queued?: boolean, status?: string}>,
 *          charges?: Array<{id?: string, impression_id?: string, amount_cents?: number, status?: string}>,
 *          now?: number, graceMs?: number}} input
 */
export function evalReversedChargeUnrefunded(input) {
  const name = 'reversed_charge_unrefunded';
  const reviews = Array.isArray(input?.reviews) ? input.reviews : [];
  const charges = Array.isArray(input?.charges) ? input.charges : [];
  const now = Number.isFinite(input?.now) ? input.now : Date.now();
  const graceMs = Number.isFinite(input?.graceMs) ? input.graceMs : REVERSED_CHARGE_UNREFUNDED_GRACE_MS;

  // Index succeeded charges by impression_id (first wins; one succeeded charge per impression).
  const succeededByImpression = new Map();
  for (const c of charges) {
    if (String(c?.status) !== 'succeeded') continue; // defensive: edge pre-filters to succeeded
    const imp = c?.impression_id;
    if (!imp || succeededByImpression.has(imp)) continue;
    succeededByImpression.set(imp, c);
  }

  const alerts = [];
  for (const r of reviews) {
    // Only APPROVED + not-yet-refunded reviews are candidates. A refunded (refund_queued=true)
    // or non-approved review is books-vs-cash consistent → must never fire.
    if (String(r?.status) !== 'approved') continue;
    if (r?.refund_queued === true) continue;
    const imp = r?.impression_id;
    if (!imp) continue; // NULL-impression review (CPC) has no refundable charge — do not fire
    const charge = succeededByImpression.get(imp);
    if (!charge) continue; // reversed leg maps to no succeeded cash → nothing to refund
    const reviewedMs = Date.parse(String(r?.reviewed_at ?? ''));
    // Unparseable reviewed_at → treat as past grace (fail loud, never silently green).
    const ageMs = Number.isFinite(reviewedMs) ? now - reviewedMs : Infinity;
    if (ageMs > graceMs) {
      alerts.push({
        check_name: name,
        severity: 'high',
        dedup_key: `review:${r?.id ?? 'unknown'}`,
        payload: {
          review_id: r?.id ?? null,
          impression_id: imp,
          charge_id: charge?.id ?? null,
          amount_cents: charge?.amount_cents ?? null,
          reviewed_at: r?.reviewed_at ?? null,
          age_ms: Number.isFinite(ageMs) ? ageMs : null,
        },
      });
    }
  }
  if (alerts.length === 0) {
    return pass(name, 'no approved clawback review with an unrefunded succeeded charge past grace');
  }
  return fail(name, `${alerts.length} approved review(s) with a succeeded charge unrefunded > ${graceMs}ms`, alerts);
}

/**
 * Check names whose open alerts may be RESOLVED this run: only checks that actually
 * evaluated (pass/fail). An 'error' check could not see the data, so its previously-open
 * alerts must stay open (its own check_error alert still fires via the alerts list).
 * @param {Array<{name: string, status: string}>} checkResults
 * @returns {string[]}
 */
export function resolvableCheckNames(checkResults) {
  return (Array.isArray(checkResults) ? checkResults : [])
    .filter((c) => c && (c.status === 'pass' || c.status === 'fail'))
    .map((c) => c.name);
}

/**
 * Email is sent ONLY on a state change: alerts newly fired or newly resolved.
 * An all-green run — or a run where every alert was ALREADY open (dedup) — sends nothing.
 * @param {unknown[]} fired
 * @param {unknown[]} resolved
 * @returns {boolean}
 */
export function shouldSendEmail(fired, resolved) {
  return (Array.isArray(fired) && fired.length > 0) || (Array.isArray(resolved) && resolved.length > 0);
}

/**
 * Build the summary email (subject + plain text). No secret values, ever.
 * @param {Array<{check_name?: string, severity?: string, dedup_key?: string}>} fired
 * @param {Array<{check_name?: string, dedup_key?: string}>} resolved
 * @param {Array<{name: string, status: string, detail?: string}>} checks
 * @returns {{subject: string, text: string}}
 */
export function buildAlertEmail(fired, resolved, checks) {
  const f = Array.isArray(fired) ? fired : [];
  const r = Array.isArray(resolved) ? resolved : [];
  const worst = f.some((a) => a?.severity === 'critical') ? 'CRITICAL' :
    f.length > 0 ? 'HIGH' : 'RESOLVED';
  const subject = `[LumaLine monitor] ${worst}: ${f.length} fired, ${r.length} resolved`;
  const lines = [];
  if (f.length > 0) {
    lines.push('NEWLY FIRED:');
    for (const a of f) lines.push(`  - [${a?.severity ?? '?'}] ${a?.check_name ?? '?'} (${a?.dedup_key ?? '?'})`);
  }
  if (r.length > 0) {
    lines.push('NEWLY RESOLVED:');
    for (const a of r) lines.push(`  - ${a?.check_name ?? '?'} (${a?.dedup_key ?? '?'})`);
  }
  lines.push('CHECK SUMMARY:');
  for (const c of Array.isArray(checks) ? checks : []) {
    lines.push(`  - ${c?.name}: ${c?.status}${c?.detail ? ` — ${c.detail}` : ''}`);
  }
  return { subject, text: lines.join('\n') };
}

/**
 * Constant-time string comparison via crypto.subtle SHA-256 digests. Hashing both inputs
 * first removes length- and prefix-dependent timing (the byte compare then runs over two
 * equal-length digests). Empty/absent values never authorize.
 * @param {string} a
 * @param {string} b
 * @returns {Promise<boolean>}
 */
export async function timingSafeEqualStrings(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length === 0 || b.length === 0) return false;
  // Deno + Node >= 19 expose WebCrypto as globalThis.crypto; Node 18 (still in CI) only
  // has it under node:crypto.webcrypto — fall back lazily so Deno never touches node:.
  const subtle = globalThis.crypto?.subtle ?? (await import('node:crypto')).webcrypto.subtle;
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    subtle.digest('SHA-256', enc.encode(a)),
    subtle.digest('SHA-256', enc.encode(b)),
  ]);
  const ba = new Uint8Array(da);
  const bb = new Uint8Array(db);
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}
