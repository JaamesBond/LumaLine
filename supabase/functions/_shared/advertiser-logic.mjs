// Pure advertiser-prepay decision helpers for the advertiser-portal + billing edge functions.
//
// ZERO runtime deps, NO Deno/Stripe globals — importable by BOTH the Deno edge runtime and
// `node --test` (test/advertiser-billing-logic.test.mjs). Same precedent as billing-logic.mjs /
// payout-logic.mjs. These mirror the DB money/content primitives (20260716170000/190000) so the
// money-safety + content-safety decisions are exercised hermetically even when the local Supabase
// stack is down (where every advertiser integration suite self-skips).

// EUR-micros: 1 EUR = 1,000,000 micros = 100 Stripe cents. 1 cent = 10,000 micros.
export function centsToMicros(cents) {
  return Math.round(Number(cents) * 10000);
}
export function microsToCents(micros) {
  return Math.round(Number(micros) / 10000);
}

/**
 * AVAILABLE spendable credit = balance - reserved (the raw subtraction the guards use).
 * window_open reserves against this; an admin debit gates on it.
 * @param {number} balanceMicros
 * @param {number} reservedMicros
 * @returns {number}
 */
export function availableMicros(balanceMicros, reservedMicros) {
  return (Number(balanceMicros) || 0) - (Number(reservedMicros) || 0);
}

/**
 * Serve-time reserve estimate = ceil(dwellMs / 1000) * cpva_bid_micros (mirrors window_open's
 * ceil(v_dwell/1000)*clearing_price with v_dwell=5000 -> 5 attention-seconds).
 * @param {number} dwellMs
 * @param {number} cpvaBidMicros
 * @returns {number}
 */
export function reserveEstimateMicros(dwellMs, cpvaBidMicros) {
  const secs = Math.ceil((Number(dwellMs) || 0) / 1000);
  return secs * (Number(cpvaBidMicros) || 0);
}

/**
 * Chargeback-after-spend split (mirrors app.advertiser_apply_deposit_reversal):
 *   reclaim    = min(R, balance)        (unwind still-held liability)
 *   badDebt    = max(0, R - balance)    (platform write-off of already-spent funds)
 *   newBalance = max(0, balance - R)    (clamped; the cache never goes negative)
 * The zero-sum ledger group is: platform_cash -R / advertiser_funds +reclaim / advertiser_bad_debt
 * +badDebt, which sums to 0 (verified by `chargebackLegsSumToZero`).
 * @param {number} disputeMicros  R
 * @param {number} balanceMicros
 * @returns {{ reclaimMicros:number, badDebtMicros:number, newBalanceMicros:number }}
 */
export function planChargebackSplit(disputeMicros, balanceMicros) {
  const R = Number(disputeMicros) || 0;
  const bal = Number(balanceMicros) || 0;
  const reclaim = Math.min(R, bal);
  const badDebt = Math.max(0, R - bal);
  const newBalance = Math.max(0, bal - R);
  return { reclaimMicros: reclaim, badDebtMicros: badDebt, newBalanceMicros: newBalance };
}

/**
 * The chargeback ledger legs sum to zero: platform_cash(-R) + advertiser_funds(+reclaim) +
 * advertiser_bad_debt(+badDebt). Since reclaim+badDebt == R, -R + reclaim + badDebt == 0 always.
 * @param {number} disputeMicros
 * @param {number} balanceMicros
 * @returns {boolean}
 */
export function chargebackLegsSumToZero(disputeMicros, balanceMicros) {
  const { reclaimMicros, badDebtMicros } = planChargebackSplit(disputeMicros, balanceMicros);
  return (-(Number(disputeMicros) || 0)) + reclaimMicros + badDebtMicros === 0;
}

/**
 * Decide whether an incoming Stripe deposit event should CREDIT the advertiser balance.
 *
 * Money-safety (deposit-timing HIGH): credit ONLY when cash is captured. A card-only Checkout marks
 * the session payment_status='paid' exactly when its PaymentIntent succeeds. A 'processing' PI, or a
 * session whose payment_status is not 'paid' (a delayed/failed EUR method), credits NOTHING. The
 * advertiser is ALWAYS resolved by the caller from the server-stored advertiser_topup_intents row
 * keyed by sessionId — never from client/event metadata.
 *
 * @param {{ type?:string, data?:{ object?:any } }} event
 * @returns {{ action:'credit'|'ignore', sessionId:string|null, piId:string|null, reason:string }}
 */
export function evaluateDepositEvent(event) {
  const type = event?.type;
  const obj = event?.data?.object ?? {};
  const piId = piIdOf(obj.payment_intent);

  if (type === "checkout.session.completed") {
    if (obj.payment_status !== "paid") {
      return { action: "ignore", sessionId: obj.id ?? null, piId, reason: "session_not_paid" };
    }
    return { action: "credit", sessionId: obj.id ?? null, piId, reason: "session_paid" };
  }

  // A bare payment_intent.* event is NOT a credit trigger for the Checkout flow: the
  // checkout.session.completed(payment_status='paid') event is the authoritative capture signal and
  // carries the session id that resolves the topup_intent. payment_intent.processing/succeeded on
  // their own never credit (avoids crediting a 'processing' PI and avoids a double-credit).
  return { action: "ignore", sessionId: null, piId, reason: "not_a_credit_trigger" };
}

/** True when a Stripe event type is a DEPOSIT reversal (dispute/refund) -> advertiser bad-debt path. */
export function isAdvertiserDisputeEvent(type) {
  return (
    type === "charge.dispute.funds_withdrawn" ||
    type === "charge.dispute.created" ||
    type === "charge.refunded"
  );
}

/**
 * Refund branch selector (mirrors billing /refund + admin_prepay_clawback): a card-settled charge
 * refunds via Stripe; a balance-settled (prepay draw-down) charge re-credits the prepay balance —
 * NEVER both, so a prepay charge is never double-refunded.
 * @param {string} settledVia  'stripe' | 'balance'
 * @returns {'stripe_refund'|'balance_clawback'}
 */
export function refundBranch(settledVia) {
  return settledVia === "balance" ? "balance_clawback" : "stripe_refund";
}

/** Normalize a Stripe payment_intent field (string id or expanded object) to its id string. */
export function piIdOf(pi) {
  if (typeof pi === "string") return pi;
  if (pi && typeof pi === "object" && typeof pi.id === "string") return pi.id;
  return null;
}

// --- Content-safety parity with app.validate_creative_content / validate_disclosure_label ----
// Byte-identical rules to the SQL validator so the client hint + tests never drift from the server
// boundary. Control class = C0 (0x00-0x1F) + DEL (0x7F); dest_url also rejects any whitespace.
const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const DEST_UNSAFE_RE = /[\u0000-\u001f\u007f\s]/; // control OR any whitespace (incl. space)
const ALLOWED_LABELS = ["sponsored", "ad", "promoted"];

/**
 * Mirror of app.validate_creative_content — returns null when valid, else a short reason string.
 * @returns {string|null}
 */
export function validateCreativeContent(line, label, destUrl) {
  if (line == null || String(line).length === 0) return "line_empty";
  if (String(line).length > 120) return "line_too_long";
  if (CONTROL_RE.test(String(line))) return "line_control_bytes";
  if (label == null || String(label).length === 0) return "label_empty";
  if (String(label).length > 30) return "label_too_long";
  if (CONTROL_RE.test(String(label))) return "label_control_bytes";
  if (destUrl != null) {
    if (!/^https:\/\//.test(String(destUrl))) return "dest_not_https";
    if (DEST_UNSAFE_RE.test(String(destUrl))) return "dest_control_bytes";
  }
  return null;
}

/** Mirror of app.validate_disclosure_label — the exact-ASCII disclosure allow-list. */
export function isAllowedDisclosureLabel(label) {
  return ALLOWED_LABELS.includes(String(label ?? ""));
}
