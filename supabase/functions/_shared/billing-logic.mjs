// Pure live-mode billing decision helpers for the billing edge function.
//
// Deliberately ZERO runtime deps and NO Deno/Stripe globals so this can be imported by
// both the Deno edge function (../_shared/billing-logic.mjs) and `node --test`
// (test/billing-logic.test.mjs) — same precedent as ../_shared/payout-logic.mjs and
// ../_shared/webhook-secrets.mjs.
//
// WHY THIS EXISTS (M5 go-live): the charge path used to hardcode payment_method:
// 'pm_card_visa', a Stripe TEST token that does not exist in live mode. In live mode a
// real saved payment method must be used, and when the advertiser has none the group must
// be SKIPPED (honest billing: never guess a payment instrument), never "charged" against
// a test token.

/** The Stripe test-mode payment-method token. MUST NEVER be used with a live key. */
export const TEST_FALLBACK_PM = "pm_card_visa";

/**
 * Convert micro-EUR to Stripe cents. 1 EUR = 1,000,000 micro-EUR = 100 cents.
 * Rounded (banker-agnostic Math.round) — the same conversion the charge + reconcile use.
 * @param {number} micros
 * @returns {number} cents
 */
export function microsToCents(micros) {
  return Math.round(Number(micros) / 10000);
}

/**
 * Stripe idempotency key for an AGGREGATE advertiser charge, derived from the IMMUTABLE
 * charge_batch_id stamped on the reserved rows — NOT from the (mutable) set of uncharged groups.
 *
 * This is the crux of the crash-safety fix (adversarial review F1): a batch's membership is frozen
 * at reserve time, so a crash/ambiguous-error retry — or a recovery run — reselects the SAME batch
 * and recomputes the SAME key, and Stripe returns the SAME PaymentIntent. Impressions that accrue
 * afterwards form a NEW batch with a NEW key; they can never merge into an already-attempted charge
 * and trigger a re-charge of the impressions it already billed.
 * @param {string} batchId  a uuid
 * @returns {string}
 */
export function batchIdempotencyKey(batchId) {
  return `lumaline_agg_${String(batchId)}`;
}

/**
 * Partition reserved-but-unsettled (pending) advertiser_charges rows by their charge_batch_id.
 * Recovery re-issues each batch under its own stable key — never across batches. Rows without a
 * batch id (legacy/malformed) are grouped under the sentinel key "" so they can be released, not
 * silently charged.
 * @param {Array<{charge_batch_id?:string|null, advertiser_id:string}>} rows
 * @returns {Map<string, {advertiser_id:string, rows:any[]}>}
 */
export function partitionPendingByBatch(rows) {
  const byBatch = new Map();
  for (const r of rows ?? []) {
    const key = r.charge_batch_id ?? "";
    let b = byBatch.get(key);
    if (!b) { b = { advertiser_id: r.advertiser_id, rows: [] }; byBatch.set(key, b); }
    b.rows.push(r);
  }
  return byBatch;
}

/**
 * Group uncharged ledger view rows by advertiser and decide the per-advertiser action.
 *
 * WHY AGGREGATE: CPVA bills per attention-second (~€0.05 / 5s view), so a single impression is
 * ~5 cents — permanently below Stripe's 50-cent minimum. Charging per impression can therefore
 * NEVER collect from such an advertiser. Charges must be summed per advertiser into one
 * PaymentIntent. A below-minimum AGGREGATE is a NON-terminal skip: it writes no charge row, so
 * the groups stay in the uncharged view and keep accumulating until the total clears the minimum.
 *
 * PREPAY ROUTING (M9): a billing_mode='prepay' advertiser is settled by drawing down prepay
 * credit (app.advertiser_draw_down_batch), NOT a Stripe PaymentIntent — so it has NO 50-cent
 * Stripe minimum (draw-down is exact micros) and routes to action='draw_prepay' regardless of
 * the sub-minimum aggregate. House is still skip_house; legacy postpay is unchanged.
 *
 * @param {Array<{advertiser_id:string, advertiser_name?:string, is_house?:boolean,
 *   stripe_customer_id?:string|null, billing_mode?:string|null, entry_group_id:string,
 *   amount_micros:number, impression_id?:string|null, publisher_id?:string|null}>} rows
 * @param {{minCents?:number}} [opts]
 * @returns {Array<{advertiser_id:string, advertiser_name:string|null, is_house:boolean,
 *   billing_mode:string, stripe_customer_id:string|null, groups:Array<{entry_group_id:string,
 *   amount_micros:number, impression_id:string|null, publisher_id:string|null}>,
 *   entryGroupIds:string[], sumMicros:number, sumCents:number,
 *   action:'skip_house'|'skip_below_min'|'charge'|'draw_prepay'}>}
 */
export function planAdvertiserCharges(rows, { minCents = 50 } = {}) {
  const byAdv = new Map();
  for (const r of rows ?? []) {
    const id = r.advertiser_id;
    let p = byAdv.get(id);
    if (!p) {
      p = {
        advertiser_id: id,
        advertiser_name: r.advertiser_name ?? null,
        is_house: r.is_house === true,
        billing_mode: r.billing_mode ?? "postpay",
        stripe_customer_id: r.stripe_customer_id ?? null,
        groups: [],
        sumMicros: 0,
      };
      byAdv.set(id, p);
    }
    const micros = Number(r.amount_micros) || 0;
    p.groups.push({
      entry_group_id: r.entry_group_id,
      amount_micros: micros,
      impression_id: r.impression_id ?? null,
      publisher_id: r.publisher_id ?? null,
    });
    p.sumMicros += micros;
  }
  return [...byAdv.values()].map((p) => {
    const sumCents = microsToCents(p.sumMicros);
    const action = p.is_house
      ? "skip_house"
      : p.billing_mode === "prepay"
        ? "draw_prepay"
        : sumCents < minCents
          ? "skip_below_min"
          : "charge";
    return { ...p, entryGroupIds: p.groups.map((g) => g.entry_group_id), sumCents, action };
  });
}

/**
 * Pure decision for a prepay draw-down at billing-settle (mirrors app.advertiser_draw_down_batch's
 * guards so a hermetic node --test can exercise the money logic even with the stack down):
 *   - balance >= sum          → { draw:true }                        (draw the exact micros)
 *   - balance <  sum          → { draw:false, reason:'insufficient_balance' } (pause, NO partial)
 *   - reserved < sum (either) → reservedUnderflow:true               (LOUD signal; never hides drift)
 * The draw-down itself is idempotent on charge_batch_id in the DB; this helper only decides.
 * @param {{ balanceMicros:number, reservedMicros:number, sumMicros:number }} args
 * @returns {{ draw:boolean, reason:'ok'|'insufficient_balance'|'nothing_to_draw',
 *   reservedUnderflow:boolean, amountMicros:number }}
 */
export function planAdvertiserDrawDown({ balanceMicros, reservedMicros, sumMicros } = {}) {
  const bal = Number(balanceMicros) || 0;
  const res = Number(reservedMicros) || 0;
  const sum = Number(sumMicros) || 0;
  if (sum <= 0) {
    return { draw: false, reason: "nothing_to_draw", reservedUnderflow: false, amountMicros: 0 };
  }
  const reservedUnderflow = res < sum;   // reserve accounting drifted low — always surfaced
  if (bal < sum) {
    return { draw: false, reason: "insufficient_balance", reservedUnderflow, amountMicros: 0 };
  }
  return { draw: true, reason: "ok", reservedUnderflow, amountMicros: sum };
}

/**
 * True when a Stripe secret key is a LIVE key (sk_live_* or rk_live_* restricted key).
 * Anything else (sk_test_*, rk_test_*, empty, garbage) is treated as NOT live, which is
 * the safe direction: test-mode fallbacks only ever engage for non-live keys, and a
 * malformed key will fail loudly at the first Stripe call anyway.
 * @param {unknown} key
 * @returns {boolean}
 */
export function isLiveKey(key) {
  const k = typeof key === "string" ? key : "";
  return k.startsWith("sk_live_") || k.startsWith("rk_live_");
}

/**
 * Decide which payment method to charge for one advertiser billing group.
 *
 * Rules (in order):
 *   1. The customer's saved default payment method (invoice_settings.default_payment_method)
 *      always wins.
 *   2. Otherwise the first attached payment method.
 *   3. Otherwise, in TEST mode only, fall back to the Stripe test token 'pm_card_visa'
 *      (preserves every existing test and the test-mode e2e).
 *   4. Otherwise (live mode, no PM at all): { skip: 'no_payment_method' } — the caller
 *      records the group as skipped and pauses the advertiser's line items.
 *
 * EXPLICIT LIVE-MODE GUARD: this function can never return pm_card_visa when
 * liveMode=true. Even if a caller somehow passes the test token in as a "saved" or
 * "attached" PM, live mode degrades to { skip } rather than attempting a charge against
 * a test-mode-only token.
 *
 * @param {{ liveMode?: unknown,
 *           defaultPaymentMethodId?: unknown,
 *           attachedPaymentMethodIds?: unknown }} args
 * @returns {{ pm: string } | { skip: 'no_payment_method' }}
 */
export function choosePaymentMethod({
  liveMode,
  defaultPaymentMethodId,
  attachedPaymentMethodIds,
} = {}) {
  const live = liveMode === true;

  const defaultPm =
    typeof defaultPaymentMethodId === "string" ? defaultPaymentMethodId.trim() : "";
  const attached = Array.isArray(attachedPaymentMethodIds)
    ? attachedPaymentMethodIds
        .filter((id) => typeof id === "string" && id.trim() !== "")
        .map((id) => id.trim())
    : [];

  let chosen = "";
  if (defaultPm) {
    chosen = defaultPm; // rule 1: saved default wins
  } else if (attached.length > 0) {
    chosen = attached[0]; // rule 2: first attached PM
  } else if (!live) {
    chosen = TEST_FALLBACK_PM; // rule 3: test-mode fallback only
  }

  if (!chosen) return { skip: "no_payment_method" }; // rule 4

  // LIVE MODE MUST NEVER RETURN pm_card_visa — fail safe to skip, never to a test token.
  if (live && chosen === TEST_FALLBACK_PM) return { skip: "no_payment_method" };

  return { pm: chosen };
}
