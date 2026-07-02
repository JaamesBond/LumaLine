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
