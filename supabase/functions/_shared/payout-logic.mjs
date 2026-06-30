// Pure money-path decision helpers for the stripe-connect edge function.
//
// Deliberately ZERO runtime deps and NO Deno/Stripe globals so they can be imported by
// both the Deno edge function (../_shared/payout-logic.mjs) and `node --test`
// (test/stripe-connect-logic.test.mjs). These encode the rules the adversarial money-path
// review flagged as critical:
//   - classifyTransferError: when (and only when) it is safe to fail a payout after a
//     transfers.create error — biased HARD toward "ambiguous" because the cost of a wrong
//     "definitive" is a DOUBLE-PAY, while a wrong "ambiguous" only parks a payout pending.
//   - sumLumalineTransfersMicros: reconcile the Stripe side NET of reversals.
//   - reversedMicrosFromTransfer: cumulative reversed micros for amount-aware payout_reverse.

/**
 * Classify a Stripe transfers.create error.
 * Returns 'definitive' ONLY when Stripe certainly did NOT create a transfer (a pure
 * client-side parameter rejection). Everything else — connection resets, timeouts, 409
 * idempotency-in-progress, 429, 5xx, unknown — is 'ambiguous': a transfer MAY exist, so the
 * caller must leave the payout 'pending' and let the next batch self-heal via the
 * metadata.payout_id pre-check, NEVER payout_fail.
 * @param {unknown} err
 * @returns {'definitive'|'ambiguous'}
 */
export function classifyTransferError(err) {
  if (!err || typeof err !== "object") return "ambiguous";
  const e = /** @type {Record<string, unknown>} */ (err);
  const type = String(e.type ?? "");          // SDK class, e.g. "StripeInvalidRequestError"
  const rawType = String(e.rawType ?? "");    // API type, e.g. "invalid_request_error" (Deno build surfaces this)
  const code = String(e.code ?? "");
  // Idempotency replay / in-progress: the transfer may already exist or be landing.
  if (type === "StripeIdempotencyError" || code === "idempotency_error") return "ambiguous";
  // A request-validation rejection (either error shape) means Stripe did NOT create a
  // transfer — safe to fail. Covers e.g. insufficient_capabilities_for_transfer.
  if (type === "StripeInvalidRequestError" || rawType === "invalid_request_error") return "definitive";
  // Anything else (network/5xx/429/409/unknown) -> assume a transfer might exist.
  return "ambiguous";
}

/**
 * Sum LumaLine transfers for reconciliation, NET of reversals, in micro-EUR.
 * A fully-reversed transfer contributes 0, matching the DB side (which excludes it).
 * @param {Array<{amount?: number, amount_reversed?: number, metadata?: {source?: string}}>} transfers
 * @returns {number}
 */
export function sumLumalineTransfersMicros(transfers) {
  let total = 0;
  for (const t of transfers ?? []) {
    if (t && t.metadata && t.metadata.source === "lumaline") {
      const net = (Number(t.amount) || 0) - (Number(t.amount_reversed) || 0);
      total += net * 10000; // 1 cent = 10,000 micro-EUR
    }
  }
  return total;
}

/**
 * Cumulative reversed micros for a transfer.reversed event. Stripe's transfer carries the
 * CUMULATIVE amount_reversed (cents); fall back to the full amount when absent.
 * @param {{amount?: number, amount_reversed?: number}} transfer
 * @returns {number}
 */
export function reversedMicrosFromTransfer(transfer) {
  const cents = (transfer && (transfer.amount_reversed ?? transfer.amount)) ?? 0;
  return (Number(cents) || 0) * 10000;
}
