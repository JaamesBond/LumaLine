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

/** Constant-time string compare (no early-exit on mismatch). Empty strings never authorize. */
export function constantTimeEqual(a, b) {
  const sa = String(a ?? ""), sb = String(b ?? "");
  if (sa.length === 0 || sb.length === 0 || sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
}

/** Payout minimum in micro-EUR from env; default €1 (1_000_000). Garbage/<1 → default. */
export function payoutMinMicros(envVal) {
  const n = Number(envVal);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1000000;
}

/**
 * Find the id of an existing transfer carrying metadata.payout_id === payoutId, paginating ALL pages
 * (has_more / starting_after) and optionally bounding by a created lower bound. `listFn` is injected —
 * in prod: (params) => stripe.transfers.list(params); in tests: a fake returning {data, has_more}.
 * Returns the transfer id, or null when exhausted. Bounding by createdGteUnix keeps a high-volume
 * publisher's scan cheap: the orphaned transfer, if it exists, was created AFTER its payout row.
 * A13: a >24h-old orphan beyond the last 100 destination transfers must still be found, never re-created.
 * @param {(params: Record<string, unknown>) => Promise<{data?: Array<{id?: string, metadata?: {payout_id?: string}}>, has_more?: boolean}>} listFn
 * @param {{destination: string, payoutId: string, createdGteUnix?: number}} opts
 * @returns {Promise<string|null>}
 */
export async function findTransferIdByMetadata(listFn, { destination, payoutId, createdGteUnix } = {}) {
  let startingAfter;
  for (;;) {
    const params = { destination, limit: 100 };
    if (createdGteUnix != null) params.created = { gte: createdGteUnix };
    if (startingAfter) params.starting_after = startingAfter;
    const page = await listFn(params);
    const data = page && Array.isArray(page.data) ? page.data : [];
    for (const t of data) {
      if (t && t.metadata && t.metadata.payout_id === payoutId) return t.id;
    }
    if (!page || page.has_more !== true || data.length === 0) return null;
    startingAfter = data[data.length - 1].id;
  }
}

/**
 * Resolve the country for Express-account creation: explicit request choice → stored publisher
 * country → CDN geo header (cf-ipcountry). Returns a valid ISO-3166-1 alpha-2 code or null.
 * NEVER defaults to a country: Stripe fixes the country at account creation, so a guessed value
 * permanently mis-creates the account (the old `?? "US"` fallback locked out every publisher
 * whose row had country NULL — which was all of them, since nothing ever set the column).
 * @param {unknown} bodyCountry   country the caller explicitly passed in the request body
 * @param {unknown} storedCountry publishers.country from the DB
 * @param {unknown} headerCountry cf-ipcountry request header (absent when not proxied)
 * @returns {string|null}
 */
export function resolveOnboardCountry(bodyCountry, storedCountry, headerCountry) {
  for (const c of [bodyCountry, storedCountry, headerCountry]) {
    if (typeof c !== 'string') continue;
    const up = c.trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(up)) return up;
  }
  return null;
}

/**
 * Countries LumaLine pays out to. Stripe cross-border payouts let an EEA platform transfer to
 * connected accounts in the US, UK, Canada, and Switzerland in addition to the EEA itself
 * (docs.stripe.com/connect/cross-border-payouts: "Platforms based in the United States, United
 * Kingdom, EEA, Canada, and Switzerland can transfer funds to connected accounts located in any
 * of these same regions"). Keep in sync with publisher-tos §7.7 and the README.
 * Australia + rest-of-world need Stripe Global Payouts (not self-serve) — deliberately absent.
 */
export const PAYOUT_SUPPORTED_COUNTRIES = new Set([
  // EU-27
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE',
  'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
  // EEA (non-EU)
  'IS', 'LI', 'NO',
  // Stripe cross-border regions reachable from an EEA platform
  'US', 'GB', 'CA', 'CH',
]);

/**
 * May a mis-picked onboarding country be redone? Only when the caller EXPLICITLY requests a
 * different valid country AND Stripe onboarding was never completed (no details submitted, no
 * payouts enabled). Stripe fixes the country at account creation, so "redo" means delete the
 * un-onboarded account and create a fresh one — never allowed once the person has actually
 * submitted details or the account can move money.
 * @param {{requested: unknown, storedCountry: unknown, detailsSubmitted: unknown, payoutsEnabled: unknown}} p
 * @returns {boolean}
 */
export function canRedoOnboardCountry({ requested, storedCountry, detailsSubmitted, payoutsEnabled } = {}) {
  if (typeof requested !== 'string' || !/^[A-Z]{2}$/.test(requested)) return false;
  if (requested === storedCountry) return false;
  if (detailsSubmitted === true || payoutsEnabled === true) return false;
  return true;
}
