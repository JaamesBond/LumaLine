// Comma-split STRIPE_WEBHOOK_SECRET so one function can verify events signed by multiple
// Stripe endpoints (connected account.updated + platform transfer.reversed).
//
// Deliberately ZERO runtime deps and NO Deno/Stripe globals so this can be imported by
// both the Deno edge function (../_shared/webhook-secrets.mjs) and `node --test`
// (test/webhook-multi-secret.test.mjs) — same precedent as ../_shared/payout-logic.mjs.

/**
 * Parse a (possibly comma-separated) webhook-secret env value into a list of secrets.
 * @param {string} raw
 * @returns {string[]}
 */
export function parseWebhookSecrets(raw) {
  return String(raw ?? '').split(',').map((s) => s.trim()).filter(Boolean);
}
