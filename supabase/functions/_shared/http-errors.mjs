// Shared error-response shaping for the money/admin edge functions.
//
// Security-audit hardening (error-detail residual): jsonErr historically echoed the raw
// DB/RPC payload (`detail`) back to the caller. Those bodies only ever reach admins / Stripe
// webhooks, but they can carry constraint text, internal ids, and other reconnaissance value.
// In production we drop `detail` from the RESPONSE and log it server-side instead; it is echoed
// only when the operator explicitly opts in via LUMALINE_DEBUG_ERRORS=1 (dev/triage).

// True when error `detail` may be included in responses. Off by default -> production responses
// carry only { error: message }. `env` is a Deno.env-like object exposing .get(name).
export function errorDetailEnabled(env) {
  const v = env && typeof env.get === "function" ? env.get("LUMALINE_DEBUG_ERRORS") : undefined;
  return v === "1" || v === "true";
}

// Build the JSON error body. Always { error: message }; appends { detail } only when a non-null
// detail is present AND detail-echo is enabled. Otherwise detail is dropped (log it server-side).
export function errorResponseBody(message, detail, includeDetail) {
  const body = { error: message };
  if (includeDetail && detail !== undefined && detail !== null) body.detail = detail;
  return body;
}
