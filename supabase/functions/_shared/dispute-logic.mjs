// Pure validator for the publisher /dispute free-text description (auth-device edge fn).
// ZERO deps, node:-importable so `node --test` exercises it hermetically (mirrors advertiser-logic.mjs).
//
// SECURITY (D2): the description is written via service_role into public.disputes.description and later
// rendered in the admin dashboard. Bound its size (storage abuse) and reject raw control bytes
// (terminal/log injection, NUL tricks). This is NOT the XSS defense — the dashboard MUST HTML-escape
// on render; control-byte rejection only removes non-printing bytes, not HTML metacharacters.

// Max stored size: 2KB of UTF-8. Multi-line free text, so tab/newline/CR are allowed; every other
// C0 control (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F) and DEL (0x7F) is rejected. The character class is
// built from String.fromCharCode so this source stays pure-ASCII (no raw control bytes / fragile
// escapes) — the same idiom auth-device/index.ts uses to keep its inline script pure-ASCII.
export const DISPUTE_DESCRIPTION_MAX_BYTES = 2048;
const cc = String.fromCharCode; // 09=\t 0A=\n 0D=\r are the only C0 controls we ALLOW.
const DISPUTE_CONTROL_RE = new RegExp(
  "[" + cc(0x00) + "-" + cc(0x08) + cc(0x0b) + cc(0x0c) + cc(0x0e) + "-" + cc(0x1f) + cc(0x7f) + "]",
);

/**
 * Validate a dispute description. Returns null when valid, else a short reason string.
 * Caller has already trimmed + non-empty-checked, but this re-checks empty for safety.
 * @param {string} description
 * @returns {string|null}
 */
export function validateDisputeDescription(description) {
  const s = String(description ?? "");
  if (s.length === 0) return "description_empty";
  if (new TextEncoder().encode(s).length > DISPUTE_DESCRIPTION_MAX_BYTES) return "description_too_long";
  if (DISPUTE_CONTROL_RE.test(s)) return "description_control_bytes";
  return null;
}
