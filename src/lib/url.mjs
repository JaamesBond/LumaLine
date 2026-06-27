// Shared URL safety for the status line. A control char in a feed-supplied URL could break
// out of an OSC-8 escape OR inject terminal control codes when the URL is shown as plain
// text, so any URL that is displayed or made clickable MUST pass through here first. Only an
// absolute http(s) URL with no control chars survives; anything else => null (not shown, not
// linked). The ad is ed25519-signed, but this stays as defense-in-depth: the client never
// emits terminal control sequences a feed could smuggle in.

// Detect control chars via char codes (keeps this source ASCII-only).
export function hasControlChars(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

export function safeClickUrl(u) {
  if (typeof u !== 'string' || hasControlChars(u)) return null;
  try {
    const x = new URL(u);
    return (x.protocol === 'http:' || x.protocol === 'https:') ? u : null;
  } catch {
    return null;
  }
}
