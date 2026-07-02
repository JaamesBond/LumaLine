// src/client/session.mjs — derive a stable per-Claude-Code-window key from statusLine stdin.
// The key is embedded in a state filename, so it MUST be filename-safe (sanitized). Primary
// key is Claude Code's own per-session id; fallback is a hash of the workspace dir (stable but
// coarse — two windows on the same dir collide, degrading to shared state only when session_id
// is unavailable). NB: NOT the process pid — the statusline is a fresh process each tick, so pid
// is per-tick, not per-session.
import { createHash } from 'node:crypto';

// Keep only filename-safe chars, cap length. Empty/garbage => 'default'.
function sanitize(s) {
  return String(s).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 64) || 'default';
}

export function sessionKey(claude) {
  const sid = claude?.session_id;
  if (typeof sid === 'string' && sid.length > 0) return sanitize(sid);
  const dir = claude?.workspace?.current_dir;
  if (typeof dir === 'string' && dir.length > 0) {
    return 'dir-' + createHash('sha256').update(dir).digest('hex').slice(0, 16);
  }
  return 'default';
}
