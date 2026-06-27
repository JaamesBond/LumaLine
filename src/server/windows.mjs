// src/server/windows.mjs — in-memory window store with heartbeat + activity
// verification. Pure (clock injected). Ported to Postgres RPCs in Phase 1.
//
// Honest-billing invariants enforced here (hardened after the Phase 0 trust gate):
//   - crediting is idempotent: a window credits AT MOST once (no double-close billing);
//   - a window credits only after the FULL dwell elapsed (server wall-clock), so the
//     3-beat anti-batch floor (~1.5s) cannot be billed as a full 5s impression;
//   - heartbeat HMACs are compared in constant time.
// Honest LIMIT (documented, not a bug): activity progress is asserted by the client via
// `activityDelta`. The in-memory v1 has no independent activity oracle, so activity-binding
// is NOT fraud-proof here — it is bound to a server-observed session signal in the Phase 1
// window_beat RPC. Treat Phase 0 CPVA as client-asserted, bounded by dwell + anti-batch.
import crypto from 'node:crypto';
import { hmacHex, randomId } from '../lib/crypto.mjs';

// Constant-time string compare (length-guarded) — avoids HMAC timing oracles.
function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

export function createWindowStore(opts = {}) {
  const now = opts.now ?? (() => Date.now());
  const dwellMs = opts.dwellMs ?? 5000;
  const hbIntervalMs = opts.hbIntervalMs ?? 1000;
  const minBeats = opts.minBeats ?? 3;
  const minSpacingMs = opts.minSpacingMs ?? 500;
  const windows = new Map();

  function open({ sessionId, activitySnapshot }) {
    const windowId = randomId();
    const w = {
      windowId, sessionId, activitySnapshot: activitySnapshot ?? null,
      challenge: randomId(), nonce: randomId(),
      startedAt: now(), lastRecv: now(), prevHash: windowId,
      beats: 0, activityProgress: false, closed: false, credited: false,
    };
    windows.set(windowId, w);
    return { windowId, nonce: w.nonce, challenge: w.challenge, dwellMs, hbIntervalMs, serverTime: w.startedAt };
  }

  function beat({ windowId, seq, hmac, activityDelta }) {
    const w = windows.get(windowId);
    if (!w || w.closed) throw new Error('unknown or closed window');
    if (seq !== w.beats + 1) throw new Error('out-of-order seq');
    const t = now();
    if (t - w.lastRecv < minSpacingMs) throw new Error('anti-batch: beats too close');
    const expected = hmacHex(w.challenge, `${seq}|${w.prevHash}|${activityDelta}`);
    if (!safeEqual(hmac, expected)) throw new Error('bad hmac chain');
    w.beats = seq;
    w.lastRecv = t;
    w.prevHash = hmac;
    if (activityDelta && activityDelta !== 'none') w.activityProgress = true;
    return { ok: true };
  }

  function close({ windowId }) {
    const w = windows.get(windowId);
    if (!w) return { credited: false, attentionSeconds: 0, reason: 'unknown window' };
    if (w.closed) return { credited: false, attentionSeconds: 0, reason: 'already closed' };
    w.closed = true;   // mark BEFORE any credit decision -> close is idempotent / single-credit
    if (w.beats < minBeats) return { credited: false, attentionSeconds: 0, reason: `too few beats (${w.beats})` };
    if (!w.activityProgress) return { credited: false, attentionSeconds: 0, reason: 'no activity progress' };
    const elapsed = now() - w.startedAt;
    if (elapsed < dwellMs) return { credited: false, attentionSeconds: 0, reason: 'dwell too short' };
    w.credited = true;
    const attentionSeconds = Math.round(Math.min(elapsed, dwellMs) / 1000);
    return { credited: true, attentionSeconds, reason: 'ok' };
  }

  return { open, beat, close, _windows: windows };
}
