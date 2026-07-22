// src/client/window.mjs — pure per-tick protocol step. Claude Code runs the
// status-line client once per tick (~1/s via refreshInterval); each call advances
// the window state machine by one step: open -> beat... -> close. Clock, HTTP poster,
// and the ad-signature verifier are injected so this is fully unit-testable.
//
// Hardened after the Phase 0 trust gate:
//   - the ad (line, label, clickUrl) is taken from the SIGNED /window/open payload and
//     verified via cfg.verifyAd before anything is rendered (signed-content-only);
//   - only a coarse activity bucket leaves the machine; the raw cost/token value used to
//     detect change is kept locally in state.lastActivityValue and never sent;
//   - close is best-effort (the server credits idempotently), so a lost close response
//     never re-bills.
//
// WHAT THE HEARTBEAT CHAIN IS (and is NOT): the per-window `challenge` returned by /window/open IS
// the HMAC key, so this chain SEQUENCES beats and makes THIRD-PARTY tampering evident — it is NOT a
// proof of attention against the publisher, who holds the same key and could synthesize beats. The
// real anti-farm enforcement is SERVER-SIDE: in-DB per-device velocity + concurrency caps in
// window_open, per-device/IP scan_ivt, and the 72h clawback. The chain is kept because sequencing +
// third-party tamper-evidence still add value; it is just not the fraud gate.
import { hmacHex } from '../lib/crypto.mjs';
import { safeClickUrl } from '../lib/url.mjs';

// Coarse magnitude of the per-tick activity change. Raw values never leave the machine;
// only this bucket is sent. 'none' => no real progress (idle is never billed).
function bucketDelta(activity, last) {
  if (activity == null || activity === last) return 'none';
  const d = (typeof activity === 'number' && typeof last === 'number') ? activity - last : 1;
  if (d <= 0) return 'none';
  if (d < 1) return 'low';
  if (d < 100) return 'med';
  return 'high';
}

// `★ <line>  ·  <url>  ·  <label> (Ns)` — the click URL is shown inline (between the
// description and the disclosure) so it is transparent AND copy/click-reachable in any
// terminal, not just IDE terminals where the OSC-8 hyperlink works. The URL is sanitized
// here (it becomes visible text); cfg.showUrl === false drops it (keeps the line clickable
// via OSC-8 only). The "sponsored" label is always present — honest disclosure.
const adLine = (state, left, showUrl) => {
  const u = showUrl === false ? null : safeClickUrl(state.clickUrl);
  return `★ ${state.line}${u ? `  ·  ${u}` : ''}  ·  ${state.label} (${left}s)`;
};
const refuse = () => ({ state: null, status: null, verifyFail: true });

export async function step({ state, now, activity, post, cfg }) {
  const cooldownMs = cfg.cooldownMs ?? 15000;

  // Decide whether to (re)open a window: no active window, or the prior window's
  // dwell + cooldown elapsed AND real activity advanced since (idle never re-bills).
  const cooled = state && now - state.startedAt >= state.dwellMs + cooldownMs;
  const activeSince = state && state.lastActivityValue !== activity;
  if (!state || (cooled && activeSince)) {
    const w = await post('/window/open', { sessionId: cfg.sessionId ?? 'cli', activitySnapshot: 'session' });
    // Signed content only: select the trusted key by the envelope's keyid (absent => legacy
    // default), then verify. Unknown keyid or a bad sig => refuse (rotation-safe).
    if (!cfg.verifyAd(w.adData, w.sig, w.keyid)) return refuse();
    let ad;
    try { ad = JSON.parse(w.adData); } catch { return refuse(); }
    if (ad.windowId !== w.windowId) return refuse();        // ad must be bound to this window
    // Start the dwell clock AFTER the open round-trip. The server stamps ad_windows.started_at at
    // the open TRANSACTION time (post round-trip + sentinel-JWT mint + ad signing), so measuring the
    // dwell from `now` (captured before the round-trip) made the server see a dwell ~network-latency
    // short of dwellMs and reject a full honest dwell as 'dwell too short'. Re-sampling here aligns
    // the client's dwell start with the server's. cfg.clock is injected (Date.now in prod, a fake in
    // tests); fall back to `now` when absent so the pure-clock tests stay deterministic.
    const startedAt = cfg.clock ? cfg.clock() : now;
    state = {
      // `challenge` is the server-issued per-window HMAC KEY (shared with us by design): it lets us
      // SEQUENCE beats + makes third-party tampering evident; it is NOT an attention proof vs the
      // publisher. Real anti-farm gates are server-side (velocity caps + scan_ivt + clawback).
      windowId: w.windowId, challenge: w.challenge, seq: 0, prevHash: w.windowId,
      startedAt, dwellMs: w.dwellMs, hbIntervalMs: w.hbIntervalMs,
      line: ad.line, label: ad.label ?? 'sponsored', clickUrl: ad.clickUrl,
      reported: false, lastActivityValue: activity,
    };
    return { state, status: adLine(state, Math.round(state.dwellMs / 1000), cfg.showUrl), clickUrl: state.clickUrl };
  }

  const elapsed = now - state.startedAt;
  if (elapsed < state.dwellMs) {
    const seq = state.seq + 1;
    const activityDelta = bucketDelta(activity, state.lastActivityValue);
    const hmac = hmacHex(state.challenge, `${seq}|${state.prevHash}|${activityDelta}`);
    await post('/window/beat', { windowId: state.windowId, seq, hmac, activityDelta });
    state = { ...state, seq, prevHash: hmac, lastActivityValue: activity };
    const left = Math.ceil((state.dwellMs - elapsed) / 1000);
    return { state, status: adLine(state, left, cfg.showUrl), clickUrl: state.clickUrl };
  }

  if (!state.reported) {
    // Best-effort: the server credits at most once, so a lost response cannot double-bill.
    try { await post('/window/close', { windowId: state.windowId }); } catch { /* idempotent server */ }
    state = { ...state, reported: true };
  }
  return { state, status: null, clickUrl: null };
}
