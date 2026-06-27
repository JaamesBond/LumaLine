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
import { hmacHex } from '../lib/crypto.mjs';

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

const adLine = (state, left) => `★ ${state.line}  ·  ${state.label} (${left}s)`;
const refuse = () => ({ state: null, status: null, verifyFail: true });

export async function step({ state, now, activity, post, cfg }) {
  const cooldownMs = cfg.cooldownMs ?? 15000;

  // Decide whether to (re)open a window: no active window, or the prior window's
  // dwell + cooldown elapsed AND real activity advanced since (idle never re-bills).
  const cooled = state && now - state.startedAt >= state.dwellMs + cooldownMs;
  const activeSince = state && state.lastActivityValue !== activity;
  if (!state || (cooled && activeSince)) {
    const w = await post('/window/open', { sessionId: 'cli', activitySnapshot: 'session' });
    if (!cfg.verifyAd(w.adData, w.sig)) return refuse();   // signed content only
    let ad;
    try { ad = JSON.parse(w.adData); } catch { return refuse(); }
    if (ad.windowId !== w.windowId) return refuse();        // ad must be bound to this window
    state = {
      windowId: w.windowId, challenge: w.challenge, seq: 0, prevHash: w.windowId,
      startedAt: now, dwellMs: w.dwellMs, hbIntervalMs: w.hbIntervalMs,
      line: ad.line, label: ad.label ?? 'sponsored', clickUrl: ad.clickUrl,
      reported: false, lastActivityValue: activity,
    };
    return { state, status: adLine(state, Math.round(state.dwellMs / 1000)), clickUrl: state.clickUrl };
  }

  const elapsed = now - state.startedAt;
  if (elapsed < state.dwellMs) {
    const seq = state.seq + 1;
    const activityDelta = bucketDelta(activity, state.lastActivityValue);
    const hmac = hmacHex(state.challenge, `${seq}|${state.prevHash}|${activityDelta}`);
    await post('/window/beat', { windowId: state.windowId, seq, hmac, activityDelta });
    state = { ...state, seq, prevHash: hmac, lastActivityValue: activity };
    const left = Math.ceil((state.dwellMs - elapsed) / 1000);
    return { state, status: adLine(state, left), clickUrl: state.clickUrl };
  }

  if (!state.reported) {
    // Best-effort: the server credits at most once, so a lost response cannot double-bill.
    try { await post('/window/close', { windowId: state.windowId }); } catch { /* idempotent server */ }
    state = { ...state, reported: true };
  }
  return { state, status: null, clickUrl: null };
}
