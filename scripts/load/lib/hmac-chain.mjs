// Synthetic-client heartbeat HMAC chain — must byte-match public.window_beat's server check
// (supabase/migrations/20260627025330_window_rpcs.sql). The load harness (M6-T2) drives honest
// windows, so it has to produce the exact hash-chain the server recomputes, or every beat 400s.
//
// Server contract (from the SQL):
//   msg      = format('%s|%s|%s', seq, prev, activity_delta)
//   hmac     = encode(hmac(msg, challenge, 'sha256'), 'hex')
//   prev     = coalesce(prev_hash, window_id::text)   -- prev_hash is the PREVIOUS beat's hmac
//   seq      = beats_count + 1                          -- 1-based, strictly increasing
//   spacing  = >=500ms wall-clock between beats (anti-batch) — enforced by the harness scheduler
//   activity ∈ {none, low, med, high}; at least one non-'none' beat sets activity_progress
//
// Pure + dependency-free (node:crypto only) so test/load-harness.test.mjs can pin it hermetically.
import { createHmac } from 'node:crypto';

export const ACTIVITY_BUCKETS = ['none', 'low', 'med', 'high'];

// One beat's HMAC. prev = previous beat's hmac hex, or the window_id string for seq 1.
export function beatHmac({ seq, prev, activity, challenge }) {
  if (!ACTIVITY_BUCKETS.includes(activity)) throw new Error(`bad activity bucket: ${activity}`);
  const msg = `${seq}|${prev}|${activity}`;
  return createHmac('sha256', challenge).update(msg).digest('hex');
}

/**
 * Build the full chain of `count` beats for a window.
 * Returns [{ seq, prev, activity, hmac }] where each beat's `prev` is the prior beat's hmac
 * (or window_id for the first), exactly as the server derives it.
 * `activityFor(seq)` picks the bucket per beat (default: 'low' on beat 1 so activity_progress
 * is set, 'none' thereafter — the minimum that credits).
 */
export function buildChain({ windowId, challenge, count, activityFor }) {
  const pick = activityFor || ((seq) => (seq === 1 ? 'low' : 'none'));
  const beats = [];
  let prev = String(windowId);
  for (let seq = 1; seq <= count; seq++) {
    const activity = pick(seq);
    const hmac = beatHmac({ seq, prev, activity, challenge });
    beats.push({ seq, prev, activity, hmac });
    prev = hmac; // chain head advances to this beat's hmac
  }
  return beats;
}
