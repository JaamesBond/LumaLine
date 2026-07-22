// Pure, dependency-free fixed-window in-memory rate limiter. Per-isolate fallback used by the edge
// functions when the durable salted-IP DB limiter (rl_hit) is unconfigured/unavailable. Keyed by an
// opaque string (the edge keys it by raw client IP, kept only in this Map, never persisted). NOT a
// security control — a cost/abuse floor. Deterministic (caller supplies `now`) so node --test can
// exercise it without timers.
export function createMemoryLimiter({ max = 60, windowMs = 60000 } = {}) {
  const buckets = new Map(); // key -> { start, count }
  return {
    // true = allowed, false = over budget for the current window.
    hit(key, now) {
      if (!key) return true;                         // no signal -> caller decides
      const b = buckets.get(key);
      if (!b || now - b.start >= windowMs) {         // new / expired window
        buckets.set(key, { start: now, count: 1 });
        // opportunistic prune so the Map can't grow unbounded on a busy isolate
        if (buckets.size > 10000) this.prune(now);
        return true;
      }
      b.count += 1;
      return b.count <= max;
    },
    prune(now) { for (const [k, b] of buckets) if (now - b.start >= windowMs) buckets.delete(k); },
    size() { return buckets.size; },
  };
}
