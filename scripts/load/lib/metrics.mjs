// Pure load-test metrics: latency percentiles, throughput, error taxonomy. No I/O — the harness
// feeds it recorded samples and it renders the summary. Hermetically tested (test/load-harness.test.mjs).

// Nearest-rank percentile over a numeric array (p in [0,100]). Empty -> null.
export function percentile(values, p) {
  if (!values || values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * sorted.length);
  const idx = Math.min(sorted.length - 1, Math.max(0, rank - 1));
  return sorted[idx];
}

/**
 * summarize(samples, durationMs) -> report.
 * samples: [{ op, ok, ms, code }]   op ∈ {open,beat,close}; code = error class on failure.
 * Reports overall + per-op: count, ok/err, throughput (ops/s over durationMs), latency
 * percentiles (over ok samples only), and an error histogram by (op, code).
 */
export function summarize(samples, durationMs) {
  const secs = durationMs > 0 ? durationMs / 1000 : 0;
  const ops = samples.length;
  const okSamples = samples.filter((s) => s.ok);
  const errSamples = samples.filter((s) => !s.ok);

  const perOp = {};
  for (const op of ['open', 'beat', 'close']) {
    const forOp = samples.filter((s) => s.op === op);
    const okOp = forOp.filter((s) => s.ok).map((s) => s.ms);
    perOp[op] = {
      count: forOp.length,
      ok: forOp.filter((s) => s.ok).length,
      err: forOp.filter((s) => !s.ok).length,
      throughput_ops_s: secs ? +(forOp.length / secs).toFixed(1) : null,
      p50_ms: percentile(okOp, 50),
      p95_ms: percentile(okOp, 95),
      p99_ms: percentile(okOp, 99),
      max_ms: okOp.length ? Math.max(...okOp) : null,
    };
  }

  const errorHistogram = {};
  for (const s of errSamples) {
    const key = `${s.op}:${s.code || 'unknown'}`;
    errorHistogram[key] = (errorHistogram[key] || 0) + 1;
  }

  return {
    duration_ms: durationMs,
    total_ops: ops,
    ok: okSamples.length,
    errors: errSamples.length,
    error_rate: ops ? +(errSamples.length / ops).toFixed(4) : 0,
    throughput_ops_s: secs ? +(ops / secs).toFixed(1) : null,
    writes_per_s: secs ? +(okSamples.length / secs).toFixed(1) : null, // each ok RPC = >=1 DB write
    per_op: perOp,
    error_histogram: errorHistogram,
  };
}

// Render a summary as a compact text block.
export function renderSummary(r) {
  const ms = (x) => (x == null ? '—' : (Math.round(x * 10) / 10) + 'ms');
  const L = [];
  L.push(`total ops ${r.total_ops}  ok ${r.ok}  err ${r.errors} (${(r.error_rate * 100).toFixed(2)}%)  over ${(r.duration_ms / 1000).toFixed(1)}s`);
  L.push(`throughput ${r.throughput_ops_s} ops/s  |  successful writes ${r.writes_per_s}/s`);
  for (const op of ['open', 'beat', 'close']) {
    const o = r.per_op[op];
    L.push(`  ${op.padEnd(5)} n=${o.count} ok=${o.ok} err=${o.err}  p50=${ms(o.p50_ms)} p95=${ms(o.p95_ms)} p99=${ms(o.p99_ms)}`);
  }
  const eh = Object.entries(r.error_histogram);
  if (eh.length) {
    L.push('  errors:');
    for (const [k, v] of eh.sort((a, b) => b[1] - a[1])) L.push(`    ${k}: ${v}`);
  }
  return L.join('\n');
}
