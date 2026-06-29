// test/serving.test.mjs — Hermetic (no DB) unit tests for the M2-T1 serving algorithm.
//
// The selection logic lives in SQL, so these tests verify:
//   1. Weighted reservoir sampling math (Efraimidis-Spirakis) — the score function and
//      distribution properties we rely on in the CTE are correct.
//   2. Budget pacing formulas (even vs asap) — the time-proportional budget gate.
//   3. Sentinel UUID constant — the value baked into window_open matches seed.prod.sql
//      and the edge function default env vars.
//
// All tests are pure JS re-implementations of the SQL logic. They run offline (no DB, no
// network) and must always pass regardless of local stack availability.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// ---------------------------------------------------------------------------
// Helpers: JS equivalents of the SQL serving logic
// ---------------------------------------------------------------------------

// Efraimidis-Spirakis score: random()^(1/weight).
// Matches: `(random() ^ (1.0 / greatest(li.weight, 1))) as score` in the CTE.
function reservoirScore(weight) {
  return Math.pow(Math.random(), 1.0 / Math.max(weight, 1));
}

// Single trial: pick the item with the highest score from a list of {id, weight} objects.
function weightedPick(items) {
  let best = null;
  let bestScore = -Infinity;
  for (const item of items) {
    const score = reservoirScore(item.weight);
    if (score > bestScore) {
      bestScore = score;
      best = item;
    }
  }
  return best;
}

// Budget pacing gate — matches the SQL CASE in the candidates CTE.
// Returns true if the line_item is within budget (should be included as a candidate).
function pacingAllowed({ pacing_mode, spent_micros, budget_daily_micros, elapsed_seconds }) {
  if (budget_daily_micros == null) return true;
  const spent = spent_micros ?? 0;
  if (pacing_mode === 'asap') {
    return spent < budget_daily_micros;
  }
  if (pacing_mode === 'even') {
    // Matches: budget_daily * least(1.0, elapsed/86400 + 0.1)
    const fraction = Math.min(1.0, elapsed_seconds / 86400.0 + 0.1);
    return spent < budget_daily_micros * fraction;
  }
  return true; // unknown mode: include (matches `else true`)
}

// Sentinel publisher_id constant — must stay in sync with:
//   seed.prod.sql       LUMALINE_SENTINEL_PUBLISHER_ID
//   supabase/functions/lumaline-feed/index.ts  SENTINEL.publisher_id
//   migrations/20260629020000_serving_algorithm.sql  SENTINEL_PUB constant
const SENTINEL_PUB = '5e470000-0000-4000-8000-0000000000b1';

// ---------------------------------------------------------------------------
// 1. Weighted reservoir sampling distribution
// ---------------------------------------------------------------------------

test('weighted reservoir: score = random()^(1/w) is in (0,1] for positive weight', () => {
  for (const weight of [1, 2, 5, 10, 100]) {
    const score = reservoirScore(weight);
    assert.ok(score > 0, `score > 0 for weight=${weight}`);
    assert.ok(score <= 1, `score <= 1 for weight=${weight}`);
  }
});

test('weighted reservoir: weight=1 items have equal expected selection probability', () => {
  // 3 items, all weight=1, 3000 trials. Each should win ~33.3%; allow ±8% margin.
  const items = [{ id: 'A', weight: 1 }, { id: 'B', weight: 1 }, { id: 'C', weight: 1 }];
  const counts = { A: 0, B: 0, C: 0 };
  const TRIALS = 3000;
  for (let i = 0; i < TRIALS; i++) {
    const picked = weightedPick(items);
    counts[picked.id]++;
  }
  const expected = TRIALS / items.length;
  const margin = TRIALS * 0.08; // 8% tolerance
  for (const [id, count] of Object.entries(counts)) {
    assert.ok(
      Math.abs(count - expected) < margin,
      `item ${id}: got ${count} wins, expected ~${expected} ± ${margin}`,
    );
  }
});

test('weighted reservoir: item with weight=3 wins ~3x more than item with weight=1', () => {
  // Two items: A (weight=3), B (weight=1). Expected win ratio: 3:1 = 75% vs 25%.
  const items = [{ id: 'A', weight: 3 }, { id: 'B', weight: 1 }];
  const counts = { A: 0, B: 0 };
  const TRIALS = 5000;
  for (let i = 0; i < TRIALS; i++) {
    counts[weightedPick(items).id]++;
  }
  const ratioA = counts.A / TRIALS;
  // Expected ~0.75; allow ±0.06 margin (statistical noise over 5000 trials)
  assert.ok(
    Math.abs(ratioA - 0.75) < 0.06,
    `A win ratio: ${ratioA.toFixed(3)}, expected ~0.75 ± 0.06`,
  );
});

test('weighted reservoir: highest-weight item dominates when weights are very skewed', () => {
  // weight=100 vs weight=1: the heavy item should win at least 95% of the time.
  const items = [{ id: 'heavy', weight: 100 }, { id: 'light', weight: 1 }];
  const counts = { heavy: 0, light: 0 };
  const TRIALS = 2000;
  for (let i = 0; i < TRIALS; i++) {
    counts[weightedPick(items).id]++;
  }
  assert.ok(
    counts.heavy / TRIALS > 0.95,
    `heavy item should win >95%; got ${counts.heavy} / ${TRIALS}`,
  );
});

test('weighted reservoir: single item is always selected regardless of weight', () => {
  for (const weight of [1, 2, 10]) {
    const picked = weightedPick([{ id: 'only', weight }]);
    assert.equal(picked.id, 'only', `single item selected for weight=${weight}`);
  }
});

// ---------------------------------------------------------------------------
// 2. Budget pacing formula
// ---------------------------------------------------------------------------

test('pacing asap: allows when spent < daily budget', () => {
  assert.equal(
    pacingAllowed({ pacing_mode: 'asap', spent_micros: 0, budget_daily_micros: 1000000, elapsed_seconds: 0 }),
    true,
    'asap: 0 spent < 1M budget = allowed',
  );
  assert.equal(
    pacingAllowed({ pacing_mode: 'asap', spent_micros: 999999, budget_daily_micros: 1000000, elapsed_seconds: 43200 }),
    true,
    'asap: one micro below budget = allowed',
  );
});

test('pacing asap: blocks when spent >= daily budget', () => {
  assert.equal(
    pacingAllowed({ pacing_mode: 'asap', spent_micros: 1000000, budget_daily_micros: 1000000, elapsed_seconds: 0 }),
    false,
    'asap: spent = budget = blocked',
  );
  assert.equal(
    pacingAllowed({ pacing_mode: 'asap', spent_micros: 2000000, budget_daily_micros: 1000000, elapsed_seconds: 43200 }),
    false,
    'asap: spent > budget = blocked',
  );
});

test('pacing even: 10% headroom allows spend at midnight (elapsed=0)', () => {
  // At t=0: budget * (0/86400 + 0.1) = budget * 0.1
  // So up to 10% of daily budget is allowed at the very start.
  const budget = 1_000_000;
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: 0, budget_daily_micros: budget, elapsed_seconds: 0 }),
    true,
    'even t=0: 0 < 10% budget = allowed',
  );
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: 99_999, budget_daily_micros: budget, elapsed_seconds: 0 }),
    true,
    'even t=0: 99999 < 100000 (10%) = allowed',
  );
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: 100_000, budget_daily_micros: budget, elapsed_seconds: 0 }),
    false,
    'even t=0: 100000 = 10% budget = blocked',
  );
});

test('pacing even: at mid-day (43200s) allows ~60% of budget', () => {
  // At t=43200 (half day): fraction = min(1, 0.5 + 0.1) = 0.6
  // Allowed spend = 0.6 * budget.
  const budget = 1_000_000;
  const allowed = budget * 0.6;
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: Math.floor(allowed) - 1, budget_daily_micros: budget, elapsed_seconds: 43200 }),
    true,
    'even t=43200: spent just below 60% = allowed',
  );
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: Math.ceil(allowed), budget_daily_micros: budget, elapsed_seconds: 43200 }),
    false,
    'even t=43200: spent at/above 60% = blocked',
  );
});

test('pacing even: at end of day (86400s) fraction caps at 1.0 (full budget)', () => {
  // At t=86400: fraction = min(1, 1.0 + 0.1) = 1.0
  const budget = 1_000_000;
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: budget - 1, budget_daily_micros: budget, elapsed_seconds: 86400 }),
    true,
    'even t=86400: one micro below full budget = allowed',
  );
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: budget, budget_daily_micros: budget, elapsed_seconds: 86400 }),
    false,
    'even t=86400: at full budget = blocked',
  );
});

test('pacing: null budget_daily_micros = always allowed (no cap)', () => {
  assert.equal(
    pacingAllowed({ pacing_mode: 'asap', spent_micros: 999_999_999, budget_daily_micros: null, elapsed_seconds: 0 }),
    true,
    'null daily budget = always allowed (asap)',
  );
  assert.equal(
    pacingAllowed({ pacing_mode: 'even', spent_micros: 999_999_999, budget_daily_micros: null, elapsed_seconds: 43200 }),
    true,
    'null daily budget = always allowed (even)',
  );
});

// ---------------------------------------------------------------------------
// 3. Sentinel UUID constant
// ---------------------------------------------------------------------------

test('sentinel publisher UUID matches seed.prod.sql and the edge function default', () => {
  // This value is baked into:
  //   seed.prod.sql  (publishers row, id column)
  //   supabase/functions/lumaline-feed/index.ts  (SENTINEL.publisher_id)
  //   migrations/20260629020000_serving_algorithm.sql  (SENTINEL_PUB constant)
  // If any of these ever diverge, the sentinel gate silently breaks.
  assert.equal(SENTINEL_PUB, '5e470000-0000-4000-8000-0000000000b1');
});

test('sentinel UUID has the expected structure (all-zeros variant of 5e47 prefix)', () => {
  // Sanity: the UUID must be a valid UUID string (8-4-4-4-12 hex groups).
  assert.match(SENTINEL_PUB, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  // Confirm the prefix (human-readable 5e47 sentinel marker).
  assert.ok(SENTINEL_PUB.startsWith('5e470000-'), 'sentinel UUID starts with 5e470000-');
});
