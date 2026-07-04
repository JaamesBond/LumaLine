// test/load-harness.test.mjs — hermetic unit tests for the M6-T2 load harness's pure core
// (scripts/load/lib/{hmac-chain,metrics}.mjs). No network, no stack. The HMAC vectors are LOCKED to
// public.window_beat's server contract — if the message format or chaining drifts, every real beat
// would 400, and these tests catch it offline.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { beatHmac, buildChain, ACTIVITY_BUCKETS } from '../scripts/load/lib/hmac-chain.mjs';
import { percentile, summarize, renderSummary } from '../scripts/load/lib/metrics.mjs';

const CHALLENGE = '00112233445566778899aabbccddeeff';
const WINDOW_ID = '11111111-1111-4111-8111-111111111111';
// Locked vectors (independently reproduced via inline crypto oracle below).
const BEAT1 = '2b87b662450324ec162a082aabf40cbf6f7d0e8ff556097ecdbb9fc03251d082';
const BEAT2 = '8321cc0bc215bcde6649f19d5894c4f27ec8480dcf069c4dd9f91834e71894fa';
const BEAT3 = 'e155ec485aa440e5b907f11a960d5ec6dee5ea7c1924a25a01910debe92bb6ad';

test('H1 beatHmac matches the server message format (seq|prev|activity, keyed by challenge)', () => {
  const got = beatHmac({ seq: 1, prev: WINDOW_ID, activity: 'low', challenge: CHALLENGE });
  assert.equal(got, BEAT1);
  // independent oracle: prove it is exactly HMAC-SHA256("1|<window>|low", challenge)
  const oracle = createHmac('sha256', CHALLENGE).update(`1|${WINDOW_ID}|low`).digest('hex');
  assert.equal(got, oracle);
});

test('H2 buildChain chains prev = previous beat hmac (window_id for the first)', () => {
  const chain = buildChain({ windowId: WINDOW_ID, challenge: CHALLENGE, count: 3 });
  assert.equal(chain.length, 3);
  assert.deepEqual(chain.map((b) => b.hmac), [BEAT1, BEAT2, BEAT3]);
  assert.equal(chain[0].prev, WINDOW_ID);
  assert.equal(chain[1].prev, BEAT1); // chain head advanced
  assert.equal(chain[2].prev, BEAT2);
  // default activity: 'low' on beat 1 (sets activity_progress), 'none' after
  assert.deepEqual(chain.map((b) => b.activity), ['low', 'none', 'none']);
});

test('H3 buildChain honors a custom activityFor and seq is 1-based increasing', () => {
  const chain = buildChain({ windowId: WINDOW_ID, challenge: CHALLENGE, count: 4, activityFor: () => 'high' });
  assert.deepEqual(chain.map((b) => b.seq), [1, 2, 3, 4]);
  assert.ok(chain.every((b) => b.activity === 'high'));
});

test('H4 beatHmac rejects an invalid activity bucket', () => {
  assert.throws(() => beatHmac({ seq: 1, prev: WINDOW_ID, activity: 'bogus', challenge: CHALLENGE }), /bad activity/);
  assert.deepEqual(ACTIVITY_BUCKETS, ['none', 'low', 'med', 'high']);
});

test('M1 percentile is nearest-rank and null on empty', () => {
  assert.equal(percentile([], 50), null);
  const v = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
  assert.equal(percentile(v, 50), 50);
  assert.equal(percentile(v, 95), 100);
  assert.equal(percentile(v, 99), 100);
  assert.equal(percentile([5], 99), 5);
});

test('M2 summarize computes counts, error rate, per-op, and error histogram', () => {
  const samples = [
    { op: 'open', ok: true, ms: 10 },
    { op: 'open', ok: false, ms: 5, code: 'http_429' },
    { op: 'beat', ok: true, ms: 8 },
    { op: 'beat', ok: true, ms: 12 },
    { op: 'close', ok: false, ms: 7, code: 'P0001' },
  ];
  const r = summarize(samples, 1000);
  assert.equal(r.total_ops, 5);
  assert.equal(r.ok, 3);
  assert.equal(r.errors, 2);
  assert.equal(r.error_rate, 0.4);
  assert.equal(r.throughput_ops_s, 5); // 5 ops / 1s
  assert.equal(r.writes_per_s, 3); // ok ops only
  assert.equal(r.per_op.open.count, 2);
  assert.equal(r.per_op.open.err, 1);
  assert.equal(r.per_op.beat.p50_ms, 8); // nearest-rank over [8,12]
  assert.deepEqual(r.error_histogram, { 'open:http_429': 1, 'close:P0001': 1 });
});

test('M3 renderSummary is a readable block naming ops and errors', () => {
  const r = summarize([{ op: 'open', ok: false, ms: 5, code: 'http_429' }], 1000);
  const txt = renderSummary(r);
  assert.match(txt, /total ops 1/);
  assert.match(txt, /open:http_429: 1/);
});
