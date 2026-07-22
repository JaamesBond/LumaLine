// test/sec-monitor-chargeback.test.mjs — SECURITY-AUDIT HARDENING (A9). Pure decision function for
// the new money-path monitor check `postpay_chargeback` in
// supabase/functions/_shared/monitor-logic.mjs.
//
// Hermetic: `node --test`, node: builtins only. The export is NEW -> pre-fix the import is
// undefined and calling it throws (fail-before); post-fix it passes. A postpay CPVA PaymentIntent
// disputed after settlement is money already lost — the monitor must surface it (one HIGH alert per
// dispute id) and auto-resolve once the row ages out of the 24h window.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  evalPostpayChargebacks,
  CHECK_NAMES,
} from '../supabase/functions/_shared/monitor-logic.mjs';

test('sec A9: postpay_chargeback is a registered check name', () => {
  assert.ok(CHECK_NAMES.includes('postpay_chargeback'));
});

test('sec A9: empty window => pass, no alerts', () => {
  const r = evalPostpayChargebacks([]);
  assert.equal(r.name, 'postpay_chargeback');
  assert.equal(r.status, 'pass');
  assert.deepEqual(r.alerts, []);
});

test('sec A9: non-array input is tolerated as empty => pass', () => {
  assert.equal(evalPostpayChargebacks(undefined).status, 'pass');
  assert.equal(evalPostpayChargebacks(null).status, 'pass');
});

test('sec A9: two disputes => fail with two HIGH alerts, dedup key per dispute id', () => {
  const rows = [
    { dispute_id: 'du_1', advertiser_id: 'adv_a', amount_micros: 1_100_000, created_at: '2026-07-22T10:00:00Z' },
    { dispute_id: 'du_2', advertiser_id: 'adv_b', amount_micros: 5_000_000, created_at: '2026-07-22T11:00:00Z' },
  ];
  const r = evalPostpayChargebacks(rows);
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts.length, 2);
  for (const a of r.alerts) {
    assert.equal(a.check_name, 'postpay_chargeback');
    assert.equal(a.severity, 'high');
  }
  assert.deepEqual(r.alerts.map((a) => a.dedup_key), ['dispute:du_1', 'dispute:du_2']);
  assert.equal(r.alerts[0].payload.advertiser_id, 'adv_a');
  assert.equal(r.alerts[0].payload.amount_micros, 1_100_000);
});

test('sec A9: missing dispute_id degrades dedup key to dispute:unknown (still fires)', () => {
  const r = evalPostpayChargebacks([{ advertiser_id: 'adv_x' }]);
  assert.equal(r.status, 'fail');
  assert.equal(r.alerts[0].dedup_key, 'dispute:unknown');
  assert.equal(r.alerts[0].payload.dispute_id, null);
});
