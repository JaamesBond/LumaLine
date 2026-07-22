// test/sec-payout-transfer-scan.test.mjs — SECURITY-AUDIT HARDENING (A13). Pure paginating scan for
// an orphaned Stripe transfer by metadata.payout_id (supabase/functions/_shared/payout-logic.mjs).
//
// Hermetic: `node --test`, node: builtins only, no Stripe. `listFn` is injected as a fake page
// source. The export is NEW -> pre-fix the import is undefined (fail-before); post-fix it passes.
//
// THE A13 EXPLOIT: a >24h-old orphaned transfer beyond the last 100 destination transfers must
// still be FOUND (never re-created = double-pay). The pre-fix single-page (limit 100) scan would
// miss it and re-issue the transfer. This helper walks ALL pages via has_more/starting_after.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findTransferIdByMetadata } from '../supabase/functions/_shared/payout-logic.mjs';

// Build a fake listFn over an array of transfers, paginating `pageSize` at a time and honoring
// starting_after (cursor = transfer id). Records the params of every call for assertions.
function fakeStripeList(allTransfers, pageSize = 100) {
  const calls = [];
  const listFn = async (params) => {
    calls.push(params);
    let start = 0;
    if (params.starting_after) {
      const idx = allTransfers.findIndex((t) => t.id === params.starting_after);
      start = idx + 1;
    }
    const data = allTransfers.slice(start, start + pageSize);
    const has_more = start + pageSize < allTransfers.length;
    return { data, has_more };
  };
  return { listFn, calls };
}

test('sec A13: finds an orphan on the FIRST page', async () => {
  const transfers = [
    { id: 'tr_1', metadata: { payout_id: 'po_other' } },
    { id: 'tr_2', metadata: { payout_id: 'po_target' } },
  ];
  const { listFn } = fakeStripeList(transfers);
  const id = await findTransferIdByMetadata(listFn, { destination: 'acct_1', payoutId: 'po_target' });
  assert.equal(id, 'tr_2');
});

test('sec A13: finds an orphan BEYOND the first 100 (walks to page 2) — the core fix', async () => {
  // 150 decoy transfers, then the real orphan at index 150 (page 2). A single-page scan misses it.
  const transfers = [];
  for (let i = 0; i < 150; i++) transfers.push({ id: `tr_decoy_${i}`, metadata: { payout_id: `po_x_${i}` } });
  transfers.push({ id: 'tr_orphan', metadata: { payout_id: 'po_target' } });
  const { listFn, calls } = fakeStripeList(transfers, 100);
  const id = await findTransferIdByMetadata(listFn, { destination: 'acct_1', payoutId: 'po_target' });
  assert.equal(id, 'tr_orphan');
  assert.ok(calls.length >= 2, 'must paginate past the first page');
  // page 2 was fetched with the last id of page 1 as the cursor
  assert.equal(calls[1].starting_after, 'tr_decoy_99');
});

test('sec A13: returns null when no transfer matches (exhausts all pages, no infinite loop)', async () => {
  const transfers = [];
  for (let i = 0; i < 250; i++) transfers.push({ id: `tr_${i}`, metadata: { payout_id: `po_${i}` } });
  const { listFn, calls } = fakeStripeList(transfers, 100);
  const id = await findTransferIdByMetadata(listFn, { destination: 'acct_1', payoutId: 'po_none' });
  assert.equal(id, null);
  assert.equal(calls.length, 3); // 100 + 100 + 50, then has_more=false
});

test('sec A13: passes destination + limit + created lower bound through to Stripe', async () => {
  const { listFn, calls } = fakeStripeList([], 100);
  await findTransferIdByMetadata(listFn, { destination: 'acct_9', payoutId: 'po_1', createdGteUnix: 1_700_000_000 });
  assert.equal(calls[0].destination, 'acct_9');
  assert.equal(calls[0].limit, 100);
  assert.deepEqual(calls[0].created, { gte: 1_700_000_000 });
});

test('sec A13: tolerates transfers with no metadata (skips, never throws)', async () => {
  const transfers = [
    { id: 'tr_a' },                                  // no metadata
    { id: 'tr_b', metadata: {} },                    // empty metadata
    { id: 'tr_c', metadata: { payout_id: 'po_hit' } },
  ];
  const { listFn } = fakeStripeList(transfers);
  const id = await findTransferIdByMetadata(listFn, { destination: 'acct_1', payoutId: 'po_hit' });
  assert.equal(id, 'tr_c');
});

test('sec A13: empty first page returns null immediately (no cursor churn)', async () => {
  const { listFn, calls } = fakeStripeList([], 100);
  const id = await findTransferIdByMetadata(listFn, { destination: 'acct_1', payoutId: 'po_x' });
  assert.equal(id, null);
  assert.equal(calls.length, 1);
});
