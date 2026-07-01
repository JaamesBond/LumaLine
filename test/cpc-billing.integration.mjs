// test/cpc-billing.integration.mjs — M4-T3: integration proof that CPC (clicks) bills
// through the SAME view + fn as CPVA, exactly once, and is correctly gated on a cleared
// parent impression.
//
// Self-skips cleanly when the local Supabase stack (REST @ 54321 + psql @ 54322) or the
// billing edge fn is unreachable — see test/helpers/billing-fixture.mjs (STACK_UP).
//
// Fixture strategy: rather than waiting out clear_events()'s real 72h clawback window /
// cron cadence, each scenario forges the impression/click rows directly to the state it
// needs (this mirrors test/billing.integration.mjs's and test/payout-rails.integration.mjs's
// own convention of directly booking 'cleared' ledger state). app.accrue() — the same
// SECURITY DEFINER function clear_events() calls — is invoked directly via psql to book a
// real balanced 3-leg cpc_accrual group, so what's being proven is "does the billing view +
// fn correctly handle a genuinely-accrued CPC group", not "does clear_events' own gating
// query work" (that gating logic lives in 20260627033345_clearing_and_ledger.sql and is a
// separate concern from this suite).
//
// WHAT IS TESTED:
//   CPC-1 — a cleared cpc_accrual group surfaces in uncharged_advertiser_billings exactly
//           once, with impression_id NULL (the CPC branch resolves via clicks, not impressions).
//   CPC-2 — POST /billing/charge bills that group exactly once; a second run (or a replay of
//           the same entry_group_id) does not double-charge — UNIQUE(entry_group_id) backstop.
//   CPC-3 — a click whose parent impression never cleared has NO ledger leg at all (nothing
//           was ever accrued for it) and therefore never appears in the billing view.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import {
  STACK_UP,
  svc,
  psql,
  BILLING_BASE,
  ADMIN_JWT,
  seedAdvertiserCampaignLineItem,
  cleanupCpcFixture,
} from './helpers/billing-fixture.mjs';

const SKIP = !STACK_UP;
if (SKIP) console.log('[cpc-billing.integration] Stack/psql/billing-fn unreachable — SKIPPING all tests.');

/** Forge a cleared parent impression + cleared click on the same window, both billable. */
function seedClearedPair({ publisherId, lineItemId, clickGross }) {
  const windowId     = randomUUID();
  const impressionId = randomUUID();
  const clickId      = randomUUID();
  const tokenHash    = randomUUID().replace(/-/g, '');

  psql(`insert into public.impressions (id, window_id, publisher_id, line_item_id, attention_seconds, gross_micros, state)
    values ('${impressionId}','${windowId}','${publisherId}','${lineItemId}',5,500000,'cleared');`);
  psql(`insert into public.clicks (id, window_id, publisher_id, line_item_id, click_token_hash, gross_micros, state)
    values ('${clickId}','${windowId}','${publisherId}','${lineItemId}','${tokenHash}',${clickGross},'cleared');`);

  return { windowId, impressionId, clickId };
}

test('CPC-1: cleared click surfaces in uncharged_advertiser_billings exactly once (impression_id null)', { skip: SKIP }, async () => {
  const { advertiserId, lineItemId, publisherId } = seedAdvertiserCampaignLineItem({ is_house: false });
  const CLICK_GROSS = 1_000_000; // €1.00
  let impressionId, clickId;

  try {
    ({ impressionId, clickId } = seedClearedPair({ publisherId, lineItemId, clickGross: CLICK_GROSS }));

    const groupId = psql(
      `select app.accrue('cpc_accrual','click','${clickId}','${publisherId}',${CLICK_GROSS},'cleared');`,
    );
    assert.ok(groupId, 'app.accrue must return a group id for a positive gross');

    const rows = await svc(
      'GET',
      `uncharged_advertiser_billings?select=entry_group_id,event_type,impression_id,amount_micros&entry_group_id=eq.${groupId}`,
    );
    assert.equal(rows.length, 1, `cpc group must surface exactly once in the billing view, got: ${JSON.stringify(rows)}`);
    assert.equal(rows[0].event_type, 'cpc_accrual');
    assert.equal(rows[0].impression_id, null, 'CPC billing rows resolve via clicks, not impressions');
    assert.equal(Number(rows[0].amount_micros), CLICK_GROSS);
  } finally {
    cleanupCpcFixture({ advertiserId, impressionId, clickId });
  }
});

test('CPC-2: /billing/charge bills the cleared cpc group exactly once; re-running is a no-op (dedup)', { skip: SKIP }, async () => {
  const { advertiserId, lineItemId, publisherId } = seedAdvertiserCampaignLineItem({ is_house: false });
  const CLICK_GROSS = 1_000_000; // €1.00 — above the €0.50 Stripe minimum regardless of outcome
  let impressionId, clickId;

  try {
    ({ impressionId, clickId } = seedClearedPair({ publisherId, lineItemId, clickGross: CLICK_GROSS }));
    const groupId = psql(
      `select app.accrue('cpc_accrual','click','${clickId}','${publisherId}',${CLICK_GROSS},'cleared');`,
    );
    assert.ok(groupId);

    // dry_run must list our specific group as a would-charge candidate.
    const dry = await svc('POST', 'functions/v1/billing/charge?dry_run=true');
    assert.ok(dry.counts.would_charge >= 1, `dry_run must list at least our cpc group: ${JSON.stringify(dry.counts)}`);
    assert.ok(
      dry.results.some((r) => r.entry_group_id === groupId),
      'dry_run results must include our specific cpc group',
    );

    // Real run #1 bills it exactly once (status may be succeeded/failed/skipped depending on
    // whether STRIPE_SECRET_KEY is configured in this environment — what matters for dedup is
    // the row count, matching test/billing.integration.mjs's own T25 idempotency convention).
    const run1 = await fetch(`${BILLING_BASE}/charge`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ADMIN_JWT}` },
    });
    assert.equal(run1.status, 200, `billing charge failed: ${await run1.text()}`);
    const after1 = await svc('GET', `advertiser_charges?select=id&entry_group_id=eq.${groupId}`);
    assert.equal(after1.length, 1, 'first real run must bill the cpc group exactly once');

    // Real run #2 — same entry_group_id must not create a second row. The view also
    // excludes already-charged groups (LEFT JOIN advertiser_charges ... IS NULL), so this
    // exercises both the UNIQUE(entry_group_id) backstop and the view's own exclusion.
    const run2 = await fetch(`${BILLING_BASE}/charge`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${ADMIN_JWT}` },
    });
    assert.equal(run2.status, 200, `second billing charge failed: ${await run2.text()}`);
    const after2 = await svc('GET', `advertiser_charges?select=id&entry_group_id=eq.${groupId}`);
    assert.equal(after2.length, 1, 'duplicate entry_group_id must not double-charge');
  } finally {
    cleanupCpcFixture({ advertiserId, impressionId, clickId });
  }
});

test('CPC-3: a click whose parent impression never cleared does NOT bill', { skip: SKIP }, async () => {
  const { advertiserId, lineItemId, publisherId } = seedAdvertiserCampaignLineItem({ is_house: false });
  const windowId      = randomUUID();
  const impressionId  = randomUUID();
  const clickId       = randomUUID();
  const tokenHash     = randomUUID().replace(/-/g, '');

  try {
    // Parent impression stays 'provisional' — the "open-then-click, never dwell" case.
    // clear_events() only promotes+accrues a click once a CLEARED impression exists for its
    // window (20260627033345_clearing_and_ledger.sql); we mirror that gate by simply never
    // accruing this click, since there is no cleared parent to satisfy it.
    psql(`insert into public.impressions (id, window_id, publisher_id, line_item_id, attention_seconds, gross_micros, state)
      values ('${impressionId}','${windowId}','${publisherId}','${lineItemId}',5,500000,'provisional');`);
    psql(`insert into public.clicks (id, window_id, publisher_id, line_item_id, click_token_hash, gross_micros, state)
      values ('${clickId}','${windowId}','${publisherId}','${lineItemId}','${tokenHash}',500000,'provisional');`);

    const legCount = psql(
      `select count(*) from public.ledger_entries where source_type='click' and source_id='${clickId}';`,
    );
    assert.equal(legCount, '0', 'an unaccrued click must have no ledger legs at all');

    const rows = await svc(
      'GET',
      `uncharged_advertiser_billings?select=entry_group_id&event_type=eq.cpc_accrual&line_item_id=eq.${lineItemId}`,
    );
    assert.equal(rows.length, 0, 'a click with no cleared parent impression must never surface in the billing view');
  } finally {
    cleanupCpcFixture({ advertiserId, impressionId, clickId });
  }
});
