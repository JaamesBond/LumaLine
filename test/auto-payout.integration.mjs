// test/auto-payout.integration.mjs — needs local stack + `supabase functions serve stripe-connect`.
import test from 'node:test';
import assert from 'node:assert/strict';

const FN = process.env.STRIPE_CONNECT_URL || 'http://127.0.0.1:54321/functions/v1/stripe-connect';
async function up() { try { const r = await fetch(`${FN}/payout/batch`, { method: 'OPTIONS', signal: AbortSignal.timeout(2000) }); return r.status === 200; } catch { return false; } }
const SKIP = !(await up()) ? 'stripe-connect fn not served — SKIPPING' : false;
if (SKIP) console.log(`[auto-payout.integration] ${SKIP}`);

test('payout/batch: bad cron secret is rejected (403)', { skip: SKIP }, async () => {
  const r = await fetch(`${FN}/payout/batch?dry_run=true`, { method: 'POST', headers: { 'x-lumaline-cron-secret': 'wrong', 'content-type': 'application/json' }, body: '{}' });
  assert.equal(r.status, 403);
});

test('payout/batch: valid cron secret authorizes the dry-run', { skip: SKIP || !process.env.LUMALINE_CRON_SECRET }, async () => {
  const r = await fetch(`${FN}/payout/batch?dry_run=true`, { method: 'POST', headers: { 'x-lumaline-cron-secret': process.env.LUMALINE_CRON_SECRET, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(r.status, 200);
  const b = await r.json();
  assert.equal(b.ok, true); assert.equal(b.dry_run, true);
});
