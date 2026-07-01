import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const migDir = fileURLToPath(new URL('../supabase/migrations/', import.meta.url));
const cpcMig = readdirSync(migDir).find((f) => f.endsWith('_cpc_billing.sql'));
const sql = cpcMig ? readFileSync(migDir + cpcMig, 'utf8') : '';

test('cpc_billing migration exists', () => {
  assert.ok(cpcMig, 'expected a *_cpc_billing.sql migration');
});
test('billing view has a clicks-sourced cpc branch', () => {
  assert.match(sql, /JOIN public\.clicks\s+cl\s+ON cl\.id = le\.source_id/);
  assert.match(sql, /event_type = 'cpc_accrual'/);
});
test('recon totals include cpc_accrual', () => {
  assert.match(sql, /event_type IN \('cpva_accrual', 'cpc_accrual'\)/);
});
test('payable fn no longer RAISEs the loud CPC guard', () => {
  assert.doesNotMatch(sql, /refusing to underpay/);
  assert.match(sql, /v_earned_cpc/);
});
test('view re-asserts security_invoker + service_role-only', () => {
  assert.match(sql, /security_invoker = on/);
  assert.match(sql, /REVOKE ALL ON public\.uncharged_advertiser_billings FROM anon, authenticated/);
});
