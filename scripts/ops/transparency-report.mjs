#!/usr/bin/env node
// LumaLine public transparency report generator (M6-T5) — READ-ONLY.
// Pulls aggregate, non-identifying figures from the live DB (one management-API SELECT), builds the
// public report via the pure lib, PROVES it reconciles to the double-entry ledger and asserts it
// carries no PII / no raw cost-token-activity signal, then prints it (and optionally writes docs/).
//
// The aggregation, reconciliation, and non-PII guard live in ./lib/transparency.mjs and are unit
// tested offline (test/transparency-report.test.mjs). This wrapper only does the read + I/O.
// Not shipped to npm. Exit code is non-zero if reconciliation fails or PII is detected.
//
//   node scripts/ops/transparency-report.mjs            print Markdown
//   node scripts/ops/transparency-report.mjs --json     print the JSON report
//   node scripts/ops/transparency-report.mjs --write     also write docs/transparency-report.{md,json}
//   node scripts/ops/transparency-report.mjs --check     assert-only (reconcile + non-PII), print PASS/FAIL
import { readFileSync, writeFileSync } from 'node:fs';
import { buildReport, assertNonPII, toMarkdown } from './lib/transparency.mjs';

const ENV = readFileSync(new URL('../../.env', import.meta.url), 'utf8');
const get = (k) => (ENV.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim();
const REF = get('SUPABASE_PROJECTID_REMOTE') || 'prmsonskzrubqsazmpwd';
const PAT = get('SUPABASE_ACCESS_TOKEN_REMOTE');
if (REF !== 'prmsonskzrubqsazmpwd') { console.error(`FATAL: ref mismatch: ${REF}`); process.exit(2); }
if (!PAT) { console.error('FATAL: no SUPABASE_ACCESS_TOKEN_REMOTE in .env'); process.exit(2); }

const argv = new Set(process.argv.slice(2));

const INPUT_SQL = `
select jsonb_build_object(
  'ledger', (select coalesce(jsonb_agg(jsonb_build_object(
       'account',account,'state',state,'event_type',event_type,'amount_micros',amt,'n',n)),'[]') from (
     select account, state, event_type, sum(amount_micros) amt, count(*) n
     from public.ledger_entries group by account, state, event_type) x),
  'ledger_global_sum_micros', (select coalesce(sum(amount_micros),0) from public.ledger_entries),
  'unbalanced_group_count', (select count(*) from (
     select entry_group_id from public.ledger_entries group by entry_group_id having sum(amount_micros)<>0) u),
  'windows', (select coalesce(jsonb_object_agg(state, n),'{}') from (
     select state, count(*) n from public.ad_windows group by state) x),
  'impressions', (select coalesce(jsonb_agg(jsonb_build_object(
       'state',state,'n',n,'billable_n',billable_n,'gross_micros',gross,'attention_seconds',att)),'[]') from (
     select state, count(*) n, count(*) filter (where gross_micros>0) billable_n,
            coalesce(sum(gross_micros),0) gross, coalesce(sum(attention_seconds),0) att
     from public.impressions group by state) x),
  'clicks_credited', (select count(*) from public.clicks where state in ('provisional','cleared'))
) as input`;

async function sql(query) {
  const r = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${PAT}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  if (!r.ok) throw new Error(`SQL ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

const [{ input }] = await sql(INPUT_SQL);
const report = buildReport({ ...input, generated_at: new Date().toISOString() });
assertNonPII(report); // throws -> non-zero exit if any identifying/cost/token field slipped in

if (!report.reconciliation.all_ok) {
  console.error('RECONCILE FAIL:', JSON.stringify(report.reconciliation, null, 2));
  if (argv.has('--check')) { console.log('FAIL'); process.exit(1); }
  process.exitCode = 1; // still print below so the operator sees the numbers
}

if (argv.has('--check')) {
  console.log(report.reconciliation.all_ok ? 'PASS — reconciles to ledger, no PII' : 'FAIL');
  process.exit(report.reconciliation.all_ok ? 0 : 1);
}

const md = toMarkdown(report);
if (argv.has('--json')) console.log(JSON.stringify(report, null, 2));
else console.log(md);

if (argv.has('--write')) {
  const mdPath = new URL('../../docs/transparency-report.md', import.meta.url);
  const jsonPath = new URL('../../docs/transparency-report.json', import.meta.url);
  writeFileSync(mdPath, md);
  writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n');
  console.error(`wrote docs/transparency-report.md + .json`);
}
