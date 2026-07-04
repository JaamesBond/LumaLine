#!/usr/bin/env node
// LumaLine read-only ops dashboard (M6-T1) — the fuller view watch-billing.mjs was a stand-in for.
// ONE management-API round-trip renders: serving/fill, impressions & credited views, clicks, the
// double-entry ledger + zero-sum invariant, chargeable billing, fraud (risk_flags / clawbacks),
// rate-limit saturation, money-path monitor state, and the advertiser/publisher roster.
//
// READS ONLY. Every value is a SELECT via the same ref-guarded management PAT as scripts/ops/sql.mjs
// (postgres role, so it sees through RLS). It never writes — safe to run while M5 validates prod.
// Not shipped to npm (package.json#files is bin/src/README only).
//
//   node scripts/ops/dashboard.mjs            one-shot snapshot
//   node scripts/ops/dashboard.mjs --watch    refresh every 5s (Ctrl-C to quit)
//   node scripts/ops/dashboard.mjs --json     raw single JSON object (for piping / diffing vs SQL)
import { readFileSync } from 'node:fs';

const ENV = readFileSync(new URL('../../.env', import.meta.url), 'utf8');
const get = (k) => (ENV.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim();
const REF = get('SUPABASE_PROJECTID_REMOTE') || 'prmsonskzrubqsazmpwd';
const PAT = get('SUPABASE_ACCESS_TOKEN_REMOTE');
if (REF !== 'prmsonskzrubqsazmpwd') { console.error(`FATAL: ref mismatch: ${REF}`); process.exit(2); }
if (!PAT) { console.error('FATAL: no SUPABASE_ACCESS_TOKEN_REMOTE in .env'); process.exit(2); }

const argv = new Set(process.argv.slice(2));
const AS_JSON = argv.has('--json');
const WATCH = argv.has('--watch');

const eur = (m) => '€' + (Number(m || 0) / 1_000_000).toFixed(4);
const pct = (x) => (x == null ? 'n/a' : (Number(x) * 100).toFixed(2) + '%');
const n = (x) => Number(x || 0).toLocaleString('en-US');

// One query, one object. Read-only: pure SELECT / aggregates, no RPC that mutates.
const SNAPSHOT_SQL = `
select jsonb_build_object(
  'windows', (select coalesce(jsonb_object_agg(state, nn),'{}') from (
     select state, count(*) nn from public.ad_windows group by state) x),
  'impressions', (select coalesce(jsonb_agg(jsonb_build_object('state',state,'n',nn,'gross',gross)),'[]') from (
     select state, count(*) nn, coalesce(sum(gross_micros),0) gross from public.impressions group by state order by state) x),
  'clicks', (select coalesce(jsonb_agg(jsonb_build_object('state',state,'n',nn,'gross',gross)),'[]') from (
     select state, count(*) nn, coalesce(sum(gross_micros),0) gross from public.clicks group by state order by state) x),
  'ledger', (select coalesce(jsonb_agg(jsonb_build_object('account',account,'state',state,'n',nn,'sum',s)),'[]') from (
     select account, state, count(*) nn, sum(amount_micros) s from public.ledger_entries group by account, state order by account, state) x),
  'ledger_global_sum', (select coalesce(sum(amount_micros),0) from public.ledger_entries),
  'ledger_unbalanced_groups', (select count(*) from (
     select entry_group_id from public.ledger_entries group by entry_group_id having sum(amount_micros)<>0) u),
  'owner_balance', (select to_jsonb(b) from public.v_publisher_balance b
     where b.publisher_id='bc50d59b-dc14-4b75-a68d-0c032c3b4fc3'),
  'uncharged_micros', (select coalesce(sum(amount_micros),0) from public.uncharged_advertiser_billings),
  'charges', (select coalesce(jsonb_agg(jsonb_build_object('status',status,'n',nn,'micros',micros)),'[]') from (
     select status, count(*) nn, coalesce(sum(amount_micros),0) micros from public.advertiser_charges group by status order by status) x),
  'risk_flags', (select coalesce(jsonb_agg(jsonb_build_object('reason',reason,'n',nn)),'[]') from (
     select reason, count(*) nn from public.risk_flags group by reason order by reason) x),
  'clawed_back', jsonb_build_object(
     'impressions', (select count(*) from public.impressions where state='clawed_back'),
     'clicks',      (select count(*) from public.clicks where state='clawed_back')),
  'rate_limit', jsonb_build_object(
     'bucket_rows', (select count(*) from public.rl_buckets),
     'max_count_current_minute', (select coalesce(max(count),0) from public.rl_buckets
        where window_start = date_trunc('minute', now()))),
  'monitor', jsonb_build_object(
     'open_alerts', (select count(*) from app.alert_events where status='open'),
     'checks', (select coalesce(jsonb_object_agg(check_name, jsonb_build_object(
                  'open', oc, 'last_event_at', last_at)),'{}') from (
        select check_name, count(*) filter (where status='open') oc, max(created_at) last_at
        from app.alert_events group by check_name) s)),
  'advertisers', (select coalesce(jsonb_agg(jsonb_build_object(
        'name',name,'status',status,'is_house',is_house,'has_customer',stripe_customer_id is not null)),'[]') from (
     select name, status, is_house, stripe_customer_id from public.advertisers order by is_house desc, name) x),
  'publishers_count', (select count(*) from public.publishers)
) as snap`;

async function sql(query) {
  const r = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${PAT}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  if (!r.ok) throw new Error(`SQL ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return r.json();
}

function fillRate(windows) {
  const credited = windows.credited || 0;
  const terminal = credited + (windows.abandoned || 0) + (windows.void || 0); // open = still in-flight
  return terminal ? credited / terminal : null;
}

// Derive the credited-view + gross split the panels need, so both the JSON and the text view agree.
function derive(s) {
  const impBy = Object.fromEntries((s.impressions || []).map((r) => [r.state, r]));
  const billable = ['provisional', 'cleared'];
  const creditedViews = billable.reduce((a, st) => a + Number(impBy[st]?.n || 0), 0);
  const provisionalGross = Number(impBy.provisional?.gross || 0);
  const clearedGross = Number(impBy.cleared?.gross || 0);
  return {
    fill_rate: fillRate(s.windows || {}),
    credited_views: creditedViews,
    provisional_gross_micros: provisionalGross,
    cleared_gross_micros: clearedGross,
    zero_sum_ok: Number(s.ledger_global_sum) === 0 && Number(s.ledger_unbalanced_groups) === 0,
  };
}

function render(s) {
  const d = derive(s);
  const w = s.windows || {};
  const L = [];
  const hr = '─'.repeat(64);
  L.push(`\x1b[1mLumaLine ops dashboard\x1b[0m  ·  ${REF}  ·  ${new Date().toISOString()}`);
  L.push(hr);

  L.push('\x1b[1mSERVING / FILL\x1b[0m');
  L.push(`  windows: open ${n(w.open)}  credited ${n(w.credited)}  abandoned ${n(w.abandoned)}  void ${n(w.void)}`);
  L.push(`  fill rate (credited / terminal): ${pct(d.fill_rate)}`);

  L.push('\x1b[1mIMPRESSIONS\x1b[0m');
  L.push(`  credited views (billable): ${n(d.credited_views)}`);
  for (const r of s.impressions || []) L.push(`    ${r.state.padEnd(12)} n=${n(r.n)}  gross=${eur(r.gross)}`);
  L.push(`  clicks:`);
  for (const r of s.clicks || []) L.push(`    ${r.state.padEnd(12)} n=${n(r.n)}  gross=${eur(r.gross)}`);

  L.push('\x1b[1mLEDGER (double-entry, source of truth)\x1b[0m');
  const zok = d.zero_sum_ok ? '\x1b[32m✓ balanced\x1b[0m' : '\x1b[31m✗ IMBALANCE — P0\x1b[0m';
  L.push(`  zero-sum: ${zok}  (global_sum=${s.ledger_global_sum}, unbalanced_groups=${s.ledger_unbalanced_groups})`);
  if ((s.ledger || []).length === 0) L.push('    (no ledger entries yet — nothing cleared)');
  for (const r of s.ledger || []) L.push(`    ${r.account.padEnd(20)} ${String(r.state).padEnd(12)} n=${n(r.n)}  sum=${eur(r.sum)}`);
  if (s.owner_balance) {
    const b = s.owner_balance;
    L.push(`  owner publisher balance: earned ${eur(b.earned_micros)}  paid ${eur(b.paid_micros)}  reversed ${eur(b.reversed_micros)}  net ${eur(b.balance_micros)}`);
  }

  L.push('\x1b[1mBILLING\x1b[0m');
  L.push(`  chargeable now (uncharged cleared): ${eur(s.uncharged_micros)}`);
  if ((s.charges || []).length === 0) L.push('    charges: none yet');
  for (const r of s.charges || []) L.push(`    ${r.status.padEnd(12)} n=${n(r.n)}  ${eur(r.micros)}`);

  L.push('\x1b[1mFRAUD / IVT\x1b[0m');
  if ((s.risk_flags || []).length === 0) L.push('    risk flags: none');
  for (const r of s.risk_flags || []) L.push(`    ${String(r.reason).padEnd(16)} n=${n(r.n)}`);
  L.push(`  clawed back: impressions ${n(s.clawed_back?.impressions)}  clicks ${n(s.clawed_back?.clicks)}`);

  L.push('\x1b[1mRATE LIMIT\x1b[0m');
  L.push(`  active bucket rows: ${n(s.rate_limit?.bucket_rows)}  max hits this minute: ${n(s.rate_limit?.max_count_current_minute)}`);

  L.push('\x1b[1mMONITOR (money-path)\x1b[0m');
  const oa = Number(s.monitor?.open_alerts || 0);
  L.push(`  open alerts: ${oa === 0 ? '\x1b[32m0 (all clear)\x1b[0m' : `\x1b[31m${oa}\x1b[0m`}`);
  const checks = s.monitor?.checks || {};
  for (const [k, v] of Object.entries(checks)) {
    const st = Number(v.open) > 0 ? '\x1b[31malerting\x1b[0m' : '\x1b[32mok\x1b[0m';
    L.push(`    ${k.padEnd(22)} ${st}  (last ${v.last_event_at || '—'})`);
  }

  L.push('\x1b[1mROSTER\x1b[0m');
  for (const a of s.advertisers || [])
    L.push(`    ${a.is_house ? '[house]' : '[paid] '} ${String(a.name).padEnd(24)} ${a.status}${a.has_customer ? '  card✓' : ''}`);
  L.push(`  publishers: ${n(s.publishers_count)}`);
  L.push(hr);
  return L.join('\n');
}

async function snapshot() {
  const [row] = await sql(SNAPSHOT_SQL);
  return row.snap;
}

if (AS_JSON) {
  const s = await snapshot();
  console.log(JSON.stringify({ ...s, derived: derive(s) }, null, 2));
} else if (WATCH) {
  const draw = async () => {
    try {
      const s = await snapshot();
      process.stdout.write('\x1b[2J\x1b[H' + render(s) + '\n(--watch: refreshing every 5s, Ctrl-C to quit)');
    } catch (e) {
      process.stdout.write('\x1b[2J\x1b[H[err] ' + e.message);
    }
  };
  await draw();
  setInterval(draw, 5000);
} else {
  console.log(render(await snapshot()));
}
