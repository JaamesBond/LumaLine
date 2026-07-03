#!/usr/bin/env node
// Live LumaLine billing monitor — stand-in until the T8 admin dashboard exists.
// Refreshes every 5s: Degen serving/crediting, ledger accrual, owner earnings, chargeable total.
// Reads the management PAT from the repo-root .env. Run: node scripts/ops/watch-billing.mjs
import { readFileSync } from 'node:fs';

const ENV = readFileSync(new URL('../../.env', import.meta.url), 'utf8');
const get = (k) => (ENV.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim();
const PAT = get('SUPABASE_ACCESS_TOKEN_REMOTE');
const REF = 'prmsonskzrubqsazmpwd';
const DEGEN = '4779db17-99e9-4bde-9723-ffe7dd4f7e58';
const YOU = 'bc50d59b-dc14-4b75-a68d-0c032c3b4fc3';
const eur = (m) => '€' + (Number(m || 0) / 1_000_000).toFixed(4);

async function sql(query) {
  const r = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${PAT}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  if (!r.ok) throw new Error(`SQL ${r.status}: ${(await r.text()).slice(0, 120)}`);
  return r.json();
}

async function tick() {
  try {
    const [row] = await sql(`
      select
        (select count(*) from public.ad_windows w join public.creatives c on c.id=w.creative_id
           join public.line_items li on li.id=c.line_item_id join public.campaigns cm on cm.id=li.campaign_id
         where cm.advertiser_id='${DEGEN}' and w.state='credited') as degen_credited,
        (select coalesce(sum(gross_micros),0) from public.impressions i join public.line_items li on li.id=i.line_item_id
           join public.campaigns cm on cm.id=li.campaign_id where cm.advertiser_id='${DEGEN}') as provisional,
        (select coalesce(sum(amount_micros),0) from public.ledger_entries
         where publisher_id='${YOU}' and account='publisher_earnings') as your_earn,
        (select coalesce(sum(amount_micros),0) from public.uncharged_advertiser_billings) as uncharged,
        (select count(*) from public.ledger_entries) as ledger_rows`);
    const t = new Date().toLocaleTimeString();
    const line = [
      `[${t}]`,
      `Degen credited: ${row.degen_credited}`,
      `provisional: ${eur(row.provisional)}`,
      `your earnings: ${eur(row.your_earn)}`,
      `chargeable: ${eur(row.uncharged)}`,
      `ledger rows: ${row.ledger_rows}`,
    ].join('  |  ');
    process.stdout.write('\x1b[2K\r' + line);
  } catch (e) {
    process.stdout.write('\x1b[2K\r[err] ' + e.message);
  }
}

console.log('LumaLine billing monitor — Ctrl-C to quit. Refreshing every 5s...\n');
await tick();
setInterval(tick, 5000);
