#!/usr/bin/env node
// Ref-guarded PAT SQL runner for the LumaLine remote (prmsonskzrubqsazmpwd).
// Reads creds from the repo-root .env (gitignored). Not shipped to npm (package.json#files
// is bin/src/README only). Usage: node scripts/ops/sql.mjs "select 1"   (or @file.sql)
import { readFileSync } from 'node:fs';

const ENV = readFileSync(new URL('../../.env', import.meta.url), 'utf8');
const get = (k) => (ENV.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim();
const REF = get('SUPABASE_PROJECTID_REMOTE');
const PAT = get('SUPABASE_ACCESS_TOKEN_REMOTE');
if (REF !== 'prmsonskzrubqsazmpwd') { console.error(`FATAL: ref mismatch: ${REF}`); process.exit(2); }
if (!PAT) { console.error('FATAL: no SUPABASE_ACCESS_TOKEN_REMOTE in .env'); process.exit(2); }

let query = process.argv[2] || '';
if (query.startsWith('@')) query = readFileSync(query.slice(1), 'utf8');
if (!query) { console.error('usage: sql.mjs "<sql>" | @file.sql'); process.exit(1); }

const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/database/query`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${PAT}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ query }),
});
const text = await res.text();
if (!res.ok) { console.error(`HTTP ${res.status}: ${text}`); process.exit(1); }
try { console.log(JSON.stringify(JSON.parse(text), null, 2)); } catch { console.log(text); }
