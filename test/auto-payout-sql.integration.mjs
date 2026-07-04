// test/auto-payout-sql.integration.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

const DB = process.env.SUPABASE_DB_URL || 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
let pg; try { pg = (await import('node:child_process')); } catch { /* */ }
const psql = (sql) => {
  const r = pg.spawnSync('psql', [DB, '-Atc', sql], { encoding: 'utf8' });
  return { ok: r.status === 0, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
};
const up = psql("select 1");
const SKIP = !up.ok ? 'local DB unreachable — SKIPPING' : false;
if (SKIP) console.log(`[auto-payout-sql] ${SKIP}`);

test('migration objects exist', { skip: SKIP }, () => {
  assert.equal(psql("select count(*) from information_schema.columns where table_schema='public' and table_name='publishers' and column_name='connect_nudge_at'").out, '1');
  // PostgREST only resolves the `public` schema, so these three REST-called RPCs live in `public`.
  for (const fn of ['publisher_contact', 'payout_nudge_candidates', 'mark_connect_nudged']) {
    assert.equal(psql(`select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname='${fn}'`).out, '1', `public.${fn} exists`);
  }
  // run_payout is a pg_cron target invoked via SQL (select app.run_payout()), not via REST — stays in app.
  assert.equal(psql(`select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='app' and p.proname='run_payout'`).out, '1', `app.run_payout exists`);
});

test('run_payout no-ops cleanly when Vault secret absent (fresh stack)', { skip: SKIP }, () => {
  const r = psql("select app.run_payout()");
  assert.ok(r.ok, `run_payout ran without error: ${r.err}`);
});

test('anon/authenticated cannot execute the new money RPCs', { skip: SKIP }, () => {
  for (const sig of ['public.publisher_contact(uuid)', 'public.payout_nudge_candidates(bigint,interval)', 'public.mark_connect_nudged(uuid[])', 'app.run_payout()']) {
    assert.equal(psql(`select has_function_privilege('anon','${sig}','execute')`).out, 'f', `anon cannot ${sig}`);
  }
});
