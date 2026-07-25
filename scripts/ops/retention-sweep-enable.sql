-- Owner-gated rollout for app.retention_sweep(). Run against prmsonskzrubqsazmpwd ONLY,
-- via the ref-guarded PAT runner. Do NOT run any of this from CI.
--
-- The first production pass is by far the largest: ad_windows has never been purged and
-- impressions.ip_hash has never been scrubbed. Review the counts before mutating anything.
--
-- NOTE on local verification: the repo's full `npm test` has pre-existing failures confined to
-- five known-broken suites (phase1.rpc.integration, serving.integration, advertiser-serving.integration,
-- advertiser-gdpr.integration, clawback.integration); the total fail count is state-sensitive across
-- back-to-back runs (observed 14-18) and is NOT a valid gate. The meaningful local check is
-- `supabase db reset` followed by `node --test test/retention-sweep.integration.mjs` alone, green.

-- STEP 1 — dry run. Read the counts. Nothing is mutated.
select app.retention_sweep(p_dry_run => true);

-- STEP 2 — first real pass, deliberately small so the blast radius is inspectable.
-- Repeat until the dry-run counts stop shrinking; each call does at most
-- p_batch * p_max_batches rows per target.
select app.retention_sweep(p_batch => 1000, p_max_batches => 5);

-- STEP 3 — confirm the ledger is untouched and still balanced (must return 0).
select coalesce(sum(amount_micros), 0) as ledger_sum from public.ledger_entries;

-- STEP 4 — only after STEPs 1-3 look right: schedule nightly at 03:17 UTC.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('lumaline-retention-sweep', '17 3 * * *',
      $cron$ select app.retention_sweep() $cron$);
  else
    raise warning 'pg_cron absent; run app.retention_sweep() nightly externally';
  end if;
end $$;

-- ROLLBACK — unschedule without dropping the function.
-- select cron.unschedule('lumaline-retention-sweep');
