-- Owner-gated rollout for app.retention_sweep(). Run against prmsonskzrubqsazmpwd ONLY,
-- via the ref-guarded PAT runner. Do NOT run any of this from CI.
--
-- The first production pass is by far the largest: ad_windows.ip_hash and impressions.ip_hash have
-- never been scrubbed. Review the counts before mutating anything.
--
-- WHAT THE SWEEP DOES (and does not do):
--   * impressions  — scrubs ip_hash/asn past 90d. The ROW IS NEVER DELETED (ledger anchor).
--   * ad_windows   — scrubs ip_hash past 7d IN PLACE. The ROW IS NEVER DELETED: reserve_micros is
--                    summed with NO time bound by app.advertiser_expected_reserved (money
--                    invariant (C) RESERVED) and read at 30d by app.scan_selfdeal_risk.
--   * clicks       — scrubs click_token_hash past 90d to a per-row sentinel. Row preserved.
--   * device_auth_codes — deleted past 24h. The only DELETE in the sweep.
--   * risk_flags   — NOT SWEPT AT ALL. clawback_reviews references it NO ACTION (a DELETE aborts
--                    the whole sweep) and a pending review is what blocks clearing flagged revenue.
--
-- ONE CALL IS ONE TRANSACTION. plpgsql cannot commit between batches, so p_batch/p_max_batches cap
-- statement size and total work per call — they do not shorten the lock or the transaction. Real
-- commit boundaries come from calling the function repeatedly with small caps, which is why both
-- STEP 2 and the STEP 4 cron pass explicit caps instead of the 10000 x 100 defaults.
--
-- NOTE on local verification: the repo's full `npm test` has pre-existing failures confined to
-- five known-broken suites (phase1.rpc.integration, serving.integration, advertiser-serving.integration,
-- advertiser-gdpr.integration, clawback.integration); the total fail count is state-sensitive across
-- back-to-back runs (observed 14-18) and is NOT a valid gate. The meaningful local check is
-- `supabase db reset` followed by `node --test test/retention-sweep.integration.mjs` alone, green.

-- STEP 1 — dry run. Read the counts. Nothing is mutated.
select app.retention_sweep(p_dry_run => true);

-- STEP 1b — record the reserve baseline. This is app.advertiser_expected_reserved's own query
-- (20260716170000) summed across all advertisers: the right-hand side of money invariant
-- (C) RESERVED. Write the number down; STEP 3 must reproduce it exactly.
select coalesce(sum(w.reserve_micros), 0) as expected_reserved_micros
  from public.ad_windows w
  join public.line_items li on li.id = w.line_item_id
  join public.campaigns  c  on c.id  = li.campaign_id
 where not exists (select 1 from public.impressions i
                    where i.window_id = w.window_id
                      and i.state in ('clawed_back', 'void'));

-- STEP 2 — first real pass, deliberately small so the blast radius is inspectable.
-- Repeat until the dry-run counts stop shrinking; each call does at most
-- p_batch * p_max_batches rows per target, in one transaction.
select app.retention_sweep(p_batch => 1000, p_max_batches => 5);

-- STEP 3 — confirm the ledger is untouched and still balanced (must return 0), and that the
-- reserve baseline from STEP 1b is UNCHANGED. The sweep scrubs ad_windows in place, so this
-- number must not move at all; any drift means a window row disappeared, which would let
-- app.advertiser_reconcile_reserved "self-heal" a hold that was never released.
select coalesce(sum(amount_micros), 0) as ledger_sum from public.ledger_entries;
select coalesce(sum(w.reserve_micros), 0) as expected_reserved_micros
  from public.ad_windows w
  join public.line_items li on li.id = w.line_item_id
  join public.campaigns  c  on c.id  = li.campaign_id
 where not exists (select 1 from public.impressions i
                    where i.window_id = w.window_id
                      and i.state in ('clawed_back', 'void'));

-- STEP 4 — only after STEPs 1-3 look right: schedule nightly at 03:41 UTC.
-- NOT 03:17 — that slot belongs to lumaline-selfdeal-scan (20260722070000), which reads and
-- updates ad_windows.reserve_micros; running the sweep on the same table in the same minute buys
-- nothing but lock contention. Explicit small caps, matching the shape of the manual STEP 2.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('lumaline-retention-sweep', '41 3 * * *',
      $cron$ select app.retention_sweep(p_batch => 2000, p_max_batches => 10) $cron$);
  else
    raise warning 'pg_cron absent; run app.retention_sweep() nightly externally';
  end if;
end $$;

-- ROLLBACK — unschedule without dropping the function.
-- select cron.unschedule('lumaline-retention-sweep');
