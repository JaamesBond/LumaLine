-- Owner-gated rollout for app.gdpr_complete_pending() — GDPR Phase 3. Run against
-- prmsonskzrubqsazmpwd ONLY, via the ref-guarded PAT runner. Do NOT run any of this from CI.
--
-- Unlike the Phase 1 retention sweep, the first pass here is expected to be EMPTY: nothing can be
-- pending until the Phase 3 migration is deployed and a user actually requests a deletion. That
-- makes STEP 1 a different kind of check — it is confirming the function is reachable and reports
-- zeroes, NOT that a backlog was reviewed. An all-zero result on an empty table proves the
-- function ran; it proves nothing about whether it works. STEP 2 is what proves that, and it is
-- deliberately a rehearsal on a row you create and roll back.
--
-- WHAT THE PASS DOES (and does not do):
--   * It calls the UNCHANGED app.gdpr_erase_publisher / app.advertiser_gdpr_erase. It contains no
--     erasure logic of its own, so it cannot erase anything those bodies would refuse to erase.
--   * It NEVER touches money. It moves no balance, books no ledger entry, and does not sweep a
--     residual advertiser credit — a spend_down row simply waits until the credit is gone.
--   * It clears deletion_requested_at only on a row it actually erased.
--   * A row it cannot complete stays pending and, past 25 days, raises app.alert_events
--     (check_name='gdpr_pending_overdue') — five days inside the Art. 12(3) one-month deadline.
--
-- ONE CALL IS ONE TRANSACTION, but each row's erasure sits in its own subtransaction, so a single
-- failing account is reported in `skipped` and every other row still completes. Read `skipped` on
-- every pass: a non-empty array is a data subject whose Art. 17 request is NOT being honoured.
--
-- NOTE on local verification: the repo's full `npm test` has pre-existing failures confined to
-- five known-broken suites (phase1.rpc.integration, serving.integration, advertiser-serving.integration,
-- advertiser-gdpr.integration, clawback.integration); the total fail count is state-sensitive
-- across back-to-back runs and is NOT a valid gate. The meaningful local check is
-- `supabase db reset` followed by test/gdpr-self-delete.integration.mjs green (11/11) and
-- test/advertiser-gdpr.integration.mjs green except its two documented aal2 baselines (G6/G8).

-- STEP 1 — reachability. Expected on a fresh deploy: every counter 0, skipped [].
-- A non-empty `skipped` here means an account is already stuck; stop and read it before going on.
select app.gdpr_complete_pending();

-- STEP 2 — REHEARSAL, inside a transaction that is rolled back. This is the step that proves the
-- pass actually works, because STEP 1 cannot: an all-zero result on an empty table is
-- indistinguishable from a no-op. Pick a REAL advertiser id that is live, has no money in flight
-- and holds no balance, then confirm the pass erases it — and roll the whole thing back.
--
--   begin;
--     -- substitute a real, live, zero-balance advertiser id:
--     \set adv '00000000-0000-0000-0000-000000000000'
--     update public.advertisers
--        set deletion_requested_at = now() - interval '26 days', deletion_disposition = 'dormant'
--      where id = :'adv';
--     select app.gdpr_complete_pending();          -- expect advertisers_erased >= 1, alerts_raised >= 1
--     select deleted_at, name, deletion_requested_at from public.advertisers where id = :'adv';
--     select coalesce(sum(amount_micros), 0) as ledger_sum from public.ledger_entries;  -- must be 0
--   rollback;
--
-- The ledger_sum line is the money check: erasure is anonymize-in-place and PRESERVES the ledger,
-- so this number must be 0 (globally balanced) both before and after. If it is not, stop.

-- STEP 3 — confirm the alert plumbing is wired the way the monitor expects. The dedup index is
-- partial on open rows, so an hourly cron cannot spam a new row per hour for the same subject.
select check_name, dedup_key, status, created_at, resolved_at, payload
  from app.alert_events
 where check_name = 'gdpr_pending_overdue'
 order by created_at desc
 limit 20;

-- STEP 4 — only after STEPs 1-3 look right: schedule HOURLY at :23.
-- Minute 23 is chosen because it is genuinely free, not merely unused today:
--   * 03:17 / 03:41 / 03:53 belong to lumaline-selfdeal-scan, lumaline-sybil-fleet-scan and
--     lumaline-retention-sweep;
--   * :00 belongs to the hourly lumaline-clear-events;
--   * 23 is odd and not a multiple of 5 or 10, so it can never coincide with the */2 (scan-ivt,
--     scan-click-ivt), */5 (rl-prune, device-approve-prune, signup-throttle-prune) or */10
--     (sweep-windows) jobs.
-- Hourly rather than nightly because the blockers this waits on (a Stripe deposit, a charge, a
-- payout) settle at any hour, and the Art. 12(3) clock does not stop overnight.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('lumaline-gdpr-complete-pending', '23 * * * *',
      $cron$ select app.gdpr_complete_pending() $cron$);
  else
    raise warning 'pg_cron absent; run app.gdpr_complete_pending() hourly externally';
  end if;
end $$;

-- STEP 5 — after the first scheduled run, confirm it executed and read what it did.
select jobname, schedule, active from cron.job where jobname = 'lumaline-gdpr-complete-pending';
select start_time, status, return_message
  from cron.job_run_details
 where jobid = (select jobid from cron.job where jobname = 'lumaline-gdpr-complete-pending')
 order by start_time desc
 limit 5;

-- ROLLBACK — unschedule without dropping the function. Pending rows simply stop completing; the
-- request path, the freeze and cancel all keep working, and nothing is lost.
-- select cron.unschedule('lumaline-gdpr-complete-pending');
