-- lumaline GDPR Phase 1 — scheduled retention sweep.
--
-- docs/legal/privacy-policy.md §8 promises operational records are kept <= 90 days and financial
-- records 7 years, "then deleted or anonymized". Nothing enforced it: the only prune crons on disk
-- are rl_buckets / device_code_approve_attempts / signup_throttle_buckets. Consequently
-- impressions.ip_hash was retained forever and public.ad_windows -- UNLOGGED, carrying ip_hash --
-- was never scrubbed. That is an Art. 5(1)(e) storage-limitation exposure AND a
-- published-promise-vs-reality gap. (Row-count growth on ad_windows is a separate, purely
-- operational concern and is NOT addressed here -- see the money note below for why.)
--
-- NOTHING THAT ANCHORS MONEY IS DELETED. impressions rows are NEVER deleted: they anchor
-- ledger_entries and the deferred zero-sum trigger. ad_windows rows are NEVER deleted either:
-- app.advertiser_expected_reserved (20260716170000) sums ad_windows.reserve_micros with NO time
-- bound whatsoever -- it is the right-hand side of money invariant (C) RESERVED in
-- advertiser_ledger_health() and the source of truth for app.advertiser_reconcile_reserved -- and
-- app.scan_selfdeal_risk reads the same column at a 30-day lookback. Deleting aged windows would
-- drop their reserve out of that sum and let reconciliation "self-heal" by releasing a hold that
-- was never actually drawn. So retention on both tables is COLUMN-LEVEL scrubbing of the personal
-- data only (impressions.ip_hash/asn and ad_windows.ip_hash -> NULL) on a timer -- the same
-- anonymize-in-place technique gdpr_erase_publisher already uses, scheduled instead of on demand.
-- The window row, its state and its reserve_micros survive untouched, precisely so the unbounded
-- reserve reader, the 30-day self-deal scan and the public transparency histogram keep working.
-- (ad_windows.device_id is NOT NULL with an ON DELETE CASCADE FK, so it cannot be nulled here; it
-- is an opaque internal id and erasure removes it by deleting the publisher's devices.)
--
-- SAFE AGAINST THE FRAUD SCANS. Enumerated by column, not by table:
--   * impressions.ip_hash / asn — NOTHING in migrations, functions or scripts READS either column.
--     Every reference is a write (close_window stamps ip_hash from the window) or an index
--     definition (20260627022224:79, 20260722140000:16); asn has never had a reader at all.
--     90 days is therefore pure margin. (app.scan_selfdeal_risk is the longest reader of the
--     impressions TABLE at 30 days, but it touches neither column.)
--   * ad_windows.ip_hash — read by the window_open velocity caps (1-2 min), scan_ivt (3 min),
--     scan_click_ivt (10 min), fleet_velocity_monitor (1 hour) and the click_resolve self-click
--     gate (click-token lifetime). Longest is 1 hour, so 7 days clears it by ~168x.
-- And because only ip_hash is touched on ad_windows, the unbounded reserve reader and the 30-day
-- self-deal scan see an unchanged row at every age.
--
-- risk_flags IS DELIBERATELY NOT SWEPT. public.clawback_reviews.risk_flag_id references it with
-- NO ACTION and every scan inserts a review row atomically with every flag, so deleting flags
-- aborts the entire sweep on an FK violation. Relaxing that FK is worse: clear_events() treats a
-- non-rejected review as an indefinite block on clearing, so removing a forgotten pending flag
-- would release fraud-flagged revenue into the 60/40 split with no human ever reviewing it. A flag
-- holds a reason plus two ids and no direct personal data, so the storage-limitation pressure is
-- weak while the money-safety coupling is strong.
--
-- BATCHING BOUNDS STATEMENT SIZE, NOT LOCK DURATION. A plpgsql function cannot commit between
-- iterations, so one call is one transaction: locks taken by every batch are held until the call
-- returns, and a failure anywhere discards all the work before it. p_batch / p_max_batches keep
-- each individual statement small and cap total work per call; the operator gets real commit
-- boundaries only by calling the function repeatedly with small caps, which is what the runbook
-- and the scheduled cron both do.
--
-- NOT SCHEDULED HERE, DELIBERATELY. The first production pass is by far the largest (nothing has
-- ever been swept), so the rollout is: deploy the function -> run it with p_dry_run => true ->
-- review the counts by hand -> schedule the cron. See scripts/ops/retention-sweep-enable.sql.

-- Supporting indexes. Every sweep predicate filters on a timestamp that is not the leading column
-- of any pre-existing index, so without these each batch plans as a full Seq Scan -- and because
-- already-processed rows stay physically present inside the one transaction, the scan does not get
-- cheaper as the loop progresses. Partial where the sweep's own idempotency predicate allows it,
-- which also keeps the index tiny once the backlog is scrubbed.
create index if not exists impressions_retention_idx
  on public.impressions (created_at)
  where ip_hash is not null or asn is not null;

create index if not exists ad_windows_retention_idx
  on public.ad_windows (started_at)
  where ip_hash is not null;

create index if not exists clicks_retention_idx
  on public.clicks (created_at)
  where click_token_hash not like 'scrubbed-%';

create index if not exists device_auth_codes_retention_idx
  on public.device_auth_codes (created_at);

-- Drop the pre-review 8-argument shape if a dev stack already applied an earlier revision of this
-- migration. CREATE OR REPLACE cannot change a function's argument list -- it would leave the old
-- form behind as an overload, making the all-defaults call app.retention_sweep() ambiguous.
-- No-op on production, where this migration has never run.
drop function if exists app.retention_sweep(
  boolean, integer, integer, interval, interval, interval, interval, interval);

create or replace function app.retention_sweep(
  p_dry_run      boolean  default false,
  p_batch        integer  default 10000,
  p_max_batches  integer  default 100,
  p_ip_age       interval default interval '90 days',
  p_window_age   interval default interval '7 days',
  p_click_age    interval default interval '90 days',
  p_authcode_age interval default interval '24 hours')
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_impr  integer := 0;
  v_win   integer := 0;
  v_click integer := 0;
  v_code  integer := 0;
begin
  if p_dry_run then
    select count(*) into v_impr from public.impressions
      where created_at < now() - p_ip_age and (ip_hash is not null or asn is not null);
    select count(*) into v_win from public.ad_windows
      where started_at < now() - p_window_age and ip_hash is not null;
    select count(*) into v_click from public.clicks
      where created_at < now() - p_click_age and click_token_hash not like 'scrubbed-%';
    select count(*) into v_code from public.device_auth_codes
      where created_at < now() - p_authcode_age;
  else
    -- impressions: NEVER delete the row (ledger anchor + deferred zero-sum trigger).
    -- Scrub the network columns only. The `is not null` predicate is what makes it idempotent.
    declare v_n integer; v_i integer := 0;
    begin
      loop
        update public.impressions set ip_hash = null, asn = null
         where id in (select id from public.impressions
                       where created_at < now() - p_ip_age
                         and (ip_hash is not null or asn is not null)
                       limit p_batch);
        get diagnostics v_n = row_count;
        v_impr := v_impr + v_n;
        v_i := v_i + 1;
        exit when v_n = 0 or v_i >= p_max_batches;
      end loop;
    end;

    -- ad_windows: NEVER delete the row either. app.advertiser_expected_reserved sums
    -- reserve_micros with no time bound and app.scan_selfdeal_risk reads it at 30 days, so the row
    -- must outlive its personal data. Scrub ip_hash only -- device_id is NOT NULL and cannot be
    -- nulled; erasure removes it by cascading from the publisher's devices.
    declare v_n integer; v_i integer := 0;
    begin
      loop
        update public.ad_windows set ip_hash = null
         where window_id in (select window_id from public.ad_windows
                              where started_at < now() - p_window_age
                                and ip_hash is not null
                              limit p_batch);
        get diagnostics v_n = row_count;
        v_win := v_win + v_n;
        v_i := v_i + 1;
        exit when v_n = 0 or v_i >= p_max_batches;
      end loop;
    end;

    -- clicks: click_token_hash is NOT NULL UNIQUE, so scrub to a per-row unique sentinel rather
    -- than NULL. The row is a financial record and is preserved. The `not like 'scrubbed-%'`
    -- predicate is what makes the sweep idempotent here.
    declare v_n integer; v_i integer := 0;
    begin
      loop
        update public.clicks set click_token_hash = 'scrubbed-' || id::text
         where id in (select id from public.clicks
                       where created_at < now() - p_click_age
                         and click_token_hash not like 'scrubbed-%'
                       limit p_batch);
        get diagnostics v_n = row_count;
        v_click := v_click + v_n;
        v_i := v_i + 1;
        exit when v_n = 0 or v_i >= p_max_batches;
      end loop;
    end;

    -- device_auth_codes: short-lived login codes, nothing references them. Safe to delete.
    declare v_n integer; v_i integer := 0;
    begin
      loop
        delete from public.device_auth_codes
         where id in (select id from public.device_auth_codes
                       where created_at < now() - p_authcode_age
                       limit p_batch);
        get diagnostics v_n = row_count;
        v_code := v_code + v_n;
        v_i := v_i + 1;
        exit when v_n = 0 or v_i >= p_max_batches;
      end loop;
    end;
  end if;

  return jsonb_build_object(
    'dry_run',                   p_dry_run,
    'impressions_scrubbed',      v_impr,
    'ad_windows_scrubbed',       v_win,
    'clicks_scrubbed',           v_click,
    'device_auth_codes_deleted', v_code);
end;
$$;

revoke all on function app.retention_sweep(boolean, integer, integer, interval, interval, interval, interval)
  from public, anon, authenticated;
grant execute on function app.retention_sweep(boolean, integer, integer, interval, interval, interval, interval)
  to service_role;

comment on function app.retention_sweep is
  'Scheduled retention enforcement for privacy-policy §8. Scrubs impressions.ip_hash/asn past 90d, '
  'ad_windows.ip_hash past 7d and clicks.click_token_hash past 90d -- all three rows are PRESERVED '
  '(ledger anchor, unbounded reserve_micros reader, financial record) -- and deletes '
  'device_auth_codes past 24h. risk_flags is deliberately NOT swept: clawback_reviews references it '
  'NO ACTION and a pending review is what blocks clearing fraud-flagged revenue. Batched (statement '
  'size only -- one call is one transaction). p_dry_run => true counts without mutating. '
  'service_role only; not scheduled by its migration -- see scripts/ops/retention-sweep-enable.sql.';

-- Migration-tail assertion — no client role may execute the sweep.
do $$
declare
  v_sig text := 'app.retention_sweep(boolean,integer,integer,interval,interval,interval,interval)';
begin
  if has_function_privilege('anon', v_sig, 'EXECUTE')
     or has_function_privilege('authenticated', v_sig, 'EXECUTE') then
    raise exception 'a client role retains EXECUTE on % — REVOKE missing', v_sig;
  end if;
end $$;
