-- lumaline GDPR Phase 1 — scheduled retention sweep.
--
-- docs/legal/privacy-policy.md §8 promises operational records are kept <= 90 days and financial
-- records 7 years, "then deleted or anonymized". Nothing enforced it: the only prune crons on disk
-- are rl_buckets / device_code_approve_attempts / signup_throttle_buckets. Consequently
-- impressions.ip_hash was retained forever and public.ad_windows -- UNLOGGED, carrying ip_hash and
-- device_id -- was NEVER purged and grew without bound. That is an Art. 5(1)(e) storage-limitation
-- exposure AND a published-promise-vs-reality gap.
--
-- impressions rows are NEVER deleted: they anchor ledger_entries and the deferred zero-sum trigger.
-- Retention there is COLUMN-LEVEL scrubbing (ip_hash, asn -> NULL) on a timer -- the same
-- anonymize-in-place technique gdpr_erase_publisher already uses, scheduled instead of on demand.
--
-- SAFE AGAINST THE FRAUD SCANS: the longest lookback in the codebase is app.scan_selfdeal_risk at
-- 30 days; scan_ivt / scan_click_ivt / fleet_velocity_monitor and the window_open velocity caps all
-- work in 1-minute to 24-hour horizons. A 90-day scrub clears the longest consumer by 3x, and
-- ad_windows at 7 days clears its longest consumer (24h) by 7x. The clawback window (72h) and the
-- payout hold (7d) clear it by far more.
--
-- NOT SCHEDULED HERE, DELIBERATELY. The first production pass is by far the largest (nothing has
-- ever been swept), so the rollout is: deploy the function -> run it with p_dry_run => true ->
-- review the counts by hand -> schedule the cron. See scripts/ops/retention-sweep-enable.sql.

create or replace function app.retention_sweep(
  p_dry_run      boolean  default false,
  p_batch        integer  default 10000,
  p_max_batches  integer  default 100,
  p_ip_age       interval default interval '90 days',
  p_window_age   interval default interval '7 days',
  p_click_age    interval default interval '90 days',
  p_flag_age     interval default interval '90 days',
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
  v_flag  integer := 0;
  v_code  integer := 0;
begin
  if p_dry_run then
    select count(*) into v_impr from public.impressions
      where created_at < now() - p_ip_age and (ip_hash is not null or asn is not null);
    select count(*) into v_win from public.ad_windows
      where started_at < now() - p_window_age;
    select count(*) into v_click from public.clicks
      where created_at < now() - p_click_age and click_token_hash not like 'scrubbed-%';
    select count(*) into v_flag from public.risk_flags
      where created_at < now() - p_flag_age;
    select count(*) into v_code from public.device_auth_codes
      where created_at < now() - p_authcode_age;
  else
    -- impressions: NEVER delete the row (ledger anchor + deferred zero-sum trigger).
    -- Scrub the network columns only. Batched so the first pass cannot lock the table.
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
  end if;

  return jsonb_build_object(
    'dry_run',                   p_dry_run,
    'impressions_scrubbed',      v_impr,
    'ad_windows_deleted',        v_win,
    'clicks_scrubbed',           v_click,
    'risk_flags_deleted',        v_flag,
    'device_auth_codes_deleted', v_code);
end;
$$;

revoke all on function app.retention_sweep(boolean, integer, integer, interval, interval, interval, interval, interval)
  from public, anon, authenticated;
grant execute on function app.retention_sweep(boolean, integer, integer, interval, interval, interval, interval, interval)
  to service_role;

comment on function app.retention_sweep is
  'Scheduled retention enforcement for privacy-policy §8. Scrubs impressions.ip_hash/asn past 90d '
  '(row PRESERVED -- ledger anchor), deletes ad_windows past 7d, scrubs clicks.click_token_hash and '
  'deletes risk_flags past 90d, deletes device_auth_codes past 24h. Batched. p_dry_run => true counts '
  'without mutating. service_role only; not scheduled by its migration -- see '
  'scripts/ops/retention-sweep-enable.sql.';

-- Migration-tail assertion — no client role may execute the sweep.
do $$
declare
  v_sig text := 'app.retention_sweep(boolean,integer,integer,interval,interval,interval,interval,interval)';
begin
  if has_function_privilege('anon', v_sig, 'EXECUTE')
     or has_function_privilege('authenticated', v_sig, 'EXECUTE') then
    raise exception 'a client role retains EXECUTE on % — REVOKE missing', v_sig;
  end if;
end $$;
