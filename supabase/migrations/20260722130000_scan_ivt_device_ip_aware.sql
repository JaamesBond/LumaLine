-- lumaline security-audit hardening (Cluster A): sharper IVT.
--
-- v1 scan_ivt was per-PUBLISHER only (120/6min). This makes it per-DEVICE and per-IP-hash aware and
-- runs it faster than clearing. device_id + ip_hash come from ad_windows (joined by window_id); the
-- edge-computed salted IP hash is stamped onto ad_windows by the recreated window_open (migration
-- 20260722120000). close_window and the client->server envelope are untouched. Flags carry window_id
-- so clear_events' window-canonical predicate blocks the flagged window from clearing (unchanged
-- semantics — flags only WITHHOLD clearing pending review; they do NOT auto-clawback).
--
-- RECONCILIATION (vs the Cluster A spec): the CURRENT scan_ivt (20260629070000_clawback_review.sql)
-- ALSO inserts a pending clawback_reviews row per flag; the whole human-review workflow (reject_clawback
-- / approve_clawback) AND cluster E's clear_events A8 fix depend on that review row existing. This
-- recreate PRESERVES that clawback_reviews insert.
--
-- This is the ONE authoritative scan_ivt recreate for the audit.
-- DEPENDS ON: 20260722120000 (ad_windows.ip_hash + its populating window_open).

drop function if exists public.scan_ivt(interval, integer);

create or replace function public.scan_ivt(
  p_window  interval default interval '3 minutes',
  p_pub_max integer  default 45,   -- per-publisher over p_window (~15/min): coarse backstop
  p_dev_max integer  default 24,   -- per-device    over p_window (~8/min): sharp — one machine
  p_ip_max  integer  default 36    -- per-ip-hash   over p_window (~12/min): NAT aggregate
) returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_flagged integer := 0;
  r record;
  v_pub_cnt integer;
  v_dev_cnt integer;
  v_ip_cnt  integer;
  v_reason  text;
  v_rf_id   uuid;
begin
  for r in
    select i.id, i.window_id, i.publisher_id, w.device_id, w.ip_hash
      from public.impressions i
      join public.ad_windows  w on w.window_id = i.window_id
     where i.state = 'provisional'
       and i.created_at > now() - p_window
       and not exists (select 1 from public.risk_flags rf where rf.impression_id = i.id)
  loop
    -- Per-publisher rate (billable rows only, so void/house don't inflate it).
    select count(*) into v_pub_cnt
      from public.impressions i2
     where i2.publisher_id = r.publisher_id
       and i2.created_at > now() - p_window
       and i2.state in ('provisional', 'cleared');

    -- Per-device rate (device_id via ad_windows).
    select count(*) into v_dev_cnt
      from public.impressions i2
      join public.ad_windows w2 on w2.window_id = i2.window_id
     where w2.device_id = r.device_id
       and i2.created_at > now() - p_window
       and i2.state in ('provisional', 'cleared');

    -- Per-IP-hash rate — only when the window carried an ip_hash (salt configured). Inert (0)
    -- otherwise, so the dimension is forward-compatible and never false-positives on null.
    if r.ip_hash is null then
      v_ip_cnt := 0;
    else
      select count(*) into v_ip_cnt
        from public.impressions i2
        join public.ad_windows w2 on w2.window_id = i2.window_id
       where w2.ip_hash = r.ip_hash
         and i2.created_at > now() - p_window
         and i2.state in ('provisional', 'cleared');
    end if;

    v_reason := case
      when v_dev_cnt > p_dev_max then 'ivt:rate:dev'
      when r.ip_hash is not null and v_ip_cnt > p_ip_max then 'ivt:rate:ip'
      when v_pub_cnt > p_pub_max then 'ivt:rate:pub'
      else null end;

    if v_reason is not null then
      insert into public.risk_flags(impression_id, window_id, reason)
        values (r.id, r.window_id, v_reason)
        returning id into v_rf_id;
      -- Preserve the human-review queue (current scan_ivt behavior, 20260629070000): each flag gets a
      -- pending clawback_reviews row so the impression waits for admin approval rather than auto-reversal
      -- — and so a REJECTED review can later release the window for clearing (clear_events / A8).
      insert into public.clawback_reviews(risk_flag_id, impression_id, status)
        values (v_rf_id, r.id, 'pending');
      v_flagged := v_flagged + 1;
    end if;
  end loop;

  return v_flagged;
end;
$$;
revoke execute on function public.scan_ivt(interval, integer, integer, integer) from public, anon, authenticated;
grant  execute on function public.scan_ivt(interval, integer, integer, integer) to service_role;

-- Reschedule: run every 2 min (faster than hourly clearing); lookback 3min >= cadence so no impression
-- escapes the scan before it ages into clearing. Guard for local (no pg_cron). The old cron command
-- referenced the now-dropped 2-arg signature, so the unschedule+reschedule is required.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule('lumaline-scan-ivt')
      where exists (select 1 from cron.job where jobname = 'lumaline-scan-ivt');
    perform cron.schedule('lumaline-scan-ivt', '*/2 * * * *',
      'select public.scan_ivt(interval ''3 minutes'', 45, 24, 36)');
    if not exists (select 1 from cron.job where jobname = 'lumaline-scan-ivt') then
      raise exception 'lumaline-scan-ivt failed to reschedule';
    end if;
  else
    raise warning 'pg_cron absent (local?); schedule public.scan_ivt(interval ''3 minutes'',45,24,36) every 2 min in prod';
  end if;
end $$;

-- Migration-tail assertion — anon holds NO EXECUTE on the recreated IVT scan.
do $$
begin
  if has_function_privilege('anon', 'public.scan_ivt(interval, integer, integer, integer)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.scan_ivt — REVOKE ... FROM anon missing';
  end if;
end $$;
