-- lumaline security-audit hardening pass-2 (cluster P2: publisher self-click CPC farming — click IVT).
--
-- Mirrors scan_ivt (20260722130000) for the CLICK side: flags high-velocity provisional (billable)
-- clicks by serving device / publisher / serving-IP-hash (joined clicks -> ad_windows). A flagged
-- click gets a risk_flags row keyed by window_id + a pending clawback_reviews row, so the EXISTING
-- clear_events click branch (20260722090000) WITHHOLDS it from CPC clearing until an admin resolves
-- the review (reject => release, mirroring the A8 impression path; approve => safe no-op for a null
-- impression, and the flag stays withheld = correct for confirmed fraud). No clear_events recreate:
-- its window_id-keyed risk-flag predicate already covers click flags. Per-window is structurally <=1
-- (click_token_hash UNIQUE), so no per-window count is needed.
-- DEPENDS ON: 20260722120000 (ad_windows.ip_hash) + 20260722090000 (clear_events A8 predicate).

create or replace function public.scan_click_ivt(
  p_window    interval default interval '10 minutes',
  p_dev_max   integer  default 8,    -- provisional clicks / serving device / window
  p_pub_max   integer  default 20,   -- provisional clicks / publisher     / window
  p_srvip_max integer  default 12    -- provisional clicks / serving-IP-hash/ window (inert when null)
) returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_flagged   integer := 0;
  r           record;
  v_dev_cnt   integer;
  v_pub_cnt   integer;
  v_srvip_cnt integer;
  v_reason    text;
  v_rf_id     uuid;
begin
  for r in
    select c.id, c.window_id, c.publisher_id, w.device_id, w.ip_hash as srv_ip
      from public.clicks c
      join public.ad_windows w on w.window_id = c.window_id
     where c.state = 'provisional'
       and c.gross_micros > 0
       and c.created_at > now() - p_window
       and not exists (select 1 from public.risk_flags rf where rf.window_id = c.window_id)
  loop
    select count(*) into v_dev_cnt
      from public.clicks c2 join public.ad_windows w2 on w2.window_id = c2.window_id
     where w2.device_id = r.device_id
       and c2.created_at > now() - p_window
       and c2.state in ('provisional', 'cleared');

    select count(*) into v_pub_cnt
      from public.clicks c2
     where c2.publisher_id = r.publisher_id
       and c2.created_at > now() - p_window
       and c2.state in ('provisional', 'cleared');

    if r.srv_ip is null then
      v_srvip_cnt := 0;
    else
      select count(*) into v_srvip_cnt
        from public.clicks c2 join public.ad_windows w2 on w2.window_id = c2.window_id
       where w2.ip_hash = r.srv_ip
         and c2.created_at > now() - p_window
         and c2.state in ('provisional', 'cleared');
    end if;

    v_reason := case
      when v_dev_cnt > p_dev_max                              then 'ivt:click:dev'
      when v_pub_cnt > p_pub_max                              then 'ivt:click:pub'
      when r.srv_ip is not null and v_srvip_cnt > p_srvip_max then 'ivt:click:srvip'
      else null end;

    if v_reason is not null then
      insert into public.risk_flags(impression_id, window_id, reason)
        values (null, r.window_id, v_reason)
        returning id into v_rf_id;
      -- Pending review so a false positive can be REJECTED -> released by clear_events (A8 parity).
      insert into public.clawback_reviews(risk_flag_id, impression_id, status)
        values (v_rf_id, null, 'pending');
      v_flagged := v_flagged + 1;
    end if;
  end loop;

  return v_flagged;
end;
$$;
revoke execute on function public.scan_click_ivt(interval, integer, integer, integer) from public, anon, authenticated;
grant  execute on function public.scan_click_ivt(interval, integer, integer, integer) to service_role;

comment on function public.scan_click_ivt is
  'Service_role cron: flags high-velocity provisional (billable) clicks by serving device/publisher/'
  'serving-IP-hash (clicks joined ad_windows). Writes a risk_flags row keyed by window_id + a pending '
  'clawback_reviews row so the existing clear_events click predicate WITHHOLDS CPC clearing pending '
  'human review (reject => release, A8 parity). NEVER auto-clawback. service_role only.';

-- cron: every 2 min, lookback 10min (>= cadence). Guard for local (no pg_cron).
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule('lumaline-scan-click-ivt')
      where exists (select 1 from cron.job where jobname = 'lumaline-scan-click-ivt');
    perform cron.schedule('lumaline-scan-click-ivt', '*/2 * * * *',
      'select public.scan_click_ivt()');
    if not exists (select 1 from cron.job where jobname = 'lumaline-scan-click-ivt') then
      raise exception 'lumaline-scan-click-ivt failed to reschedule';
    end if;
  else
    raise warning 'pg_cron absent (local?); schedule public.scan_click_ivt() every 2 min in prod';
  end if;
end $$;

-- Migration-tail assertion — anon holds NO EXECUTE on the click-IVT scan.
do $$
begin
  if has_function_privilege('anon', 'public.scan_click_ivt(interval, integer, integer, integer)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.scan_click_ivt — REVOKE missing';
  end if;
end $$;
