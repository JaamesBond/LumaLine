-- lumaline security-audit pass-2 (Cluster P3) — fleet-velocity counters for the money-path monitor.
-- READ-ONLY. Surfaces DISTRIBUTED low-and-slow Sybil that per-entity scan_ivt (per device/pub/IP) can
-- never see: aggregate provisional-impression + new-publisher/new-device velocity across the WHOLE fleet.
-- The monitor (edge fn) compares these to baselines and alerts (HIGH) for human review — it does not block.
create or replace function public.monitor_fleet_velocity()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select jsonb_build_object(
    'provisional_impressions_1h',
      (select count(*) from public.impressions
        where state = 'provisional' and created_at > now() - interval '1 hour'),
    'provisional_impressions_24h',
      (select count(*) from public.impressions
        where state = 'provisional' and created_at > now() - interval '24 hours'),
    'new_publishers_1h',
      (select count(*) from public.publishers  where created_at > now() - interval '1 hour'),
    'new_publishers_24h',
      (select count(*) from public.publishers  where created_at > now() - interval '24 hours'),
    'new_devices_1h',
      (select count(*) from public.devices     where created_at > now() - interval '1 hour'),
    'new_devices_24h',
      (select count(*) from public.devices     where created_at > now() - interval '24 hours'),
    'distinct_ip_hashes_1h',
      (select count(distinct ip_hash) from public.ad_windows
        where ip_hash is not null and started_at > now() - interval '1 hour')
  );
$$;
revoke all on function public.monitor_fleet_velocity() from public, anon, authenticated;
grant  execute on function public.monitor_fleet_velocity() to service_role;
comment on function public.monitor_fleet_velocity is
  'READ-ONLY fleet-velocity counters (provisional impressions, new publishers/devices, distinct ip_hashes) '
  'for the money-path monitor fleet_velocity check. service_role only; no writes (monitor invariant).';

do $$
begin
  if has_function_privilege('anon', 'public.monitor_fleet_velocity()', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.monitor_fleet_velocity';
  end if;
end $$;
