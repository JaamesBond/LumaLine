-- lumaline security-audit pass-2 (Cluster P3 / SYBIL) — fleet shared-IP publisher clustering.
--
-- Flags >= p_min_pub distinct publishers whose windows served from ONE ip_hash in p_window. Records a
-- payout HOLD per clustered publisher (reason 'sybil:shared_ip') + payout_status verified->pending, so
-- the earnings are WITHHELD pending human review — NEVER auto-reversed (mirrors scan_selfdeal_risk's
-- money-safe hold-only half; clawback stays admin-driven). Sentinel excluded (all anon share it).
-- No free-email whitelist (a pure-Sybil farm uses gmail): this is the signal scan_selfdeal_risk can't be.
-- Data-minimization: uses only the already-stored salted ad_windows.ip_hash + publisher_id; no new PII.
-- NOTE: payout-account clustering is intentionally omitted — publishers.stripe_account_id is UNIQUE, so a
-- shared payout account is structurally impossible; the residual (one human, many Connect accounts) is
-- Stripe KYC + ops, not code.
-- DEPENDS ON: 20260722120000 (ad_windows.ip_hash populated by window_open), 20260716200000
-- (publisher_payout_holds), 20260627022222 (publishers.payout_status).

create or replace function app.scan_publisher_sybil(
  p_window   interval default interval '24 hours',
  p_min_pub  integer  default 3)         -- >= 3 distinct real publishers on one ip_hash => cluster
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  SENTINEL_PUB constant uuid := '5e470000-0000-4000-8000-0000000000b1';
  r          record;
  v_clusters integer := 0;
  v_held     integer := 0;
  v_new_hold boolean;
begin
  for r in
    with clustered as (
      select w.ip_hash, i.publisher_id
        from public.impressions i
        join public.ad_windows  w on w.window_id = i.window_id
       where w.ip_hash is not null
         and i.publisher_id is distinct from SENTINEL_PUB
         and i.state in ('provisional', 'cleared')
         and i.created_at > now() - p_window
       group by w.ip_hash, i.publisher_id
    ),
    ips as (
      select ip_hash from clustered group by ip_hash having count(distinct publisher_id) >= p_min_pub
    )
    select distinct c.publisher_id, c.ip_hash
      from clustered c join ips using (ip_hash)
  loop
    -- Serialize vs payout_batch_reserve / admin_open_clawback (both take FOR UPDATE OF the publisher row).
    perform 1 from public.publishers where id = r.publisher_id for update;

    insert into public.publisher_payout_holds (publisher_id, reason)
    select r.publisher_id, 'sybil:shared_ip'
    where not exists (
      select 1 from public.publisher_payout_holds h
       where h.publisher_id = r.publisher_id and h.reason = 'sybil:shared_ip' and h.released_at is null);
    get diagnostics v_new_hold = row_count;
    if v_new_hold then v_held := v_held + 1; end if;

    update public.publishers set payout_status = 'pending'
     where id = r.publisher_id and payout_status = 'verified';
  end loop;

  select count(*) into v_clusters from (
    select w.ip_hash
      from public.impressions i join public.ad_windows w on w.window_id = i.window_id
     where w.ip_hash is not null and i.publisher_id is distinct from SENTINEL_PUB
       and i.state in ('provisional','cleared') and i.created_at > now() - p_window
     group by w.ip_hash having count(distinct i.publisher_id) >= p_min_pub) z;

  return jsonb_build_object('clusters_flagged', v_clusters, 'publishers_held', v_held);
end;
$$;
revoke all on function app.scan_publisher_sybil(interval, integer) from public, anon, authenticated;
grant  execute on function app.scan_publisher_sybil(interval, integer) to service_role;

comment on function app.scan_publisher_sybil is
  'Service_role cron: flags >= p_min_pub distinct real publishers sharing one salted ad_windows.ip_hash '
  'in p_window as a Sybil cluster. HOLD-ONLY (publisher_payout_holds reason sybil:shared_ip + payout_status '
  'verified->pending); NEVER auto-clawback (human review). NO free-email whitelist. Sentinel excluded. '
  'Residual cross-IP/cross-identity Sybil is operational (KYC/7d-hold/review). service_role only.';

-- Schedule (guarded for a local/CI stack with no pg_cron).
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule('lumaline-sybil-fleet-scan')
      where exists (select 1 from cron.job where jobname = 'lumaline-sybil-fleet-scan');
    perform cron.schedule('lumaline-sybil-fleet-scan', '41 3 * * *',
      $cron$ select app.scan_publisher_sybil(); $cron$);
  else
    raise notice 'pg_cron absent — skipping lumaline-sybil-fleet-scan schedule (local/CI stack)';
  end if;
end $$;

-- Migration-tail assertion — anon holds NO EXECUTE.
do $$
begin
  if has_function_privilege('anon', 'app.scan_publisher_sybil(interval, integer)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on app.scan_publisher_sybil';
  end if;
end $$;
