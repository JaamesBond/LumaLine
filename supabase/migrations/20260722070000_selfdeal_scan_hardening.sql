-- lumaline security-audit (Cluster C / A3) — scan_selfdeal_risk gets admin_open_clawback's money-safety
-- guards, and is finally cron-scheduled. Depends on 20260716200000 (function + publisher_payout_holds),
-- 20260716140000 (app.impression_earning_paid), 20260716100000 (app.payout_hold_interval).
-- Runs AFTER the A2 payout-hold migration (20260722060000).

create or replace function app.scan_selfdeal_risk(
  p_window interval default interval '30 days')
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r          record;
  v_flagged  integer := 0;   -- earnings actually reversed
  v_held     integer := 0;   -- new holds recorded
  v_deferred integer := 0;   -- linked hits NOT reversed (active payout / already paid / post-cond)
  v_reserve  bigint;
  v_new_hold boolean;
begin
  for r in
    select distinct i.id as impression_id, i.publisher_id, i.window_id, c.advertiser_id
      from public.impressions i
      join public.line_items  li on li.id = i.line_item_id
      join public.campaigns   c  on c.id  = li.campaign_id
      join public.advertiser_users au on au.advertiser_id = c.advertiser_id
      join public.publishers  p  on p.id = i.publisher_id
      join auth.users pu on pu.id = p.auth_user_id
      join auth.users vu on vu.id = au.auth_user_id
     where i.state in ('provisional', 'cleared')
       and i.gross_micros > 0
       and i.created_at > now() - p_window
       and pu.email is not null and vu.email is not null
       and (
         lower(pu.email) = lower(vu.email)
         or (position('@' in pu.email) > 0
             and lower(split_part(pu.email, '@', 2)) = lower(split_part(vu.email, '@', 2))
             and lower(split_part(pu.email, '@', 2)) not in (
               'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
               'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com',
               'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'zoho.com', 'mail.com',
               'example.com', 'example.org', 'example.net', 'test.com', 'test'))
       )
       and not exists (
         select 1 from public.risk_flags rf
          where rf.window_id = i.window_id and rf.reason = 'selfdeal:shared_email')
  loop
    -- Serialize against payout_batch_reserve (which takes FOR UPDATE OF p on the same row) and
    -- admin_open_clawback's publisher lock. Blocks until any concurrent reserve/clawback commits.
    perform 1 from public.publishers where id = r.publisher_id for update;

    -- ALWAYS hold the publisher for manual review + downgrade eligibility, even when we cannot safely
    -- reverse (both are idempotent). This is the money-safe half that never depends on the reversal.
    insert into public.publisher_payout_holds (publisher_id, reason)
    select r.publisher_id, 'selfdeal:shared_email'
    where not exists (
      select 1 from public.publisher_payout_holds h
       where h.publisher_id = r.publisher_id and h.reason = 'selfdeal:shared_email' and h.released_at is null);
    get diagnostics v_new_hold = row_count;
    if v_new_hold then v_held := v_held + 1; end if;

    update public.publishers set payout_status = 'pending'
     where id = r.publisher_id and payout_status = 'verified';

    -- GUARD 1: a payout is in flight — reversing now could net publisher_payable negative against an
    -- already-reserved transfer. Hold-only; leave the earning for manual review.
    if exists (select 1 from public.payouts
                where publisher_id = r.publisher_id and status in ('pending', 'in_transit')) then
      v_deferred := v_deferred + 1;
      continue;
    end if;

    -- GUARD 2: the target earning is within the already-paid FIFO tranche — "paid earnings can't be
    -- clawed back". Hold-only.
    if app.impression_earning_paid(r.impression_id) then
      v_deferred := v_deferred + 1;
      continue;
    end if;

    -- Safe to reverse. Per-row SAVEPOINT (nested BEGIN) so the aggregate post-condition below can RAISE
    -- to roll back ONLY THIS row without aborting the whole batch cron.
    begin
      perform public.clawback('impression', r.impression_id, 'selfdeal:shared_email');

      -- Release + zero the window's stranded serve-time reserve (a clawed-back impression never enters
      -- a charge batch, so its reserve would inflate reserved_micros forever). No-op for postpay/drawn.
      select reserve_micros into v_reserve from public.ad_windows where window_id = r.window_id;
      if coalesce(v_reserve, 0) > 0 then
        perform app.advertiser_release(r.advertiser_id, v_reserve);
        update public.ad_windows set reserve_micros = 0 where window_id = r.window_id;
      end if;

      -- Aggregate money-safety backstop (parity with admin_open_clawback): never leave the publisher's
      -- payable negative. Sourced from the SAME app.payout_hold_interval() the reserve default uses.
      if app.publisher_payable_micros(r.publisher_id, app.payout_hold_interval()) < 0 then
        raise exception 'selfdeal clawback would make publisher_payable negative' using errcode = '23514';
      end if;

      v_flagged := v_flagged + 1;
    exception when others then
      -- Roll back just this row's reversal; the hold recorded above (outside this sub-block) persists.
      v_deferred := v_deferred + 1;
    end;
  end loop;

  return jsonb_build_object('impressions_flagged', v_flagged, 'publishers_held', v_held,
                            'deferred_for_review', v_deferred);
end;
$$;
revoke all on function app.scan_selfdeal_risk(interval) from public, anon, authenticated;
grant  execute on function app.scan_selfdeal_risk(interval) to service_role;

comment on function app.scan_selfdeal_risk is
  'Service_role cron backstop for non-identity self-deal. Now carries admin_open_clawback''s guards: '
  'publisher-row FOR UPDATE (serialize vs payout_batch_reserve), refuse-to-reverse on an active payout '
  'OR an already-paid earning (hold-only in those cases), and a per-row-savepointed aggregate '
  'publisher_payable>=0 post-condition. Always records the hold + payout_status verified->pending (the '
  'eligibility block) regardless of whether the earning could be reversed. Payout transfer/confirm core '
  'untouched. service_role only.';

-- ---- Schedule the backstop (guarded so a fresh local/CI stack without pg_cron still applies) --------
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.unschedule('lumaline-selfdeal-scan')
     where exists (select 1 from cron.job where jobname = 'lumaline-selfdeal-scan');
    perform cron.schedule('lumaline-selfdeal-scan', '17 3 * * *',
                          $cron$ select app.scan_selfdeal_risk(); $cron$);
  else
    raise notice 'pg_cron absent — skipping lumaline-selfdeal-scan schedule (local/CI stack)';
  end if;
end $$;

-- Migration-tail assertion — anon holds NO EXECUTE on the money RPC.
do $$
begin
  if has_function_privilege('anon', 'app.scan_selfdeal_risk(interval)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on app.scan_selfdeal_risk';
  end if;
end $$;
