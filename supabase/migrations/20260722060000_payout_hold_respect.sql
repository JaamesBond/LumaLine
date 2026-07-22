-- lumaline security-audit (Cluster C / A2) — a fraud payout hold must survive a Stripe account.updated
-- and must block the payout batch. TWO additive, byte-minimal recreations:
--   1. payout_batch_reserve: exclude any publisher with an UNRELEASED publisher_payout_holds row
--      (belt-and-suspenders even if payout_status was restored to 'verified').
--   2. set_publisher_payout_eligibility: never RAISE payout_status to 'verified' while an open hold
--      exists (keep it 'pending'); every other status passes through unchanged.
-- Transfer/confirm core (payout_confirm/fail/reverse) and the reservation lock are UNTOUCHED.
-- Depends on: 20260716200000 (publisher_payout_holds), 20260716130000 (payout_batch_reserve body),
--             20260716100000 (app.payout_hold_interval), 20260629100000 (set_publisher_payout_eligibility).

-- ---- 1. payout_batch_reserve — body copied verbatim from 20260716130000, ONE added WHERE line.
create or replace function public.payout_batch_reserve(
  p_hold                interval default app.payout_hold_interval(),
  p_min_micros          bigint   default 25000000,
  p_velocity_max_micros bigint   default 10000000000,
  p_limit               int      default 100)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  rec       record;
  v_payable bigint;
  v_id      uuid;
  reserved  jsonb := '[]'::jsonb;
  skipped   jsonb := '[]'::jsonb;
begin
  for rec in
    select p.id
      from public.publishers p
     where p.payout_status = 'verified'
       and p.stripe_account_id is not null
       and p.status = 'active'
       and p.deleted_at is null
       and not exists (
         select 1 from public.payouts po
          where po.publisher_id = p.id and po.status in ('pending', 'in_transit'))
       and not exists (                                  -- A2: skip a publisher on an unreleased hold
         select 1 from public.publisher_payout_holds h
          where h.publisher_id = p.id and h.released_at is null)
     order by p.created_at
     limit p_limit
     for update of p
  loop
    begin
      v_payable := app.publisher_payable_micros(rec.id, p_hold);
    exception when others then
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'payable_error', 'detail', sqlerrm);
      continue;
    end;

    v_payable := (v_payable / 10000) * 10000;

    if v_payable < p_min_micros then
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'below_min', 'payable_micros', v_payable);
      continue;
    end if;
    if v_payable > p_velocity_max_micros then
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'velocity_cap', 'payable_micros', v_payable);
      continue;
    end if;

    begin
      insert into public.payouts (publisher_id, amount_micros, status, hold_until, min_payout_micros)
      values (rec.id, v_payable, 'pending', now(), p_min_micros)
      returning id into v_id;
    exception when unique_violation then
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'already_reserved');
      continue;
    end;

    reserved := reserved || jsonb_build_object('publisher_id', rec.id, 'payout_id', v_id, 'amount_micros', v_payable);
  end loop;

  return jsonb_build_object('reserved', reserved, 'skipped', skipped);
end;
$$;
revoke all on function public.payout_batch_reserve(interval, bigint, bigint, int) from public, anon, authenticated;
grant execute on function public.payout_batch_reserve(interval, bigint, bigint, int) to service_role;

comment on function public.payout_batch_reserve is
  'Phase 1 reserve (no ledger). One-active-per-publisher index is the reservation lock; FOR UPDATE OF p '
  'serializes vs admin_open_clawback; default hold = app.payout_hold_interval(). A2: also excludes any '
  'publisher with an unreleased publisher_payout_holds row. Transfer/confirm core untouched.';

-- ---- 2. set_publisher_payout_eligibility — do not restore 'verified' over an open hold.
create or replace function public.set_publisher_payout_eligibility(p_stripe_account_id text, p_status text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_n          integer;
  v_suppressed integer := 0;
begin
  if p_status not in ('none', 'pending', 'verified', 'ineligible_country') then
    raise exception 'invalid payout_status: %', p_status using errcode = '22023';
  end if;

  update public.publishers p
     set payout_status = case
       when p_status = 'verified'
            and exists (select 1 from public.publisher_payout_holds h
                         where h.publisher_id = p.id and h.released_at is null)
         then 'pending'::public.payout_status         -- A2: a fraud hold outranks Stripe's verified
       else p_status::public.payout_status
     end
   where p.stripe_account_id = p_stripe_account_id;
  get diagnostics v_n = row_count;

  if p_status = 'verified' then
    select count(*) into v_suppressed
      from public.publishers p
     where p.stripe_account_id = p_stripe_account_id
       and exists (select 1 from public.publisher_payout_holds h
                    where h.publisher_id = p.id and h.released_at is null);
  end if;

  return jsonb_build_object('ok', true, 'updated', v_n, 'hold_suppressed', v_suppressed);
end;
$$;
revoke all on function public.set_publisher_payout_eligibility(text, text) from public, anon, authenticated;
grant execute on function public.set_publisher_payout_eligibility(text, text) to service_role;

comment on function public.set_publisher_payout_eligibility is
  'Set a publisher''s payout_status from a Stripe account.updated callback. A2: never RAISES to '
  '''verified'' while an unreleased publisher_payout_holds row exists (a fraud hold outranks Stripe''s '
  'verified — held stays ''pending''); returns hold_suppressed count. Every other status passes through.';

-- Migration-tail assertion — anon holds NO EXECUTE on either recreated money RPC.
do $$
declare
  v_fn  text;
  v_fns text[] := array[
    'public.payout_batch_reserve(interval, bigint, bigint, int)',
    'public.set_publisher_payout_eligibility(text, text)'
  ];
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    end if;
  end loop;
end $$;
