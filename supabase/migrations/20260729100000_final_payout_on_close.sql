-- lumaline GDPR Phase 4 — a publisher who closes their account is paid EVERYTHING they earned.
--
-- The regular payout minimum (€25, p_min_micros) exists so a weekly batch does not fire dozens of
-- €0.30 transfers; it assumes the balance carries forward to next week. On account closure that
-- assumption dies: the account is erased and a sub-minimum balance would be stranded forever —
-- money the publisher earned and we would simply keep. So closure lifts the minimum down to
-- Stripe's own floor, one whole cent (10000 micros — the amount is already floored to whole cents
-- one line above, and a platform→connected-account transfer has no minimum and no per-transfer fee).
-- A zero balance still reserves nothing: payouts.amount_micros CHECK is (>= 0), so without the floor
-- a closing publisher with nothing owed would get a €0 pending payout and a Stripe transfer that
-- cannot succeed.
--
-- `publishers.deletion_requested_at` (20260727100000, GDPR Phase 3) is the closure marker. Phase 3
-- deliberately freezes a closing publisher by REVOKING THEIR DEVICES rather than flipping
-- `status`, precisely so the eligibility predicate below still admits them (see that file's §3
-- note). This migration is the other half of that contract.
--
-- ONE additive recreation: payout_batch_reserve, body copied VERBATIM from 20260722060000, with
-- exactly two edits — `deletion_requested_at` added to the candidate select-list, and the
-- below-minimum skip made conditional on not closing. EVERY other guard is untouched and still
-- applies to a closing publisher: payout_status='verified', stripe_account_id not null,
-- status='active', deleted_at is null, no unreleased publisher_payout_holds row (A2), no active
-- payout, and the velocity cap. Closure is NOT a way around a fraud hold.
--
-- Transfer/confirm core (payout_confirm/payout_fail/payout_reverse) and the reservation lock are
-- UNTOUCHED — the stated trust invariant.
--
-- Depends on: 20260722060000 (payout_batch_reserve body + A2 hold guard),
--             20260727100000 (publishers.deletion_requested_at).

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
    select p.id, p.deletion_requested_at              -- P4: the account-closure marker
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

    if v_payable < (case when rec.deletion_requested_at is null then p_min_micros else 10000 end) then
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
  'serializes vs admin_open_clawback; default hold = app.payout_hold_interval(). A2: excludes any '
  'publisher with an unreleased publisher_payout_holds row. P4 (GDPR): a publisher with '
  'deletion_requested_at set is paid down to Stripe''s floor (one whole cent) instead of p_min_micros, '
  'so a closing account never strands a sub-minimum balance; every other eligibility guard still '
  'applies to them. Transfer/confirm core untouched.';

-- Migration-tail assertion — anon holds NO EXECUTE on the recreated money RPC.
do $$
begin
  if has_function_privilege('anon', 'public.payout_batch_reserve(interval, bigint, bigint, int)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.payout_batch_reserve — REVOKE ALL FROM PUBLIC, anon missing';
  end if;
end $$;
