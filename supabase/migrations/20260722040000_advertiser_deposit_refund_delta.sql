-- lumaline security-audit (Cluster D / A4) — partial-refund reversal must book DELTAs, not the full deposit.
--
-- charge.refunded carries the CUMULATIVE amount_refunded on the Charge object. The old edge path
-- read obj.amount (the FULL charge) and keyed dedup on the charge id, so a partial refund reversed
-- the whole deposit and a second partial refund on the same charge was deduped away. Fix mirrors
-- public.payout_reverse (20260629110000): store per-deposit cumulative implicitly (SUM of prior
-- kind='refund' rows for the PI) and book only the increase; a replay -> delta 0 -> no-op, serialized
-- by the advertiser_balances FOR UPDATE lock. Disputes stay on advertiser_apply_deposit_reversal.

-- 1. Link column so refund-reversal rows can be SUMmed per deposit PI (NOT unique; many deltas per PI).
alter table public.advertiser_balance_ledger
  add column if not exists reversal_pi_id text;

comment on column public.advertiser_balance_ledger.reversal_pi_id is
  'For kind=refund rows only: the deposit PaymentIntent this partial-refund delta reverses. Enables the '
  'per-PI cumulative SUM (DELTA-only booking, mirrors payout_reverse). NULL for every other kind; NOT '
  'unique (a deposit can be partially refunded many times).';

create index if not exists advertiser_balance_ledger_refund_pi_idx
  on public.advertiser_balance_ledger (reversal_pi_id) where kind = 'refund';

-- 2. app.advertiser_apply_deposit_refund — cumulative-delta refund reversal (partial-capable).
--    p_cumulative_micros = the charge's amount_refunded in EUR-micros (cumulative). Books only
--    delta = max(0, cumulative - already_reversed_for_this_PI); reclaim/bad-debt split IDENTICAL to
--    advertiser_apply_deposit_reversal, applied to the delta. Zero-sum group. Idempotent: a replay
--    or stale cumulative -> delta 0 -> {reversed:false, no_new_reversal}. service_role only.
create or replace function app.advertiser_apply_deposit_refund(
  p_advertiser        uuid,
  p_pi_id             text,
  p_event_id          text,
  p_cumulative_micros bigint)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_group   uuid := gen_random_uuid();
  v_bal     bigint;
  v_already bigint;
  v_delta   bigint;
  v_reclaim bigint;
  v_bad     bigint;
begin
  if p_advertiser is null or p_pi_id is null or p_pi_id = '' then
    raise exception 'advertiser_apply_deposit_refund: advertiser + pi_id are required' using errcode = '22004';
  end if;
  if p_cumulative_micros is null or p_cumulative_micros < 0 then
    raise exception 'advertiser_apply_deposit_refund: cumulative must be >= 0 (got %)', p_cumulative_micros using errcode = '22003';
  end if;

  -- Serialize all balance movements for this advertiser on the balance row (mirrors payout_reverse's
  -- FOR UPDATE on the payout row). A refund implies a prior credited deposit, so the row exists;
  -- create-then-relock defensively so the SUM below is always read under the lock.
  select balance_micros into v_bal
    from public.advertiser_balances where advertiser_id = p_advertiser for update;
  if not found then
    insert into public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
    values (p_advertiser, 0, 0) on conflict (advertiser_id) do nothing;
    select balance_micros into v_bal
      from public.advertiser_balances where advertiser_id = p_advertiser for update;
  end if;
  v_bal := coalesce(v_bal, 0);

  -- Cumulative already reversed for THIS deposit (PI). DELTA-only booking (mirrors payout_reverse:
  -- book target - already). Guarded by the balance-row lock, so the SUM is race-consistent.
  select coalesce(sum(amount_micros), 0) into v_already
    from public.advertiser_balance_ledger
   where advertiser_id = p_advertiser and kind = 'refund' and reversal_pi_id = p_pi_id;

  v_delta := greatest(0, p_cumulative_micros - v_already);
  if v_delta = 0 then
    return jsonb_build_object('reversed', false, 'reason', 'no_new_reversal',
                              'already_micros', v_already, 'pi_id', p_pi_id);
  end if;

  -- Reclaim/bad-debt split on the DELTA (identical to advertiser_apply_deposit_reversal).
  v_reclaim := least(v_delta, v_bal);   -- min(delta, balance)
  v_bad     := v_delta - v_reclaim;      -- max(0, delta - balance)

  -- Append-only sub-ledger row (delta amount, PI-scoped for the cumulative SUM). NULL on all three
  -- UNIQUE dedup keys (pi_id/charge_batch_id/dispute_id) — refund idempotency is the delta math.
  insert into public.advertiser_balance_ledger
    (advertiser_id, kind, amount_micros, reversal_pi_id, stripe_event_id, entry_group_id)
  values
    (p_advertiser, 'refund', v_delta, p_pi_id, p_event_id, v_group);

  -- Clamp spendable balance at 0 (never a CHECK(>=0) hard-stop).
  update public.advertiser_balances
     set balance_micros = balance_micros - v_reclaim, updated_at = now()
   where advertiser_id = p_advertiser;

  -- Zero-sum reversal group: platform_cash -delta / advertiser_funds +reclaim / advertiser_bad_debt +bad.
  insert into public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
  values
    (v_group, 'advertiser_chargeback', 'platform_cash',    -v_delta,   'cleared', 'advertiser_refund', p_advertiser, p_advertiser),
    (v_group, 'advertiser_chargeback', 'advertiser_funds',  v_reclaim, 'cleared', 'advertiser_refund', p_advertiser, p_advertiser);
  if v_bad > 0 then
    insert into public.ledger_entries
      (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
    values
      (v_group, 'advertiser_chargeback', 'advertiser_bad_debt', v_bad, 'cleared', 'advertiser_refund', p_advertiser, p_advertiser);
  end if;

  -- Parity with advertiser_apply_deposit_reversal: pause active line_items so refunded funds serve
  -- nothing further. (Conservative: any reversal of captured cash stops serving; ops can reactivate.)
  update public.line_items li
     set status = 'paused'
   where li.status = 'active'
     and li.campaign_id in (select c.id from public.campaigns c where c.advertiser_id = p_advertiser);

  return jsonb_build_object('reversed', true, 'advertiser_id', p_advertiser, 'pi_id', p_pi_id,
                            'delta_micros', v_delta, 'cumulative_micros', p_cumulative_micros,
                            'reclaimed_micros', v_reclaim, 'bad_debt_micros', v_bad,
                            'entry_group_id', v_group);
end;
$$;
revoke all on function app.advertiser_apply_deposit_refund(uuid, text, text, bigint) from public, anon, authenticated;
grant  execute on function app.advertiser_apply_deposit_refund(uuid, text, text, bigint) to service_role;

comment on function app.advertiser_apply_deposit_refund is
  'Cumulative-delta refund reversal (partial-capable, mirrors payout_reverse). p_cumulative_micros = '
  'charge.amount_refunded in EUR-micros; books only delta=max(0,cumulative - SUM(prior kind=refund rows '
  'for the PI)); replay/stale -> delta 0 -> no-op, serialized by the advertiser_balances lock. '
  'reclaim=min(delta,bal)/bad=max(0,delta-bal)/balance:=max(0,bal-delta); zero-sum Cr platform_cash / '
  'Dr advertiser_funds / Dr advertiser_bad_debt; pauses active line_items. service_role only.';

-- Migration-tail assertion — anon holds NO EXECUTE on the money RPC.
do $$
begin
  if has_function_privilege('anon', 'app.advertiser_apply_deposit_refund(uuid, text, text, bigint)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on app.advertiser_apply_deposit_refund';
  end if;
end $$;
