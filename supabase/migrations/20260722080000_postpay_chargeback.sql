-- lumaline security-audit (Cluster C / A9) — postpay CPVA chargeback bad-debt. A disputed postpay
-- PaymentIntent's cash is reclaimed by the bank while the ledger still shows the charge collected and
-- the publisher keeps 60%. Book a zero-sum platform-borne bad-debt group (never claw the publisher)
-- and dedup on the Stripe dispute id. Depends on 20260716160000 (advertiser_bad_debt / platform_cash
-- accounts + ledger_entries.advertiser_id dimension), 20260629050000 (advertiser_charges).

-- Idempotency arbiter + admin-visible record. Keyed on the Stripe dispute id (its own namespace,
-- SEPARATE from advertiser_balance_ledger.dispute_id which arbitrates DEPOSIT chargebacks — a given PI
-- is either a postpay charge or a deposit, never both).
create table if not exists public.advertiser_postpay_chargebacks (
  dispute_id         text primary key,                                   -- Stripe dispute id
  advertiser_id      uuid references public.advertisers (id),
  payment_intent_id  text not null,
  amount_micros      bigint not null,
  entry_group_id     uuid,                                               -- the zero-sum bad-debt group
  created_at         timestamptz not null default now()
);
comment on table public.advertiser_postpay_chargebacks is
  'One row per postpay CPVA PaymentIntent dispute (idempotency arbiter, dedup on Stripe dispute_id). '
  'The paired zero-sum bad-debt ledger group is platform_cash -R / advertiser_bad_debt +R. '
  'Admin-visible; written only by app.book_postpay_chargeback (service_role).';

create index if not exists advertiser_postpay_chargebacks_adv_idx
  on public.advertiser_postpay_chargebacks (advertiser_id, created_at desc);
create index if not exists advertiser_postpay_chargebacks_created_idx
  on public.advertiser_postpay_chargebacks (created_at desc);

alter table public.advertiser_postpay_chargebacks enable row level security;
drop policy if exists advertiser_postpay_chargebacks_admin_read on public.advertiser_postpay_chargebacks;
create policy advertiser_postpay_chargebacks_admin_read on public.advertiser_postpay_chargebacks
  for select to authenticated using ((select app.is_admin()));
drop policy if exists advertiser_postpay_chargebacks_service on public.advertiser_postpay_chargebacks;
create policy advertiser_postpay_chargebacks_service on public.advertiser_postpay_chargebacks
  for all to service_role using (true) with check (true);

revoke all    on public.advertiser_postpay_chargebacks from public, anon;
grant  select on public.advertiser_postpay_chargebacks to authenticated;   -- admin-gated by RLS
grant  select, insert on public.advertiser_postpay_chargebacks to service_role;

-- The bad-debt writer. Resolves the advertiser from the postpay charge(s) keyed by the disputed PI; a
-- non-postpay PI (e.g. a prepay deposit dispute that also fanned out to this endpoint) returns a clean
-- no-op. Idempotent on dispute_id. Zero-sum. Never touches advertiser_billing (delivery was real; the
-- publisher earned it) so billing_recon stays consistent — the loss is surfaced via the monitor instead.
create or replace function app.book_postpay_chargeback(
  p_payment_intent_id text, p_dispute_id text, p_amount_micros bigint, p_reason text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_group     uuid := gen_random_uuid();
  v_hit       text;
  v_adv       uuid;
  v_collected bigint;
  v_amt       bigint;
begin
  if p_payment_intent_id is null or p_payment_intent_id = ''
     or p_dispute_id is null or p_dispute_id = '' then
    raise exception 'book_postpay_chargeback: payment_intent_id + dispute_id required' using errcode = '22004';
  end if;
  if p_amount_micros is null or p_amount_micros <= 0 then
    raise exception 'book_postpay_chargeback: amount must be positive (got %)', p_amount_micros using errcode = '22003';
  end if;

  -- Resolve the paying advertiser + total collected on this PI (a postpay batch settles many
  -- entry-groups onto ONE PaymentIntent, all the same advertiser).
  select ac.advertiser_id, coalesce(sum(ac.amount_micros), 0)
    into v_adv, v_collected
    from public.advertiser_charges ac
   where ac.stripe_charge_id = p_payment_intent_id
     and ac.settled_via = 'stripe'
     and ac.status = 'succeeded'
   group by ac.advertiser_id
   order by ac.advertiser_id
   limit 1;

  -- Not a postpay charge (likely a deposit dispute that fanned out here) -> clean no-op.
  if v_adv is null then
    return jsonb_build_object('booked', false, 'reason', 'no_matching_postpay_charge',
                              'payment_intent_id', p_payment_intent_id);
  end if;

  -- Cap the write-off at what we actually collected on this PI (defense vs an over-stated amount).
  v_amt := least(p_amount_micros, v_collected);
  if v_amt <= 0 then
    return jsonb_build_object('booked', false, 'reason', 'nothing_collected',
                              'payment_intent_id', p_payment_intent_id);
  end if;

  -- Idempotency arbiter: insert the chargeback row FIRST. A re-delivered dispute event -> no row -> no book.
  insert into public.advertiser_postpay_chargebacks
    (dispute_id, advertiser_id, payment_intent_id, amount_micros, entry_group_id)
  values (p_dispute_id, v_adv, p_payment_intent_id, v_amt, v_group)
  on conflict (dispute_id) do nothing
  returning dispute_id into v_hit;
  if v_hit is null then
    return jsonb_build_object('booked', false, 'reason', 'duplicate', 'dispute_id', p_dispute_id);
  end if;

  -- Zero-sum bad-debt group: platform_cash -R (bank reclaimed the collected cash) / advertiser_bad_debt
  -- +R (platform write-off). advertiser_billing is UNTOUCHED (see header) -> billing_recon unaffected.
  insert into public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
  values
    (v_group, 'postpay_chargeback', 'platform_cash',      -v_amt, 'cleared', 'advertiser_dispute', v_adv, v_adv),
    (v_group, 'postpay_chargeback', 'advertiser_bad_debt',  v_amt, 'cleared', 'advertiser_dispute', v_adv, v_adv);

  -- Defense: stop further postpay accrual against a disputing/bad payer (mirrors the billing decline
  -- pause + the deposit-reversal pause). line_item status only -> does NOT trip advertisers_protect_cols.
  update public.line_items li set status = 'paused'
   where li.status = 'active'
     and li.campaign_id in (select c.id from public.campaigns c where c.advertiser_id = v_adv);

  return jsonb_build_object('booked', true, 'advertiser_id', v_adv, 'dispute_id', p_dispute_id,
                            'bad_debt_micros', v_amt, 'entry_group_id', v_group);
end;
$$;
revoke all on function app.book_postpay_chargeback(text, text, bigint, text) from public, anon, authenticated;
grant  execute on function app.book_postpay_chargeback(text, text, bigint, text) to service_role;

comment on function app.book_postpay_chargeback is
  'Postpay CPVA chargeback bad-debt write-off (idempotent on Stripe dispute_id). Resolves the advertiser '
  'from advertiser_charges by disputed PaymentIntent id; books zero-sum platform_cash -R / '
  'advertiser_bad_debt +R (loss is platform-borne, never clawed from paid publishers), caps R at '
  'collected, pauses the advertiser''s active line_items. A non-postpay PI -> clean no-op. service_role only.';

-- Migration-tail assertion — anon holds NO EXECUTE.
do $$
begin
  if has_function_privilege('anon', 'app.book_postpay_chargeback(text, text, bigint, text)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on app.book_postpay_chargeback';
  end if;
end $$;
