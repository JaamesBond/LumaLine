-- lumaline security-audit (Cluster D / A6) — restore cpc_accrual in the billing recon.
--
-- M9 (20260716210000) recreated app.v_billing_recon + public.billing_recon_totals with
-- event_type = 'cpva_accrual' ONLY (to add the prepay LEFT-JOIN exclusion), silently reverting the
-- M4 fix (20260701090000) that had re-admitted cpc_accrual once CPC is charged. Live effect: cleared
-- CPC advertiser_billing debits ARE charged via Stripe but are absent from the DB side of
-- /billing/reconcile -> reconcile under-counts and reads red whenever CPC is billed.
--
-- Fix: restore event_type IN ('cpva_accrual','cpc_accrual') AND keep the M9 prepay exclusion. Resolve
-- the advertiser via BOTH source paths (impressions for cpva source_type='impression', clicks for cpc
-- source_type='click') so the exclusion is correct per kind. Prepay advertisers are structurally
-- CPVA-only (cpc_bid_micros=0 CHECK), so postpay CPVA totals are byte-identical to the M9 view; this
-- merely re-admits postpay CPC. This is the ONE authoritative billing_recon restore for the audit.

create or replace view app.v_billing_recon as
  select
    date_trunc('day', le.created_at)                                             as day,
    sum(case when le.amount_micros > 0 then le.amount_micros else 0 end)::bigint as debited_micros,
    count(*)::bigint                                                              as entry_count
  from public.ledger_entries le
  left join public.impressions i  on i.id  = le.source_id and le.source_type = 'impression'
  left join public.clicks      cl on cl.id = le.source_id and le.source_type = 'click'
  left join public.line_items  li on li.id = coalesce(i.line_item_id, cl.line_item_id)
  left join public.campaigns   c  on c.id  = li.campaign_id
  left join public.advertisers a  on a.id  = c.advertiser_id
  where le.account    = 'advertiser_billing'
    and le.event_type in ('cpva_accrual', 'cpc_accrual')   -- A6: CPC restored (was cpva-only in M9)
    and le.state      = 'cleared'
    and a.billing_mode is distinct from 'prepay'   -- M9: prepay reconciled by advertiser_ledger_health
  group by 1
  order by 1 desc;

alter view app.v_billing_recon set (security_invoker = on);   -- keep the hardened posture on replace
grant select on app.v_billing_recon to service_role;

create or replace function public.billing_recon_totals(
  from_ts timestamptz,
  to_ts   timestamptz
)
returns table (total_micros bigint, entry_count bigint)
language sql
security definer
set search_path = ''
as $$
  select
    coalesce(sum(le.amount_micros), 0)::bigint  as total_micros,
    count(*)::bigint                            as entry_count
  from public.ledger_entries le
  left join public.impressions i  on i.id  = le.source_id and le.source_type = 'impression'
  left join public.clicks      cl on cl.id = le.source_id and le.source_type = 'click'
  left join public.line_items  li on li.id = coalesce(i.line_item_id, cl.line_item_id)
  left join public.campaigns   c  on c.id  = li.campaign_id
  left join public.advertisers a  on a.id  = c.advertiser_id
  where le.account    = 'advertiser_billing'
    and le.event_type in ('cpva_accrual', 'cpc_accrual')   -- A6: CPC restored (was cpva-only in M9)
    and le.state      = 'cleared'
    and le.created_at >= from_ts
    and le.created_at <= to_ts
    and a.billing_mode is distinct from 'prepay';   -- M9: prepay reconciled by advertiser_ledger_health
$$;

revoke all on function public.billing_recon_totals(timestamptz, timestamptz) from public, anon;
grant execute on function public.billing_recon_totals(timestamptz, timestamptz) to service_role;

comment on function public.billing_recon_totals is
  'Aggregate cleared advertiser_billing CPVA+CPC debits for [from_ts, to_ts], EXCLUDING billing_mode=prepay '
  'advertisers (prepay has no Stripe PI — reconciled by advertiser_ledger_health). A6 restored cpc_accrual '
  '(M9 had reverted it to cpva-only); advertiser resolved via impressions (cpva) + clicks (cpc). '
  'Used by GET /billing/reconcile.';

-- Migration-tail assertion — anon holds NO EXECUTE on the recon function.
do $$
begin
  if has_function_privilege('anon', 'public.billing_recon_totals(timestamptz, timestamptz)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.billing_recon_totals — REVOKE ALL FROM PUBLIC, anon missing';
  end if;
end $$;
