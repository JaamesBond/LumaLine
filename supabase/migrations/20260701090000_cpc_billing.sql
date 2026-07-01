-- lumaline M4-T2 / carry-forward #1 — wire cpc_accrual into billing, recon, and payout.
--
-- Before M4: cpc_accrual ledger legs were accrued by clear_events() but (a) excluded from
-- uncharged_advertiser_billings (CPVA-only join), (b) excluded from recon, (c) a loud RAISE
-- guard in publisher_payable_micros blocked any publisher who had a cleared CPC earning.
-- This migration makes CPC first-class in all three, keeping the CPVA behaviour identical.
--
-- CPC join path differs from CPVA: cpc_accrual.source_type='click', source_id=clicks.id,
-- so the advertiser chain is clicks -> line_items -> campaigns -> advertisers (NOT impressions).

-- 1. Billing view: add a clicks-sourced UNION branch for cpc_accrual.
--    CREATE OR REPLACE keeps the identical column list/types; branch 1 is the unchanged CPVA
--    query (now explicit about source_type='impression'), branch 2 is the CPC path.
CREATE OR REPLACE VIEW public.uncharged_advertiser_billings AS
SELECT
  le.entry_group_id, le.event_type, le.amount_micros,
  le.source_id AS impression_id, i.line_item_id, i.publisher_id,
  li.campaign_id, c.advertiser_id, a.name AS advertiser_name,
  a.is_house, a.stripe_customer_id, le.created_at AS cleared_at
FROM public.ledger_entries le
JOIN public.impressions i  ON i.id  = le.source_id
JOIN public.line_items  li ON li.id = i.line_item_id
JOIN public.campaigns   c  ON c.id  = li.campaign_id
JOIN public.advertisers a  ON a.id  = c.advertiser_id
LEFT JOIN public.advertiser_charges ac ON ac.entry_group_id = le.entry_group_id
WHERE le.account    = 'advertiser_billing'
  AND le.state      = 'cleared'
  AND le.event_type = 'cpva_accrual'
  AND le.source_type = 'impression'
  AND ac.entry_group_id IS NULL
UNION ALL
SELECT
  le.entry_group_id, le.event_type, le.amount_micros,
  NULL::uuid AS impression_id, cl.line_item_id, cl.publisher_id,
  li.campaign_id, c.advertiser_id, a.name AS advertiser_name,
  a.is_house, a.stripe_customer_id, le.created_at AS cleared_at
FROM public.ledger_entries le
JOIN public.clicks      cl ON cl.id = le.source_id
JOIN public.line_items  li ON li.id = cl.line_item_id
JOIN public.campaigns   c  ON c.id  = li.campaign_id
JOIN public.advertisers a  ON a.id  = c.advertiser_id
LEFT JOIN public.advertiser_charges ac ON ac.entry_group_id = le.entry_group_id
WHERE le.account    = 'advertiser_billing'
  AND le.state      = 'cleared'
  AND le.event_type = 'cpc_accrual'
  AND le.source_type = 'click'
  AND ac.entry_group_id IS NULL;

-- Re-assert the hardened posture (CREATE OR REPLACE can reset options/grants).
REVOKE ALL ON public.uncharged_advertiser_billings FROM anon, authenticated;
ALTER VIEW public.uncharged_advertiser_billings SET (security_invoker = on);
GRANT SELECT ON public.uncharged_advertiser_billings TO service_role;

-- 2. Recon view + totals fn: include cpc_accrual (both just SUM ledger_entries; no join to break).
CREATE OR REPLACE VIEW app.v_billing_recon AS
  SELECT
    date_trunc('day', created_at)                                            AS day,
    SUM(CASE WHEN amount_micros > 0 THEN amount_micros ELSE 0 END)::bigint  AS debited_micros,
    COUNT(*)::bigint                                                          AS entry_count
  FROM public.ledger_entries
  WHERE account    = 'advertiser_billing'
    AND event_type IN ('cpva_accrual', 'cpc_accrual')
    AND state      = 'cleared'
  GROUP BY 1
  ORDER BY 1 DESC;
-- Re-assert security_invoker on replace (private app schema, service_role-only; keeps the
-- "views are security_invoker=on" posture consistent even though this view is not PostgREST-reachable).
ALTER VIEW app.v_billing_recon SET (security_invoker = on);
GRANT SELECT ON app.v_billing_recon TO service_role;

CREATE OR REPLACE FUNCTION public.billing_recon_totals(from_ts timestamptz, to_ts timestamptz)
RETURNS TABLE (total_micros bigint, entry_count bigint)
LANGUAGE sql SECURITY DEFINER SET search_path = ''
AS $$
  SELECT COALESCE(SUM(le.amount_micros), 0)::bigint, COUNT(*)::bigint
  FROM public.ledger_entries le
  WHERE le.account    = 'advertiser_billing'
    AND le.event_type IN ('cpva_accrual', 'cpc_accrual')
    AND le.state      = 'cleared'
    AND le.created_at >= from_ts
    AND le.created_at <= to_ts;
$$;
REVOKE ALL ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) TO service_role;
COMMENT ON FUNCTION public.billing_recon_totals IS
  'Aggregate cleared advertiser_billing CPVA+CPC debits for [from_ts, to_ts]. Used by GET /billing/reconcile.';

-- 3. Payable fn: drop the loud CPC guard; add a clicks-sourced CPC earned term (matured by hold).
CREATE OR REPLACE FUNCTION app.publisher_payable_micros(p_publisher_id uuid, p_hold interval)
RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_earned_cpva bigint;
  v_earned_cpc  bigint;
  v_paid        bigint;
BEGIN
  SELECT COALESCE(-sum(le.amount_micros), 0) INTO v_earned_cpva
    FROM public.ledger_entries le
    JOIN public.impressions imp ON imp.id = le.source_id
   WHERE le.account = 'publisher_earnings' AND le.event_type = 'cpva_accrual'
     AND le.state = 'cleared' AND le.source_type = 'impression'
     AND le.publisher_id = p_publisher_id
     AND imp.created_at <= now() - p_hold;

  SELECT COALESCE(-sum(le.amount_micros), 0) INTO v_earned_cpc
    FROM public.ledger_entries le
    JOIN public.clicks cl ON cl.id = le.source_id
   WHERE le.account = 'publisher_earnings' AND le.event_type = 'cpc_accrual'
     AND le.state = 'cleared' AND le.source_type = 'click'
     AND le.publisher_id = p_publisher_id
     AND cl.created_at <= now() - p_hold;

  SELECT COALESCE(sum(le.amount_micros), 0) INTO v_paid
    FROM public.ledger_entries le
   WHERE le.account = 'publisher_earnings' AND le.event_type = 'payout'
     AND le.state = 'cleared' AND le.publisher_id = p_publisher_id;

  RETURN v_earned_cpva + v_earned_cpc - v_paid;
END;
$$;
REVOKE ALL ON FUNCTION app.publisher_payable_micros(uuid, interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.publisher_payable_micros(uuid, interval) TO service_role;
