-- lumaline M2 fixup — scope reconciliation to cpva_accrual only.
--
-- The original 20260629060000_recon.sql included both 'cpva_accrual' and 'cpc_accrual'
-- in the DB totals, but /billing/charge only charges cpva_accrual entries (the
-- uncharged_advertiser_billings view filters event_type = 'cpva_accrual'). Including
-- cpc_accrual in the DB sum while Stripe has no corresponding charge produces a guaranteed
-- non-zero discrepancy_micros the moment the first CPC impression clears — making the
-- reconciliation report permanently red. Fix: scope both artefacts to cpva_accrual until
-- CPC billing is implemented (M3).

CREATE OR REPLACE VIEW app.v_billing_recon AS
  SELECT
    date_trunc('day', created_at)                                            AS day,
    SUM(CASE WHEN amount_micros > 0 THEN amount_micros ELSE 0 END)::bigint  AS debited_micros,
    COUNT(*)::bigint                                                          AS entry_count
  FROM public.ledger_entries
  WHERE account    = 'advertiser_billing'
    AND event_type = 'cpva_accrual'   -- cpva only; cpc billing lands in M3
    AND state      = 'cleared'
  GROUP BY 1
  ORDER BY 1 DESC;

GRANT SELECT ON app.v_billing_recon TO service_role;

CREATE OR REPLACE FUNCTION public.billing_recon_totals(
  from_ts timestamptz,
  to_ts   timestamptz
)
RETURNS TABLE (total_micros bigint, entry_count bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT
    COALESCE(SUM(le.amount_micros), 0)::bigint  AS total_micros,
    COUNT(*)::bigint                             AS entry_count
  FROM public.ledger_entries le
  WHERE le.account    = 'advertiser_billing'
    AND le.event_type = 'cpva_accrual'          -- cpva only; cpc billing lands in M3
    AND le.state      = 'cleared'
    AND le.created_at >= from_ts
    AND le.created_at <= to_ts;
$$;

REVOKE ALL ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) TO service_role;

COMMENT ON FUNCTION public.billing_recon_totals IS
  'Aggregate cleared advertiser_billing CPVA debits for [from_ts, to_ts]. Used by GET /billing/reconcile. CPC billing (M3) will extend event_type to include cpc_accrual once /charge handles it.';
