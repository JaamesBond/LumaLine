-- lumaline M2-T5 — Reconciliation helper: day-bucketed view + period aggregate function.
--
-- Design: the /reconcile endpoint asserts that the sum of cleared advertiser_billing
-- ledger debits equals the sum of Stripe charges for the same period. This migration
-- provides two artefacts:
--
--   1. app.v_billing_recon (VIEW) — day-bucketed summary for human inspection via the
--      Supabase dashboard; not accessible through the PostgREST Data API (app schema
--      is NOT in the api.schemas list).
--
--   2. public.billing_recon_totals(from_ts, to_ts) (FUNCTION) — called by the billing
--      edge function's GET /reconcile endpoint to aggregate the DB side of the check
--      without hitting PostgREST's row-limit cap. SECURITY DEFINER so it can read
--      ledger_entries regardless of the caller's RLS context. Only service_role may call.
--
-- Known structural limitation (documented, not a bug):
--   Entries below the Stripe $0.50 minimum (50 cents = 500,000 micros) generate a cleared
--   ledger debit but NO Stripe charge — a structural discrepancy in any period that includes
--   such entries. House-advertiser entries are exempt: close_window() zeros their gross and
--   clear_events() filters gross_micros>0, so house impressions never produce ledger entries.
--   Additionally, ledger created_at (clearing time) and Stripe PI created (billing-run time)
--   can differ by hours/days, so a reconcile window that straddles a billing run may show a
--   transient split. The report is most useful over periods that cover a complete billing run.

-- ---------------------------------------------------------------------------
-- 1. app.v_billing_recon — day-bucketed summary (human-readable, admin-only).
-- ---------------------------------------------------------------------------
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

-- service_role only — this view is in the private app schema.
GRANT SELECT ON app.v_billing_recon TO service_role;

-- ---------------------------------------------------------------------------
-- 2. public.billing_recon_totals(from_ts, to_ts) — period aggregate.
--
-- Returns exactly one row: { total_micros, entry_count } covering all cleared
-- advertiser_billing accrual entries whose created_at falls within [from_ts, to_ts].
-- SECURITY DEFINER with fully-qualified names; REVOKE from PUBLIC so only service_role
-- can call it (matching the hardening pattern in 20260627040000_harden_function_grants.sql).
-- ---------------------------------------------------------------------------
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
    AND le.event_type IN ('cpva_accrual', 'cpc_accrual')
    AND le.state      = 'cleared'
    AND le.created_at >= from_ts
    AND le.created_at <= to_ts;
$$;

REVOKE ALL ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) TO service_role;

COMMENT ON FUNCTION public.billing_recon_totals IS
  'Aggregate cleared advertiser_billing debits for [from_ts, to_ts]. Used by GET /billing/reconcile.';
