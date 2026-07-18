-- lumaline M9-T6 — advertiser prepay ledger-health invariants, drift alerting, and the recon split.
--
-- Prepay rides the existing zero-sum book but introduces caches (advertiser_balances.balance/reserved)
-- and two new liability/loss accounts (advertiser_funds / advertiser_bad_debt, 20260716160000) that
-- the postpay reconcile (GET /billing/reconcile) knows nothing about. This migration makes prepay
-- ACTIVELY reconciled and keeps the postpay reconcile green:
--
--   1. public.advertiser_ledger_health() — the admin read that ASSERTS the prepay money invariants
--      per advertiser and rolls them into aggregate booleans (mirrors admin_ledger_health.sql:30-105:
--      SECDEF STABLE, first-line app.is_admin() RAISE 28000, REVOKE anon/public, GRANT authenticated).
--      The invariants:
--        (A) BALANCE  — balance_micros == −SUM(cleared advertiser_funds legs) per advertiser (the
--                       held-liability backs the spendable cache exactly).
--        (B) SOLVENCY — balance_micros >= 0 (CHECK-backed) AND balance_micros >= reserved_micros.
--        (C) RESERVED — reserved_micros == SUM(ad_windows.reserve_micros) over the advertiser's windows
--                       (the BACKED-reserve invariant; flags ANY nonzero delta, not just <0).
--        (D) ZERO-SUM — every advertiser-dimensioned ledger group sums to 0 per advertiser (detects a
--                       mis-booked/ bypassed leg the deferred group trigger would otherwise be the only
--                       guard for).
--        (E) BAD-DEBT — SUM(advertiser_bad_debt) surfaced (the chargeback write-off is visible + alerted,
--                       never a silent Stripe-vs-book divergence).
--
--   2. public.advertiser_health_sync() — the service_role monitor wiring: recomputes the drift breaches
--      (balance drift / reserved drift / negative available) and fires+resolves them through the SAME
--      public.monitor_sync_alerts (money_monitoring.sql:130-179) the money monitor uses, on ANY nonzero
--      delta. Distinct check names from the draw-down solvency alarms (advertiser_reserved_underflow /
--      advertiser_insufficient_balance emitted by app.advertiser_alert, 20260716170000), so a health
--      run never resolves a live draw-down alarm and vice-versa.
--
--   3. MODIFY public.billing_recon_totals + app.v_billing_recon (recon_cpva_only.sql:11-49) — join the
--      cleared cpva_accrual advertiser_billing legs up to the advertiser and EXCLUDE billing_mode=
--      'prepay'. Prepay accruals have NO source=lumaline PaymentIntent (they draw down a balance), so
--      without this the accrual==Stripe identity behind GET /reconcile goes permanently RED the moment
--      the first prepay impression clears — training operators to ignore a red reconcile. Postpay totals
--      are byte-identical (the LEFT JOIN + IS DISTINCT FROM keeps every non-prepay/unresolved row).
--
-- clear_events + app.accrue are UNTOUCHED. This migration is READ-ONLY on money tables except the
-- monitor's own app.alert_events (written only through monitor_sync_alerts). SECDEF, search_path=''.
--
-- DEPENDS ON: 20260716160000 (advertiser_funds / advertiser_bad_debt / ledger_entries.advertiser_id),
-- 20260716170000 (advertiser_balances, ad_windows.reserve_micros, advertiser_balance_ledger),
-- 20260702010000 (app.alert_events + public.monitor_sync_alerts), 20260629066000 (the recon it modifies).

-- ===========================================================================
-- 1. public.advertiser_ledger_health() — admin read + per-advertiser invariant assertions.
-- ===========================================================================
CREATE OR REPLACE FUNCTION public.advertiser_ledger_health()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v jsonb;
BEGIN
  -- The real gate: admin membership re-checked in-body (aal1 read suffices, like admin_ledger_health).
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  SELECT jsonb_build_object(
    'advertisers_count',
      (SELECT count(*) FROM public.advertiser_balances),

    -- Headline totals.
    'total_balance_micros',
      COALESCE((SELECT sum(balance_micros)  FROM public.advertiser_balances), 0),
    'total_reserved_micros',
      COALESCE((SELECT sum(reserved_micros) FROM public.advertiser_balances), 0),
    -- Held-deposit liability magnitude (advertiser_funds carried negative → negate).
    'total_held_liability_micros',
      COALESCE((SELECT -sum(amount_micros) FROM public.ledger_entries
                 WHERE account = 'advertiser_funds' AND state = 'cleared'), 0),
    -- (E) Bad debt surfaced (the chargeback write-off).
    'total_bad_debt_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.ledger_entries
                 WHERE account = 'advertiser_bad_debt' AND state = 'cleared'), 0),
    'total_deposited_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.advertiser_balance_ledger WHERE kind = 'deposit'), 0),
    'total_drawn_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.advertiser_balance_ledger WHERE kind = 'drawdown'), 0),

    -- (A) BALANCE identity drift: advertisers whose balance <> −SUM(cleared advertiser_funds legs).
    -- Uses the single-source app.advertiser_expected_balance so the read + monitor never diverge.
    'balance_drift_count',
      (SELECT count(*) FROM public.advertiser_balances b
        WHERE b.balance_micros <> app.advertiser_expected_balance(b.advertiser_id)),

    -- (C) RESERVED identity drift: advertisers whose reserved <> the BACKED-reserve target
    -- (SUM(ad_windows.reserve_micros) EXCLUDING clawed_back/void windows). Single-source
    -- app.advertiser_expected_reserved so a clawback-before-drawdown is DETECTED here (and
    -- self-healed by advertiser_reconcile_reserved), not silently "confirmed" as the stale value.
    'reserved_drift_count',
      (SELECT count(*) FROM public.advertiser_balances b
        WHERE b.reserved_micros <> app.advertiser_expected_reserved(b.advertiser_id)),

    -- (B) SOLVENCY: any advertiser with reserved > balance (available < 0), and any negative balance
    -- (CHECK-backed, so expected 0 — asserting it here catches a bypass).
    'available_negative_count',
      (SELECT count(*) FROM public.advertiser_balances WHERE reserved_micros > balance_micros),
    'balance_negative_count',
      (SELECT count(*) FROM public.advertiser_balances WHERE balance_micros < 0),

    -- (D) ZERO-SUM: advertiser-dimensioned groups that do not sum to 0 per advertiser (expected 0).
    'per_advertiser_unbalanced_count',
      (SELECT count(*) FROM (
         SELECT le.advertiser_id
           FROM public.ledger_entries le
          WHERE le.advertiser_id IS NOT NULL
          GROUP BY le.advertiser_id
         HAVING sum(le.amount_micros) <> 0) g)
  ) INTO v;

  -- Derived booleans (all-green when every invariant holds).
  RETURN v || jsonb_build_object(
    'balance_identity_ok',      (v->>'balance_drift_count')::int = 0,
    'reserved_identity_ok',     (v->>'reserved_drift_count')::int = 0,
    'solvency_ok',              (v->>'available_negative_count')::int = 0
                                AND (v->>'balance_negative_count')::int = 0,
    'per_advertiser_zero_sum_ok', (v->>'per_advertiser_unbalanced_count')::int = 0,
    'held_liability_matches_balance',
      (v->>'total_balance_micros')::bigint = (v->>'total_held_liability_micros')::bigint
  );
END;
$$;
REVOKE ALL     ON FUNCTION public.advertiser_ledger_health() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_ledger_health() TO authenticated;

COMMENT ON FUNCTION public.advertiser_ledger_health IS
  'Admin-only prepay ledger-health aggregate + invariant assertions: BALANCE (balance == −SUM advertiser_funds), SOLVENCY (balance>=0, balance>=reserved), RESERVED (reserved == SUM ad_windows.reserve_micros), per-advertiser ZERO-SUM, and BAD-DEBT surfaced — with *_ok booleans + drift counts. First-line app.is_admin() RAISE 28000; STABLE; mirrors admin_ledger_health. The prepay counterpart to GET /reconcile (which now excludes prepay).';

-- ===========================================================================
-- 2. public.advertiser_health_sync() — fire/resolve drift alerts via monitor_sync_alerts.
--
-- Recomputes the drift breaches and routes them through the SAME atomic fire+resolve the money
-- monitor uses (partial-unique open dedup, resolve on recovery). Fires on ANY nonzero delta (both a
-- lost hold and an over-hold). service_role only (the monitor path). The check names are DISTINCT from
-- the draw-down alarms (advertiser_reserved_underflow / advertiser_insufficient_balance), so this run
-- never resolves a live solvency alarm — monitor_sync_alerts only touches its p_evaluated_checks.
-- ===========================================================================
CREATE OR REPLACE FUNCTION public.advertiser_health_sync()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_alerts jsonb;
  v_result jsonb;
BEGIN
  SELECT COALESCE(jsonb_agg(a), '[]'::jsonb) INTO v_alerts FROM (
    -- (A) BALANCE identity drift → critical (spendable cache diverged from the held liability).
    SELECT jsonb_build_object(
             'check_name', 'advertiser_balance_drift', 'severity', 'critical',
             'dedup_key',  'advertiser_balance_drift:' || d.advertiser_id::text,
             'payload',    jsonb_build_object('advertiser_id', d.advertiser_id,
                             'balance_micros', d.balance_micros, 'expected_micros', d.expected)) AS a
      FROM (
        SELECT b.advertiser_id, b.balance_micros,
               app.advertiser_expected_balance(b.advertiser_id) AS expected
          FROM public.advertiser_balances b) d
     WHERE d.balance_micros <> d.expected

    UNION ALL

    -- (C) RESERVED identity drift → high (the backed-reserve invariant broke).
    SELECT jsonb_build_object(
             'check_name', 'advertiser_reserved_drift', 'severity', 'high',
             'dedup_key',  'advertiser_reserved_drift:' || d.advertiser_id::text,
             'payload',    jsonb_build_object('advertiser_id', d.advertiser_id,
                             'reserved_micros', d.reserved_micros, 'expected_micros', d.expected)) AS a
      FROM (
        SELECT b.advertiser_id, b.reserved_micros,
               app.advertiser_expected_reserved(b.advertiser_id) AS expected
          FROM public.advertiser_balances b) d
     WHERE d.reserved_micros <> d.expected

    UNION ALL

    -- (B) SOLVENCY: reserved exceeds balance (available < 0) → critical.
    SELECT jsonb_build_object(
             'check_name', 'advertiser_available_negative', 'severity', 'critical',
             'dedup_key',  'advertiser_available_negative:' || b.advertiser_id::text,
             'payload',    jsonb_build_object('advertiser_id', b.advertiser_id,
                             'balance_micros', b.balance_micros, 'reserved_micros', b.reserved_micros)) AS a
      FROM public.advertiser_balances b
     WHERE b.reserved_micros > b.balance_micros
  ) x;

  v_result := public.monitor_sync_alerts(
    ARRAY['advertiser_balance_drift', 'advertiser_reserved_drift', 'advertiser_available_negative'],
    v_alerts);

  RETURN v_result;
END;
$$;
REVOKE ALL     ON FUNCTION public.advertiser_health_sync() FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION public.advertiser_health_sync() TO service_role;

COMMENT ON FUNCTION public.advertiser_health_sync IS
  'Service_role monitor wiring for prepay drift: recomputes balance-identity / reserved-identity / negative-available breaches and fires+resolves them via public.monitor_sync_alerts (fires on ANY nonzero delta). Check names are distinct from the draw-down solvency alarms so neither run resolves the other. Schedule alongside app.run_monitor at deploy.';

-- ===========================================================================
-- 3. billing_recon_totals + app.v_billing_recon — exclude prepay so GET /reconcile stays green.
--
-- The postpay reconcile compares cleared cpva_accrual advertiser_billing debits against source=lumaline
-- succeeded PaymentIntents. Prepay accruals have no PI (they draw down a balance), so they must be
-- excluded from BOTH artefacts or the accrual==Stripe identity goes permanently red. LEFT JOIN the
-- advertiser chain and keep every row whose advertiser is NOT prepay (IS DISTINCT FROM also keeps an
-- unresolved advertiser as non-prepay), so postpay totals are byte-identical to the pre-M9 recon.
-- ===========================================================================
CREATE OR REPLACE VIEW app.v_billing_recon AS
  SELECT
    date_trunc('day', le.created_at)                                             AS day,
    SUM(CASE WHEN le.amount_micros > 0 THEN le.amount_micros ELSE 0 END)::bigint AS debited_micros,
    COUNT(*)::bigint                                                              AS entry_count
  FROM public.ledger_entries le
  LEFT JOIN public.impressions i  ON i.id  = le.source_id
  LEFT JOIN public.line_items  li ON li.id = i.line_item_id
  LEFT JOIN public.campaigns   c  ON c.id  = li.campaign_id
  LEFT JOIN public.advertisers a  ON a.id  = c.advertiser_id
  WHERE le.account    = 'advertiser_billing'
    AND le.event_type = 'cpva_accrual'          -- cpva only; cpc billing lands in M3
    AND le.state      = 'cleared'
    AND a.billing_mode IS DISTINCT FROM 'prepay'   -- M9: prepay is reconciled by advertiser_ledger_health
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
  LEFT JOIN public.impressions i  ON i.id  = le.source_id
  LEFT JOIN public.line_items  li ON li.id = i.line_item_id
  LEFT JOIN public.campaigns   c  ON c.id  = li.campaign_id
  LEFT JOIN public.advertisers a  ON a.id  = c.advertiser_id
  WHERE le.account    = 'advertiser_billing'
    AND le.event_type = 'cpva_accrual'          -- cpva only; cpc billing lands in M3
    AND le.state      = 'cleared'
    AND le.created_at >= from_ts
    AND le.created_at <= to_ts
    AND a.billing_mode IS DISTINCT FROM 'prepay';   -- M9: prepay reconciled by advertiser_ledger_health
$$;

REVOKE ALL ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) TO service_role;

COMMENT ON FUNCTION public.billing_recon_totals IS
  'Aggregate cleared advertiser_billing CPVA debits for [from_ts, to_ts], EXCLUDING billing_mode=''prepay'' advertisers (M9: prepay has no Stripe PI — reconciled by advertiser_ledger_health instead). Used by GET /billing/reconcile so the accrual==PI identity counts only postpay. Postpay totals byte-identical to the pre-M9 recon.';

-- ===========================================================================
-- 4. Migration-tail assertion — anon must hold NO EXECUTE on any function added/modified here.
-- ===========================================================================
DO $$
DECLARE
  v_fn  text;
  v_fns text[] := ARRAY[
    'public.advertiser_ledger_health()',
    'public.advertiser_health_sync()',
    'public.billing_recon_totals(timestamptz, timestamptz)'
  ];
BEGIN
  FOREACH v_fn IN ARRAY v_fns LOOP
    IF has_function_privilege('anon', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    END IF;
  END LOOP;
END;
$$;
