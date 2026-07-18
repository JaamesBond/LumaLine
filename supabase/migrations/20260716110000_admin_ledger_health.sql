-- lumaline M8-T1 — admin_ledger_health() global ledger-health aggregate for the owner dashboard.
--
-- The owner dashboard's Overview needs a single, cheap "is the book healthy?" read: the
-- transparency invariants (global zero-sum, per-group balance, the cleared accrual identity
-- advertiser_billing = publisher_earnings + platform_revenue, and the publisher split in bps)
-- plus the headline cleared / provisional / reversed totals. Pulling the whole ledger into the
-- browser to compute these would be needlessly wide and wasteful; this RPC ports the invariants
-- server-side and returns aggregate micros / booleans only.
--
-- Mirrors the publisher_earnings_summary.sql template (SECURITY DEFINER + STABLE +
-- SET search_path='' + a first-line app.is_admin() RAISE 28000 gate + REVOKE anon/public +
-- GRANT authenticated). is_admin() (aal1) suffices HERE: this is READ-ONLY — only the money
-- ACTIONS require the aal2 money tier (app.is_money_admin(), foundation migration
-- 20260716100000). The GRANT to authenticated is intentional and RLS-equivalent; the REAL gate
-- is the in-body re-check, and anon/public EXECUTE is REVOKED in THIS migration (Supabase
-- auto-grants anon EXECUTE on every NEW public function — the exact
-- 20260629120000_secdef_grant_hardening.sql footgun that already reached prod).
--
-- RATIONALE (corrected per critique): the value is aggregate/HAVING expressiveness + fewer rows
-- over the wire, NOT a data-minimization fix — ledger_entries carries no email / IP / cost /
-- token (ledger_and_payouts.sql:13-24), so an admin reading it raw is not a PII leak. Reads
-- ONLY public.ledger_entries.
--
-- Ledger sign convention (ledger_and_payouts.sql:3-8): advertiser_billing legs are POSITIVE
-- (+G), publisher_earnings and platform_revenue legs are NEGATIVE (-0.6G / -0.4G), and every
-- entry_group_id sums to 0 (enforced at COMMIT by the ledger_group_balances constraint trigger).
-- The publisher/platform figures below negate the sum so the emitted numbers read as positive
-- magnitudes. Enum values verified against enums.sql:34-40 (ledger_account, ledger_state).

CREATE OR REPLACE FUNCTION public.admin_ledger_health()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v jsonb;
BEGIN
  -- The real gate: re-check admin membership in-body on every call (RAISE 28000 = 403 over
  -- the Data API). The GRANT to authenticated only lets the request reach this line.
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  SELECT jsonb_build_object(
    -- Zero-sum: every committed group balances, so the global signed sum is always 0.
    'global_sum_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.ledger_entries), 0),
    -- HAVING expressiveness: count groups whose legs do NOT sum to 0 (expect 0).
    'unbalanced_group_count',
      (SELECT count(*) FROM (
         SELECT entry_group_id
         FROM public.ledger_entries
         GROUP BY entry_group_id
         HAVING sum(amount_micros) <> 0
       ) g),
    -- Cleared accrual receivable from advertisers (+, event_type = the two accrual kinds).
    'cleared_advertiser_billing_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'advertiser_billing' AND state = 'cleared'
                  AND event_type IN ('cpva_accrual', 'cpc_accrual')), 0),
    -- Cleared owed-to-publishers (negated to a positive magnitude).
    'cleared_publisher_earnings_micros',
      COALESCE((SELECT -sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'publisher_earnings' AND state = 'cleared'
                  AND event_type IN ('cpva_accrual', 'cpc_accrual')), 0),
    -- Cleared platform take (negated). platform_revenue is only ever booked by accruals
    -- (payouts move platform_cash), so no event_type filter is needed.
    'cleared_platform_revenue_micros',
      COALESCE((SELECT -sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'platform_revenue' AND state = 'cleared'), 0),
    -- Provisional receivable still inside the 72h clawback window.
    'provisional_advertiser_billing_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'advertiser_billing' AND state = 'provisional'), 0),
    -- Reversed (clawed-back) publisher earnings, ever (negated to a positive magnitude).
    'reversed_publisher_earnings_micros',
      COALESCE((SELECT -sum(amount_micros) FROM public.ledger_entries
                WHERE state = 'reversed' AND account = 'publisher_earnings'), 0)
  ) INTO v;

  -- Derived transparency booleans / ratio, computed from the aggregate above.
  RETURN v || jsonb_build_object(
    'zero_sum_ok',
      (v->>'global_sum_micros')::bigint = 0 AND (v->>'unbalanced_group_count')::int = 0,
    'accrual_identity_ok',
      (v->>'cleared_advertiser_billing_micros')::bigint
        = (v->>'cleared_publisher_earnings_micros')::bigint
        + (v->>'cleared_platform_revenue_micros')::bigint,
    'publisher_split_bps',
      CASE WHEN (v->>'cleared_advertiser_billing_micros')::bigint > 0
           THEN round((v->>'cleared_publisher_earnings_micros')::numeric
                      / (v->>'cleared_advertiser_billing_micros')::numeric * 10000)::int
           ELSE NULL END
  );
END;
$$;

REVOKE ALL     ON FUNCTION public.admin_ledger_health() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.admin_ledger_health() TO authenticated;

COMMENT ON FUNCTION public.admin_ledger_health IS
  'Admin-only global ledger-health aggregate for the owner-dashboard Overview: {global_sum_micros, unbalanced_group_count, cleared/provisional/reversed totals, zero_sum_ok, accrual_identity_ok, publisher_split_bps}. First-line app.is_admin() RAISE 28000; STABLE; reads only public.ledger_entries. Rationale: aggregate/HAVING expressiveness + fewer rows, not a PII fix (ledger_entries has no email/IP/cost/token).';
