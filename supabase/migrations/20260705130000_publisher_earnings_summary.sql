-- lumaline M7 — publisher_earnings_summary() for the publisher web portal.
--
-- The portal's Overview/Earnings pages show three money figures a publisher cares
-- about: what is AVAILABLE to pay out now, what is still MATURING (cleared but inside
-- the 7-day hold), and LIFETIME earnings. None of these is readable by a plain web
-- session today:
--   * v_publisher_balance exposes only the CLEARED balance (earned/paid/reversed/balance),
--     where "cleared" is the 72h clawback window — NOT the 7-day payout hold.
--   * the matured-past-hold figure comes only from app.publisher_payable_micros(pid,'7 days'),
--     which is service_role-only (the payout batch's primitive) and unreachable by anon.
--
-- This RPC bridges that gap: it self-derives the publisher from app.current_publisher_id()
-- (so it only ever returns the CALLER's own numbers), reuses the exact same
-- app.publisher_payable_micros() the payout batch uses for `matured` (numbers the UI shows
-- therefore agree with what a payout will actually pay), and derives held = balance - matured.
--
-- SECURITY DEFINER (so it can call the service_role-only payable primitive) + a strict
-- publisher_id = self filter, mirroring publisher_payable_micros's self-scoping. STABLE,
-- read-only, granted to authenticated.
--
-- Ledger sign convention (see app.accrue / payout_confirm):
--   accrual publisher_earnings legs are NEGATIVE (owed to the publisher);
--   payout  publisher_earnings legs are POSITIVE (+amount, reduces what is owed),
--   a reversal adds the mirror (-amount) so a reversed payout nets to zero.
-- Filtering by event_type keeps `lifetime` (accruals only) and `paid` (payout legs, net of
-- reversals) from contaminating each other.

CREATE OR REPLACE FUNCTION public.publisher_earnings_summary()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_pid      uuid;
  v_lifetime bigint;   -- gross cleared accrual earnings, ever
  v_paid     bigint;   -- net of reversals (payout legs sum)
  v_balance  bigint;   -- net owed = lifetime - paid
  v_matured  bigint;   -- available to pay out now (past the 7-day hold, minus paid)
BEGIN
  v_pid := (SELECT app.current_publisher_id());
  IF v_pid IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  SELECT
    COALESCE(-sum(amount_micros) FILTER (
      WHERE state = 'cleared' AND event_type IN ('cpva_accrual', 'cpc_accrual')), 0),
    COALESCE( sum(amount_micros) FILTER (
      WHERE state = 'cleared' AND event_type = 'payout'), 0),
    COALESCE(-sum(amount_micros) FILTER (WHERE state = 'cleared'), 0)
  INTO v_lifetime, v_paid, v_balance
  FROM public.ledger_entries
  WHERE account = 'publisher_earnings' AND publisher_id = v_pid;

  -- Same primitive the payout batch uses, so "available" matches what actually pays.
  -- (Raises loudly if a cpc_accrual leg is present — CPC payouts are not wired; CPVA only.)
  v_matured := app.publisher_payable_micros(v_pid, interval '7 days');

  RETURN jsonb_build_object(
    'matured_micros',  v_matured,
    'held_micros',     v_balance - v_matured,
    'lifetime_micros', v_lifetime,
    'paid_micros',     v_paid,
    'balance_micros',  v_balance
  );
END;
$$;
REVOKE ALL ON FUNCTION public.publisher_earnings_summary() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.publisher_earnings_summary() TO authenticated;

COMMENT ON FUNCTION public.publisher_earnings_summary IS
  'Self-serve earnings summary for the publisher portal: {matured_micros (=app.publisher_payable_micros 7d), held_micros (=balance-matured), lifetime_micros, paid_micros, balance_micros} for the caller''s own publisher (app.current_publisher_id()). SECURITY DEFINER + self-filter; STABLE; granted to authenticated.';
