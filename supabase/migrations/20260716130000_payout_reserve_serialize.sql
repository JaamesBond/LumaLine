-- lumaline M8-T7 (Phase 2 prerequisite) — serialize payout reserve vs manual clawback.
--
-- The SINGLE, minimal, ADDITIVE change that lets the new money action
-- public.admin_open_clawback (next migration, 20260716140000) be race-free against the
-- payout batch. It CREATE OR REPLACEs public.payout_batch_reserve with a body BYTE-IDENTICAL
-- to the shipped hardened version (20260629110000_payout_rails_hardening.sql:28-94 — which
-- carries the Finding-B per-publisher payable-error skip AND the Finding-C whole-cent floor)
-- except for exactly TWO additive edits:
--
--   1. p_hold's DEFAULT is sourced from app.payout_hold_interval() (20260716100000) instead
--      of a hardcoded interval '7 days'. This is the single source of truth the Phase-2
--      clawback guard's post-condition (app.publisher_payable_micros(pub,
--      app.payout_hold_interval()) >= 0) also reads, so the reserve maturity boundary and the
--      clawback money-safety boundary can NEVER diverge (the must-fix coupling the review
--      flagged). app.payout_hold_interval() returns interval '7 days', so the default is
--      byte-for-byte behaviour-identical for every existing caller.
--
--   2. FOR UPDATE OF p on the publisher SELECT. This takes a row lock on each eligible
--      publisher for the duration of the reserve txn. Combined with admin_open_clawback taking
--      SELECT ... FOR UPDATE on the SAME publisher row (plus its refuse-on-any-active-payout
--      check), the two operations SERIALIZE on the publisher row: a concurrent clawback blocks
--      until reserve commits (then re-reads a payable that reflects any reversal), and a
--      concurrent reserve blocks until the clawback commits. The exact-boundary reserve/clawback
--      race that could otherwise net publisher_payable negative is eliminated.
--
-- WHAT IS INTENTIONALLY NOT TOUCHED (money-safety by construction):
--   * The two-phase transfer/confirm core — payout_confirm / payout_fail / payout_reverse
--     (20260629100000_payout_rails.sql, 20260629110000_payout_rails_hardening.sql) — is
--     UNCHANGED. Nothing here books, reverses, or re-signs a ledger group.
--   * The reservation lock payouts_one_active_per_publisher (payout_rails.sql:50-52), the
--     eligibility predicate, the cent-floor, and the per-publisher error skip are preserved
--     verbatim. Only the row lock and the default-hold source are added.
--   * The auto-payout cron (app.run_payout, 20260704150000_auto_payout.sql:57-81) POSTs
--     /payout/batch with NO explicit p_hold, so it now resolves p_hold via
--     app.payout_hold_interval() = interval '7 days' — behaviour unchanged.
--
-- DEPLOY ORDERING: depends on 20260716100000 (app.payout_hold_interval must exist). Owner-gated,
-- adversarial-review-gated (Phase 2). service_role-only, as before.

-- ---------------------------------------------------------------------------
-- payout_batch_reserve — hardened body (B + C preserved) + additive lock + single-source hold.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.payout_batch_reserve(
  p_hold                interval default app.payout_hold_interval(),  -- was: interval '7 days'
  p_min_micros          bigint   default 25000000,
  p_velocity_max_micros bigint   default 10000000000,
  p_limit               int      default 100)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  rec       record;
  v_payable bigint;
  v_id      uuid;
  reserved  jsonb := '[]'::jsonb;
  skipped   jsonb := '[]'::jsonb;
BEGIN
  FOR rec IN
    SELECT p.id
      FROM public.publishers p
     WHERE p.payout_status = 'verified'
       AND p.stripe_account_id IS NOT NULL
       AND p.status = 'active'
       AND p.deleted_at IS NULL
       AND NOT EXISTS (
         SELECT 1 FROM public.payouts po
          WHERE po.publisher_id = p.id AND po.status IN ('pending', 'in_transit'))
     ORDER BY p.created_at
     LIMIT p_limit
     FOR UPDATE OF p          -- NEW: serialize vs admin_open_clawback's publisher-row FOR UPDATE
  LOOP
    -- B: a per-publisher payable error (e.g. the M4 CPC loud-guard) must skip THIS
    -- publisher only, never abort the batch.
    BEGIN
      v_payable := app.publisher_payable_micros(rec.id, p_hold);
    EXCEPTION WHEN others THEN
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'payable_error', 'detail', SQLERRM);
      CONTINUE;
    END;

    -- C: book exactly what we will transfer. Floor to a whole-cent multiple of 10000;
    -- the sub-cent remainder stays in payable (computed fresh next cycle) and is never lost.
    v_payable := (v_payable / 10000) * 10000;

    IF v_payable < p_min_micros THEN
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'below_min', 'payable_micros', v_payable);
      CONTINUE;
    END IF;
    IF v_payable > p_velocity_max_micros THEN
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'velocity_cap', 'payable_micros', v_payable);
      CONTINUE;
    END IF;

    BEGIN
      INSERT INTO public.payouts (publisher_id, amount_micros, status, hold_until, min_payout_micros)
      VALUES (rec.id, v_payable, 'pending', now(), p_min_micros)
      RETURNING id INTO v_id;
    EXCEPTION WHEN unique_violation THEN
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'already_reserved');
      CONTINUE;
    END;

    reserved := reserved || jsonb_build_object('publisher_id', rec.id, 'payout_id', v_id, 'amount_micros', v_payable);
  END LOOP;

  RETURN jsonb_build_object('reserved', reserved, 'skipped', skipped);
END;
$$;
REVOKE ALL ON FUNCTION public.payout_batch_reserve(interval, bigint, bigint, int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.payout_batch_reserve(interval, bigint, bigint, int) TO service_role;

COMMENT ON FUNCTION public.payout_batch_reserve IS
  'Phase 1: reserve a pending payout per eligible publisher (no ledger). One-active-per-publisher index is the reservation lock. M8: default p_hold sourced from app.payout_hold_interval() (single source shared with admin_open_clawback''s guard) and FOR UPDATE OF p serializes each eligible publisher row against admin_open_clawback''s publisher-row lock. Transfer/confirm core untouched.';
