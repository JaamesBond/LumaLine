-- lumaline M3 — payout-rails hardening from the adversarial money-path review.
--
-- Fixes three confirmed defects in 20260629100000_payout_rails.sql:
--
--   B (HIGH)   — the M4 CPC loud-guard RAISE inside payout_batch_reserve unwound the
--                ENTIRE batch: one publisher with a cleared cpc_accrual earning froze
--                every publisher's payout. Now wrapped per-row -> skip only that one.
--
--   C (HIGH)   — micros->cents rounding: payout_confirm booked the FULL amount_micros to
--                the ledger while the Stripe transfer sends cent-granular money, so the
--                sub-cent remainder was treated as already-paid forever (permanent
--                underpayment) and reconcile never read ok. Now reserve floors payable to
--                a whole-cent multiple of 10000 and the remainder stays payable next cycle.
--
--   F (MEDIUM) — a PARTIAL transfer.reversed booked the FULL inverse, over-crediting
--                payable. payout_reverse is now amount-aware (cumulative reversed micros),
--                idempotent on the cumulative figure, partial keeps status 'paid', and only
--                a full reversal flips to 'failed'.

-- F: track how much of a paid payout has been reversed (cumulative).
ALTER TABLE public.payouts ADD COLUMN IF NOT EXISTS reversed_micros bigint NOT NULL DEFAULT 0;
COMMENT ON COLUMN public.payouts.reversed_micros IS
  'Cumulative micros reversed via payout_reverse() (Stripe transfer.reversed). Equals amount_micros when fully reversed.';

-- ---------------------------------------------------------------------------
-- payout_batch_reserve — B + C hardened.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.payout_batch_reserve(
  p_hold                interval default '7 days',
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

-- ---------------------------------------------------------------------------
-- payout_reverse — F: amount-aware (cumulative reversed micros), idempotent.
-- p_reversed_micros = the transfer's CUMULATIVE amount_reversed (in micros). NULL = full.
-- Books only the DELTA since the last reversal, so multiple partial reversals and event
-- replays are both correct. Only a full reversal flips status to 'failed'.
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS public.payout_reverse(uuid, text);
CREATE OR REPLACE FUNCTION public.payout_reverse(
  p_payout_id uuid, p_reason text, p_reversed_micros bigint default null)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_po     public.payouts%ROWTYPE;
  g        uuid := gen_random_uuid();
  v_target bigint;
  v_delta  bigint;
BEGIN
  SELECT * INTO v_po FROM public.payouts WHERE id = p_payout_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'payout not found' USING errcode = 'P0002';
  END IF;
  IF v_po.status <> 'paid' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_paid', 'status', v_po.status);
  END IF;

  -- Cumulative target reversed amount, clamped to the payout amount. NULL -> full.
  v_target := COALESCE(p_reversed_micros, v_po.amount_micros);
  v_target := least(greatest(v_target, 0), v_po.amount_micros);
  v_delta  := v_target - v_po.reversed_micros;     -- new reversal this call
  IF v_delta <= 0 THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'no_new_reversal', 'reversed_micros', v_po.reversed_micros);
  END IF;

  -- Book the inverse of the DELTA only (publisher_earnings -delta / platform_cash +delta).
  INSERT INTO public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) VALUES
    (g, 'payout', 'publisher_earnings', -v_delta, 'cleared', 'payout', p_payout_id, v_po.publisher_id),
    (g, 'payout', 'platform_cash',       v_delta, 'cleared', 'payout', p_payout_id, null);

  UPDATE public.payouts
     SET reversed_micros = v_target,
         failure_reason  = p_reason,
         -- only a FULL reversal terminates the payout; a partial one stays 'paid'.
         status = CASE WHEN v_target >= amount_micros THEN 'failed'::public.payout_status_kind ELSE status END
   WHERE id = p_payout_id;

  RETURN jsonb_build_object('ok', true, 'payout_id', p_payout_id, 'entry_group_id', g,
                            'reversed_micros', v_target, 'delta_micros', v_delta,
                            'fully_reversed', v_target >= v_po.amount_micros);
END;
$$;
REVOKE ALL ON FUNCTION public.payout_reverse(uuid, text, bigint) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.payout_reverse(uuid, text, bigint) TO service_role;

COMMENT ON FUNCTION public.payout_reverse IS
  'transfer.reversed: book the inverse of the DELTA reversed (cumulative target - already reversed). Partial keeps status paid; full -> failed. Idempotent on the cumulative figure.';
