-- lumaline M9 follow-up — admin_open_clawback must RELEASE the advertiser's prepay serve-reserve.
--
-- THE SEAM (documented in memory m9-advertiser-portal + AS_BUILT deferral ledger):
--   A prepay window holds ad_windows.reserve_micros against advertiser_balances.reserved_micros at
--   window_open (M9 20260716180000 serving_guardrails). That reserve is normally zeroed when the
--   impression is drawn into a Stripe charge batch. But a CLAWED-BACK impression never enters a
--   charge batch, and the generic public.clawback() (clearing_and_ledger.sql — pre-M9) predates
--   prepay and knows nothing about reserves. So public.admin_open_clawback (M8 20260716140000),
--   which delegates the reversal to public.clawback(), reverses the window WITHOUT releasing the
--   reserve → reserved_micros stays permanently inflated → the advertiser's AVAILABLE credit
--   (balance − reserved) silently shrinks and never recovers.
--
--   The M9 admin_prepay_clawback (20260716200000:446-450) DOES release on its own balance path, and
--   admin_prepay_clawback is the intended advertiser-clawback entry point — BUT admin_open_clawback
--   is still directly callable by money-admins (and admin_prepay_clawback DELEGATES to it for the
--   Stripe / postpay path, 20260716200000:421-424). A direct admin_open_clawback of a prepay
--   impression therefore strands the reserve. app.advertiser_reconcile_reserved() is the
--   self-healing backstop, but it is NOT scheduled by any cron, so the strand persists until a
--   manual recon.
--
-- FIX: mirror admin_prepay_clawback's release block into admin_open_clawback, AFTER the aggregate
--   money-safety post-condition (so it only runs when the clawback actually stands; a failed
--   post-condition RAISEs and rolls back the whole txn, release included). This is the sole change:
--   two new locals (v_adv, v_reserve) + one release block + one extra audit key. Every existing
--   control (money gate, reason-required, impression FOR UPDATE, payout_active refusal,
--   cpc_charge refusal, one-review invariant, gross<=0 no-op, earning_already_paid FIFO watermark,
--   idempotent public.clawback() delegation, aggregate publisher_payable>=0 post-condition) is
--   reproduced BYTE-FOR-BYTE. No control is weakened.
--
-- WHY SAFE / no double-release / no-op elsewhere:
--   * Postpay / house / sentinel / no-fill windows carry reserve_micros = 0 → the `v_reserve > 0`
--     guard makes the block an inert no-op there (matches admin_prepay_clawback's own guard).
--   * Idempotent: zeroing reserve_micros makes any re-entry (or a second clawback attempt) inert,
--     and app.advertiser_release floors reserved_micros at 0 (greatest(...,0)).
--   * No double-release when admin_prepay_clawback delegates to us: its delegation branch RETURNs
--     immediately with our result and never reaches its own release block, so exactly one release
--     runs (ours). Its balance path never calls us.
--   * Backed-reserve invariant preserved: by the time this runs, public.clawback() has already
--     marked the impression clawed_back, so app.advertiser_expected_reserved() (which EXCLUDES
--     clawed_back/void windows) already dropped this window's reserve. Releasing the stored
--     reserved_micros by the same amount keeps stored == expected → reconcile finds no drift.
--
-- DEPENDS ON: 20260716140000 (admin_open_clawback), 20260716170000 (app.advertiser_release),
--   20260716180000 (ad_windows.reserve_micros), 20260716200000 (admin_prepay_clawback — the
--   release pattern mirrored here). Additive: CREATE OR REPLACE only, no schema/grant change.

CREATE OR REPLACE FUNCTION public.admin_open_clawback(p_impression_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_admin           uuid;
  v_win             uuid;
  v_state           public.impression_state;
  v_gross           bigint;
  v_pub             uuid;
  v_rf              uuid;
  v_cb              jsonb;
  v_refund_required boolean;
  v_adv             uuid;      -- M9 reserve-release: the prepay advertiser owning this window (if any)
  v_reserve         bigint;    -- M9 reserve-release: micros released back to available credit (0 = none)
BEGIN
  -- Money gate: app.money_admins membership AND jwt aal='aal2'. A magic-link (aal1) session
  -- or a read/triage-only admin is refused. THIS in-body check is the real gate.
  IF NOT (SELECT app.is_money_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'reason required' USING errcode = '22023';
  END IF;

  -- Lock the impression row for the whole txn.
  SELECT window_id, state, gross_micros, publisher_id
    INTO v_win, v_state, v_gross, v_pub
    FROM public.impressions
   WHERE id = p_impression_id
   FOR UPDATE;
  IF v_win IS NULL THEN
    RAISE EXCEPTION 'impression not found' USING errcode = 'P0002';
  END IF;

  -- Idempotent: already reversed (clawed_back) or never billable (void) → no effect.
  IF v_state NOT IN ('provisional', 'cleared') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_clawed_back', 'state', v_state);
  END IF;

  -- Serialize against payout_batch_reserve (which now takes FOR UPDATE OF p on this row).
  PERFORM 1 FROM public.publishers WHERE id = v_pub FOR UPDATE;

  -- Refuse if a payout is in flight for the publisher: a reserve/transfer could otherwise pay
  -- an earning this reversal removes (drives payable negative). Reversing then is unsafe.
  IF EXISTS (
    SELECT 1 FROM public.payouts
     WHERE publisher_id = v_pub AND status IN ('pending', 'in_transit')
  ) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'payout_active');
  END IF;

  -- No CPC refund path: refuse if the window carries a succeeded click-sourced charge. CPC
  -- advertiser_charges have impression_id=NULL and POST /refund cannot process them, so reversing
  -- the CPC ledger leg would strand the advertiser's cash. (Impression-source only + this refusal
  -- means every reversed advertiser_billing leg maps to a refundable impression-linked charge.)
  IF EXISTS (
    SELECT 1
      FROM public.advertiser_charges ac
      JOIN public.ledger_entries le ON le.entry_group_id = ac.entry_group_id
     WHERE ac.status = 'succeeded'
       AND le.source_type = 'click'
       AND le.source_id IN (SELECT id FROM public.clicks WHERE window_id = v_win)
  ) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'cpc_charge_present_no_refund_path');
  END IF;

  -- One-review invariant (also enforced by the partial unique index): never write a second
  -- non-rejected review for the impression, so the per-review refund idempotency key is unique.
  IF EXISTS (
    SELECT 1 FROM public.clawback_reviews
     WHERE impression_id = p_impression_id AND status <> 'rejected'
  ) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'review_exists');
  END IF;

  v_admin := nullif(app.jwt_claim('sub'), '')::uuid;

  -- Sentinel / house / zero-bid: nothing financial to reverse. Audit the authorized action and
  -- return a clean no-op (no ledger, no review row).
  IF v_gross IS NULL OR v_gross <= 0 THEN
    PERFORM app.log_admin_action('admin_open_clawback', 'impression', p_impression_id,
                                 jsonb_build_object('reason', p_reason, 'no_op', 'gross_zero'));
    RETURN jsonb_build_object('ok', true, 'reason', 'no_op_gross_zero');
  END IF;

  -- PER-EARNING PAID-WATERMARK REFUSAL (money-safety must-fix). The aggregate post-condition
  -- below is necessary but NOT sufficient: with OTHER unpaid matured balance covering the drop, a
  -- paid earning can be reversed while aggregate payable stays >= 0 (short-paying the unpaid
  -- earning and breaking 'paid earnings can't be clawed back'). This FIFO watermark refuses the
  -- reversal outright when the target earning is within the already-paid tranche — before any
  -- mutation. Genuine unpaid aged earnings still pass (over-conservatism fix preserved).
  IF app.impression_earning_paid(p_impression_id) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'earning_already_paid');
  END IF;

  -- Delegate the reversal to the EXISTING idempotent whole-window clawback (never a raw ledger
  -- UPDATE). It flips every window ledger group to 'reversed' (each group stays SUM=0), marks the
  -- impression + sibling click clawed_back, and records one window-keyed risk_flag(reason).
  v_cb := public.clawback('impression', p_impression_id, p_reason);

  -- The window-keyed flag clawback() just recorded is the FK target for the review row.
  SELECT id INTO v_rf
    FROM public.risk_flags
   WHERE window_id = v_win AND reason = p_reason
   ORDER BY id
   LIMIT 1;

  INSERT INTO public.clawback_reviews
    (risk_flag_id, impression_id, status, reviewed_by, review_reason, reviewed_at)
  VALUES
    (v_rf, p_impression_id, 'approved', v_admin, p_reason, now());

  -- AGGREGATE MONEY-SAFETY POST-CONDITION (defense-in-depth backstop to the per-earning watermark
  -- above): never leave the publisher's aggregate payable negative. Sourced from the SAME
  -- app.payout_hold_interval() the reserve default uses, so the boundaries cannot diverge. A
  -- negative result RAISEs → the whole txn (clawback + review + would-be audit) rolls back, so
  -- ZERO mutation persists. The watermark refusal above is the PRIMARY per-earning guard; this
  -- aggregate check catches any residual whole-window edge (e.g. a sibling CPC earning older than
  -- the impression) the impression-keyed watermark could miss.
  IF app.publisher_payable_micros(v_pub, app.payout_hold_interval()) < 0 THEN
    RAISE EXCEPTION 'clawback would make publisher_payable negative' USING errcode = '23514';
  END IF;

  -- ── M9 SEAM: release the advertiser's prepay serve-reserve held by this now-clawed-back window ──
  -- Mirrors admin_prepay_clawback (20260716200000:446-450). public.clawback() above already marked
  -- the impression clawed_back but does NOT touch the prepay reserve (it predates M9), so without
  -- this the reserve is stranded and reserved_micros stays inflated forever. Resolve the owning
  -- advertiser (NULL for house / no-line-item / sentinel impressions), read the window's reserve,
  -- and release it. Postpay/house/sentinel/no-fill windows carry reserve_micros = 0 → no-op.
  -- Idempotent: zeroing reserve_micros makes re-entry inert; advertiser_release floors at 0.
  SELECT c.advertiser_id INTO v_adv
    FROM public.impressions i
    JOIN public.line_items li ON li.id = i.line_item_id
    JOIN public.campaigns  c  ON c.id  = li.campaign_id
   WHERE i.id = p_impression_id;

  SELECT reserve_micros INTO v_reserve
    FROM public.ad_windows WHERE window_id = v_win;
  v_reserve := COALESCE(v_reserve, 0);

  IF v_adv IS NOT NULL AND v_reserve > 0 THEN
    PERFORM app.advertiser_release(v_adv, v_reserve);
    UPDATE public.ad_windows SET reserve_micros = 0 WHERE window_id = v_win;
  ELSE
    v_reserve := 0;
  END IF;

  -- refund_required = a succeeded CPVA charge exists for this impression (chain POST /billing/refund).
  v_refund_required := EXISTS (
    SELECT 1 FROM public.advertiser_charges
     WHERE impression_id = p_impression_id AND status = 'succeeded'
  );

  PERFORM app.log_admin_action('admin_open_clawback', 'window', v_win,
                               jsonb_build_object('impression_id', p_impression_id,
                                                  'reason', p_reason,
                                                  'refund_required', v_refund_required,
                                                  'reserve_released_micros', v_reserve));

  RETURN jsonb_build_object('ok', true, 'window_id', v_win, 'clawback', v_cb,
                            'refund_required', v_refund_required,
                            'reserve_released_micros', v_reserve);
END;
$$;

-- Grants unchanged from 20260716140000 (CREATE OR REPLACE preserves them, but re-assert the
-- anon-REVOKE — the recurring Supabase default-priv footgun — to be safe under a fresh reset).
REVOKE ALL ON FUNCTION public.admin_open_clawback(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.admin_open_clawback(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.admin_open_clawback IS
  'Money-admin (aal2 + app.money_admins) manual clawback of an IMPRESSION and its whole window. Refuses already-clawed / any active payout / a window with a succeeded CPC charge / an existing non-rejected review / an earning already within the paid FIFO tranche (app.impression_earning_paid). Delegates the reversal to the idempotent public.clawback(); the aggregate publisher_payable>=0 post-condition is a defense-in-depth backstop (full rollback). M9: after the reversal stands, RELEASES the window''s prepay serve-reserve (advertiser_release + zero reserve_micros; no-op for postpay/house/reserve=0) so reserved_micros is not stranded. Reverses the WHOLE window and does NOT itself refund the advertiser — chain POST /billing/refund; returns refund_required + reserve_released_micros.';
