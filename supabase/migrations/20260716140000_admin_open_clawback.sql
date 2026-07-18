-- lumaline M8-T7 (Phase 2) — the ONE new money-mutating admin surface: manual clawback.
--
-- public.admin_open_clawback(p_impression_id, p_reason) is an audited, guarded manual/dispute
-- clawback of an IMPRESSION and its whole window that scan_ivt never flagged. It is the only
-- new negative-money action the owner dashboard adds; everything else in M8 is read or reuses
-- the three already-shipped gated actions. Owner-gated deploy AFTER adversarial review AND
-- after the T0 prerequisites (MFA enrolled, owner in app.money_admins, aal2 session verified —
-- see 20260716120000). Depends on 20260716100000 (is_money_admin, payout_hold_interval,
-- log_admin_action) and 20260716130000 (payout_batch_reserve's FOR UPDATE OF p).
--
-- WHY IMPRESSION-SOURCE ONLY (no p_source_type='click' branch — the money-safety must-fix):
--   CPC advertiser_charges carry impression_id = NULL (uncharged_advertiser_billings selects
--   NULL::uuid for the click branch — cpc_billing.sql:34) and POST /billing/refund keys on
--   impression_id (billing/index.ts:785-792), so a CPC charge has NO refund path. A click-source
--   clawback would reverse the ledger with no way to return the advertiser's cash → books diverge
--   from cash and recon stays red forever. So this action only takes an IMPRESSION, and it
--   additionally REFUSES any window that carries a succeeded CPC charge (no stranded CPC cash in
--   a mixed CPVA+CPC window).
--
-- MONEY-SAFETY, PAYOUT-LEG-AWARE (replaces the crude age-only rule):
--   After delegating the reversal to the EXISTING idempotent public.clawback()
--   (clearing_and_ledger.sql:187 — flips every window ledger group to 'reversed' keeping each
--   group SUM=0, marks sources clawed_back, never touches paid payout legs), it asserts
--   app.publisher_payable_micros(v_pub, app.payout_hold_interval()) >= 0 as a HARD post-condition
--   that RAISEs (rolling back the whole txn) if negative. Because payout_batch_reserve reserves
--   only matured earnings and a confirmed payout leg is counted in v_paid, reversing a covered
--   earning drives payable negative → rollback: it is structurally impossible to reverse a
--   paid/covered earning, and hold(7d) > clawback(72h) is preserved. Unpaid aged earnings keep
--   payable >= 0, so the common cleared-but-UNPAID dispute is now handled in-dashboard (the
--   over-conservatism fix) instead of being pushed to raw un-audited SQL.
--
-- SERIALIZATION: SELECT ... FOR UPDATE on the impression AND the publisher row (the latter
--   contended with payout_batch_reserve's new FOR UPDATE OF p) + a refuse-on-any-active-payout
--   check close the reserve/clawback boundary race. One non-rejected review per impression is
--   enforced by BOTH a partial unique index (below) AND the in-body existence check, so the
--   per-review refund idempotency key (lumaline_refund_<reviewId>) can never be duplicated under
--   concurrency.
--
-- AUDIT: the successful and the sentinel/gross<=0 no-op paths each write ONE row to the
--   append-only app.admin_action_log via app.log_admin_action() (20260716100000). Refusals
--   (already-clawed / active-payout / CPC-charge / existing-review / earning-already-paid) return
--   early with no effect and no ledger mutation, and are INTENTIONALLY not audited — a refusal
--   moves no money and mutates nothing, and the alternative (auditing every probe) is itself a
--   RAISE-rolled-back write for the post-condition path. Only EFFECTING branches are audited.

-- ---------------------------------------------------------------------------
-- MECHANICAL self-lockout guard — same rationale as 20260716120000: refuse to install this
-- aal2-gated action on a DB that has seeded admins but NO money admin (the half-configured prod
-- state that self-locks-out). No-op on a fresh local/CI stack (app.admins empty before seed.sql),
-- forces the T0 seed in prod.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM app.admins)
     AND NOT EXISTS (SELECT 1 FROM app.money_admins) THEN
    RAISE EXCEPTION USING
      errcode = '55000',
      message = 'SELF-LOCKOUT GUARD: app.admins is seeded but app.money_admins is EMPTY. '
             || 'Seed the owner into app.money_admins (and enroll TOTP + verify an aal2 session) '
             || 'BEFORE applying admin_open_clawback, or the aal2 gate refuses the sole admin.';
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- app.impression_earning_paid(p_impression_id) — PER-EARNING paid-watermark test.
--
-- WHY (money-safety must-fix): the aggregate post-condition below —
--   app.publisher_payable_micros(pub, hold) >= 0 — is NOT sufficient on its own to protect an
-- ALREADY-PAID earning. When the publisher holds OTHER unpaid matured earnings that cover the
-- drop, reversing a paid earning keeps the AGGREGATE payable >= 0, yet it silently short-pays the
-- unpaid earning (payable falls by the reversed amount, consuming a legitimate future payout) and
-- breaks the non-negotiable invariant "paid earnings can't be clawed back" (hold 7d > clawback 72h).
-- Example that the aggregate check misses: earning A (paid, 600k) + earning B (unpaid matured,
-- 600k) → payable = 1.2M − 600k = 600k. Clawing back A drops earned to 600k → payable = 0 ≥ 0 →
-- the aggregate check COMMITS, refunding the advertiser for A while B is never paid.
--
-- FIX: a per-earning FIFO watermark. Payouts settle oldest-matured earnings first, so v_paid (the
-- publisher's total cleared payout legs) covers the OLDEST earnings by source created_at. The
-- target earning is (at least partially) within the already-paid tranche iff the cumulative
-- cleared earnings STRICTLY OLDER than it are LESS than v_paid. This restores the "paid earnings
-- can't be clawed back" invariant precisely (an unpaid aged earning still returns false → the
-- over-conservatism fix is preserved). Mirrors app.publisher_payable_micros (cpc_billing.sql:90)
-- for the earned/paid sign convention (earnings legs stored negative → negated).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.impression_earning_paid(p_impression_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_pub        uuid;
  v_created    timestamptz;
  v_cum_before bigint;
  v_paid       bigint;
BEGIN
  SELECT publisher_id, created_at INTO v_pub, v_created
    FROM public.impressions WHERE id = p_impression_id;
  IF v_pub IS NULL THEN
    RETURN false;   -- unknown impression: the caller already RAISEs 'not found'
  END IF;

  -- Cumulative cleared publisher earnings (CPVA impressions + CPC clicks) STRICTLY OLDER than the
  -- target, by SOURCE created_at (the same maturity clock publisher_payable_micros uses). This is
  -- the target's start offset in the FIFO paid tranche. Strict '<' is conservative: on an exact
  -- created_at tie the older-cohort sum is smaller → more likely to trip the watermark → refuse
  -- (safe fallback to owner-gated SQL).
  SELECT
    COALESCE((
      SELECT -sum(le.amount_micros)
        FROM public.ledger_entries le
        JOIN public.impressions imp ON imp.id = le.source_id
       WHERE le.account = 'publisher_earnings' AND le.event_type = 'cpva_accrual'
         AND le.state = 'cleared' AND le.source_type = 'impression'
         AND le.publisher_id = v_pub
         AND imp.created_at < v_created
    ), 0)
  + COALESCE((
      SELECT -sum(le.amount_micros)
        FROM public.ledger_entries le
        JOIN public.clicks cl ON cl.id = le.source_id
       WHERE le.account = 'publisher_earnings' AND le.event_type = 'cpc_accrual'
         AND le.state = 'cleared' AND le.source_type = 'click'
         AND le.publisher_id = v_pub
         AND cl.created_at < v_created
    ), 0)
  INTO v_cum_before;

  SELECT COALESCE(sum(le.amount_micros), 0) INTO v_paid
    FROM public.ledger_entries le
   WHERE le.account = 'publisher_earnings' AND le.event_type = 'payout'
     AND le.state = 'cleared' AND le.publisher_id = v_pub;

  -- The paid watermark reaches into (or past) the target's start offset → the target earning is
  -- within the already-paid tranche → it must NOT be manually reversed.
  RETURN v_cum_before < v_paid;
END;
$$;

REVOKE ALL     ON FUNCTION app.impression_earning_paid(uuid) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.impression_earning_paid(uuid) TO service_role;

COMMENT ON FUNCTION app.impression_earning_paid IS
  'True iff the impression''s cleared earning is within the publisher''s already-paid FIFO tranche (cumulative cleared earnings strictly older than it < total paid). Per-earning money-safety guard for admin_open_clawback: the aggregate publisher_payable_micros >= 0 post-condition alone lets a PAID earning be reversed when other unpaid matured balance covers the drop.';

-- ---------------------------------------------------------------------------
-- One NON-REJECTED review per impression. Backs the in-body existence check and guarantees the
-- refund idempotency key (per review) is unique per charged impression.
--
-- PRE-DEPLOY: verify NO existing duplicate before applying (a pre-existing pair of non-rejected
-- reviews for one impression would make this index build fail):
--   SELECT impression_id, count(*) FROM public.clawback_reviews
--    WHERE status <> 'rejected' AND impression_id IS NOT NULL
--    GROUP BY impression_id HAVING count(*) > 1;
-- Today the 1:1 holds by construction (scan_ivt's NOT EXISTS-on-risk_flags guard yields at most
-- one pending review per impression; approve/reject only flip status), so this is expected empty.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS clawback_reviews_one_active_per_impression
  ON public.clawback_reviews (impression_id)
  WHERE status <> 'rejected' AND impression_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- public.admin_open_clawback — money-admin (aal2) manual clawback of an impression + its window.
-- ---------------------------------------------------------------------------
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

  -- refund_required = a succeeded CPVA charge exists for this impression (chain POST /billing/refund).
  v_refund_required := EXISTS (
    SELECT 1 FROM public.advertiser_charges
     WHERE impression_id = p_impression_id AND status = 'succeeded'
  );

  PERFORM app.log_admin_action('admin_open_clawback', 'window', v_win,
                               jsonb_build_object('impression_id', p_impression_id,
                                                  'reason', p_reason,
                                                  'refund_required', v_refund_required));

  RETURN jsonb_build_object('ok', true, 'window_id', v_win, 'clawback', v_cb,
                            'refund_required', v_refund_required);
END;
$$;

-- Callable by authenticated (money-)admins via PostgREST; anon EXECUTE revoked (the recurring
-- secdef_grant_hardening.sql footgun). The GRANT to authenticated is intentional — the real gate
-- is the first-line app.is_money_admin() re-check, not the GRANT.
REVOKE ALL ON FUNCTION public.admin_open_clawback(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.admin_open_clawback(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.admin_open_clawback IS
  'Money-admin (aal2 + app.money_admins) manual clawback of an IMPRESSION and its whole window. Refuses already-clawed / any active payout / a window with a succeeded CPC charge / an existing non-rejected review / an earning already within the paid FIFO tranche (app.impression_earning_paid). Delegates the reversal to the idempotent public.clawback(); the aggregate publisher_payable>=0 post-condition is a defense-in-depth backstop (full rollback). Reverses the WHOLE window and does NOT itself refund the advertiser — chain POST /billing/refund; returns refund_required.';
