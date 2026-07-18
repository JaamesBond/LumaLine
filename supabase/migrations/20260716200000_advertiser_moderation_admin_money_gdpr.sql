-- lumaline M9-T5 — advertiser moderation + admin money actions + self-deal scan + GDPR.
--
-- This is the human/admin control surface over the self-serve advertiser portal. Nothing an
-- advertiser can self-serve reaches SERVING without an admin approving it, and the money-sensitive
-- corrections (prepay clawback, balance adjust) sit behind the aal2 money-admin gate + the immutable
-- admin audit log. It ships five capability groups, all keeping the trust invariants intact:
--
--   1. public.advertiser_action_log + app.log_advertiser_action() — an append-only, trigger-immutable,
--      per-advertiser audit trail (cloned from app.admin_action_log, admin_dashboard_foundation.sql
--      :155-232, and advertiser_balance_ledger's immutability, 20260716170000). The advertiser reads
--      its OWN rows (moderation outcomes + reasons, admin balance actions, GDPR); admins read all.
--      PRESERVED across GDPR erasure (a financial/audit record).
--
--   2. MODERATION (admin PRE-APPROVAL, app.is_admin() = aal1 — owner decision, NO separate reviewer
--      tier): a self-serve creative lands 'pending_review' (20260716190000) and can ONLY reach
--      status='active' — the sole servable state (lumaline-feed signs verbatim, window_open serves
--      only 'active') — through public.advertiser_approve_creative, which re-runs the content
--      validator and cascades the draft campaign+line_item→active (mirror admin-booking activate).
--      advertiser_reject_creative (pending_review→rejected) and the KILL SWITCH
--      advertiser_suspend_creative (active→paused, stops serving instantly — the post-approval
--      dest_url bait-and-switch remedy, ad-policy §11) round out the trio. NONE is self-scoped;
--      an advertiser can never approve/activate its own creative.
--
--   3. ADMIN MONEY (aal2 app.is_money_admin() + audited to BOTH app.admin_action_log AND the
--      advertiser trail): admin_prepay_clawback (deposit-settled clawback that re-credits the
--      advertiser's balance for a balance-settled charge, or delegates a card-settled charge to the
--      existing admin_open_clawback so a prepay charge is NEVER double-refunded) and
--      admin_advertiser_adjust_balance (a manual goodwill/correction credit or an AVAILABLE-guarded
--      debit). There is NO withdrawal RPC: deposits are NON-REFUNDABLE prepaid ad credit (owner
--      decision) — the only exits are delivered spend, a card dispute (bad-debt, 20260716170000), an
--      admin clawback (fraud), or an admin correction. Both actions gate on the SAME AVAILABLE =
--      balance − reserved under FOR UPDATE the draw-down uses, so reserved-but-undrawn spend already
--      accrued to publisher_earnings can never be pulled out.
--
--   4. app.scan_selfdeal_risk() (service_role cron) — the NON-identity linkage defense the auth.uid()
--      serving-exclusion (20260716180000) cannot cover (a second email defeats it): it reverses (via
--      the idempotent public.clawback) any recent impression whose crediting publisher shares a
--      verified auth email (exact or same domain) with a member of the paying advertiser, and holds
--      that publisher's payouts for manual review (a publisher_payout_holds row + a
--      payout_status='verified'→'pending' downgrade so payout_batch_reserve's existing eligibility
--      predicate skips them — the payout transfer/confirm core stays UNTOUCHED). Documented: clean-money
--      self-deal is −40% self-limiting; the real threat is stolen-card laundering.
--
--   5. GDPR erasure + export (self + admin, mirroring gdpr_self_delete.sql:28-153): advertiser_gdpr_
--      self_delete() (no arg, self-scoped — cannot target another org) + advertiser_gdpr_delete(uuid)
--      (admin support path) both delegate to app.advertiser_gdpr_erase(uuid), which refuses while any
--      money is in flight (balance>0 / reserved>0 / pending topup / pending charge / uncharged
--      postpay), anonymizes advertisers.name+stripe_customer_id + tombstones member auth emails,
--      pauses the org's campaigns/line_items, and PRESERVES the balance ledger + action log as
--      financial records. advertiser_data_export() returns the caller's own campaigns/creatives/
--      spend/deposits.
--
-- CONVENTIONS (secdef_grant_hardening.sql lesson): every new PUBLIC SECDEF fn ships
-- `REVOKE ALL ... FROM PUBLIC, anon` then GRANT authenticated (the money/moderation gate is the
-- in-body re-check, not the GRANT); app-schema helpers additionally REVOKE authenticated; the
-- migration tail RAISEs if anon retains EXECUTE on anything added here. All SECDEF, search_path=''.
--
-- DEPENDS ON: 20260716100000 (is_admin/is_money_admin/log_admin_action/admin_action_log/money_admins),
-- 20260716140000 (admin_open_clawback + impression_earning_paid, for the card-clawback delegation +
-- paid-earning guard), 20260716150000 (advertiser_users, current_advertiser_id, advertisers_protect_cols),
-- 20260716170000 (advertiser_balances + the money primitives), 20260716190000 (validate_creative_content).

-- ===========================================================================
-- 0. Self-lockout guard (mirror admin_open_clawback 20260716140000:52-62).
--
-- This migration ships aal2 is_money_admin-gated actions. Refuse to install them on a half-configured
-- prod (admins seeded but NO money admin) that would self-lock-out the only admin. No-op on a fresh
-- local/CI stack (both allow-lists empty before seed) and on a fully-seeded prod.
-- ===========================================================================
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM app.admins)
     AND NOT EXISTS (SELECT 1 FROM app.money_admins) THEN
    RAISE EXCEPTION USING
      errcode = '55000',
      message = 'SELF-LOCKOUT GUARD: app.admins is seeded but app.money_admins is EMPTY. '
             || 'Seed the owner into app.money_admins (and enroll TOTP + verify an aal2 session) '
             || 'BEFORE applying the advertiser money actions, or the aal2 gate refuses the sole admin.';
  END IF;
END $$;

-- ===========================================================================
-- 1. advertisers.deleted_at — GDPR erasure watermark (mirrors publishers.deleted_at).
--
-- NOT a protected column (advertisers_protect_cols guards is_house/status/stripe_customer_id/
-- billing_mode only), so the erase path can set it. Its non-NULL value makes erasure idempotent.
-- ===========================================================================
ALTER TABLE public.advertisers ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

COMMENT ON COLUMN public.advertisers.deleted_at IS
  'GDPR erasure watermark (mirrors publishers.deleted_at). Set by app.advertiser_gdpr_erase; a non-NULL value makes a repeat erasure a no-op (already_deleted). Not a protected column.';

-- ===========================================================================
-- 2. public.advertiser_action_log — append-only, immutable, per-advertiser audit trail.
--
-- One row per admin/advertiser action ON an advertiser org (moderation outcome, admin money action,
-- GDPR). The advertiser reads its OWN rows so moderation reasons + admin balance actions are visible
-- in the portal; admins read all. Append-only: a BEFORE UPDATE/DELETE + BEFORE TRUNCATE trigger blocks
-- mutation even for the owner (cloned from advertiser_balance_ledger's immutability). No client write
-- grant — writes flow ONLY through the SECDEF app.log_advertiser_action.
-- ===========================================================================
CREATE TABLE public.advertiser_action_log (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  at            timestamptz NOT NULL DEFAULT now(),
  advertiser_id uuid REFERENCES public.advertisers (id) ON DELETE CASCADE,
  actor         uuid,          -- auth_user_id (jwt sub) of the acting admin/advertiser
  actor_role    text,          -- jwt role claim at action time
  actor_aal     text,          -- jwt aal claim at action time (expect 'aal2' for money actions)
  action        text NOT NULL, -- 'approve_creative' | 'reject_creative' | 'suspend_creative'
                               --   | 'admin_prepay_clawback' | 'admin_adjust_balance' | 'gdpr_erase' | ...
  target_type   text,          -- 'creative' | 'impression' | 'advertiser' | ...
  target_id     uuid,
  payload       jsonb
);

COMMENT ON TABLE public.advertiser_action_log IS
  'Append-only, trigger-immutable per-advertiser audit trail (moderation outcomes + reasons, admin money actions, GDPR). Advertiser reads OWN rows via RLS; admins read all. Writes only via the SECDEF app.log_advertiser_action. PRESERVED across GDPR erasure (a financial/audit record).';

CREATE INDEX advertiser_action_log_adv_idx    ON public.advertiser_action_log (advertiser_id, at DESC);
CREATE INDEX advertiser_action_log_action_idx ON public.advertiser_action_log (action, at DESC);

ALTER TABLE public.advertiser_action_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY advertiser_action_log_select_own ON public.advertiser_action_log
  FOR SELECT TO authenticated
  USING (advertiser_id = (SELECT app.current_advertiser_id()) OR (SELECT app.is_admin()));
CREATE POLICY advertiser_action_log_service ON public.advertiser_action_log
  FOR ALL TO service_role USING (true) WITH CHECK (true);

REVOKE ALL    ON public.advertiser_action_log FROM PUBLIC, anon;
GRANT  SELECT ON public.advertiser_action_log TO authenticated;   -- RLS own-row / admin; NO write grant
GRANT  SELECT, INSERT ON public.advertiser_action_log TO service_role;

-- Immutability guard (same RAISE-only fn serves row UPDATE/DELETE + statement TRUNCATE).
CREATE OR REPLACE FUNCTION app.advertiser_action_log_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'advertiser_action_log is append-only';
END;
$$;
REVOKE EXECUTE ON FUNCTION app.advertiser_action_log_immutable() FROM PUBLIC;

DROP TRIGGER IF EXISTS advertiser_action_log_no_mutate ON public.advertiser_action_log;
CREATE TRIGGER advertiser_action_log_no_mutate
  BEFORE UPDATE OR DELETE ON public.advertiser_action_log
  FOR EACH ROW EXECUTE FUNCTION app.advertiser_action_log_immutable();

DROP TRIGGER IF EXISTS advertiser_action_log_no_truncate ON public.advertiser_action_log;
CREATE TRIGGER advertiser_action_log_no_truncate
  BEFORE TRUNCATE ON public.advertiser_action_log
  FOR EACH STATEMENT EXECUTE FUNCTION app.advertiser_action_log_immutable();

-- The SECDEF writer the audited RPCs call. Attributes to the verified JWT (sub/role/aal), runs as
-- owner so it can INSERT despite no client INSERT grant, EXECUTE revoked from every client role.
CREATE OR REPLACE FUNCTION app.log_advertiser_action(
  p_advertiser_id uuid,
  p_action        text,
  p_target_type   text,
  p_target_id     uuid,
  p_payload       jsonb)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  INSERT INTO public.advertiser_action_log (advertiser_id, actor, actor_role, actor_aal, action, target_type, target_id, payload)
  VALUES (
    p_advertiser_id,
    nullif(app.jwt_claim('sub'), '')::uuid,
    app.jwt_claim('role'),
    app.jwt_claim('aal'),
    p_action,
    p_target_type,
    p_target_id,
    p_payload
  );
$$;
REVOKE ALL ON FUNCTION app.log_advertiser_action(uuid, text, text, uuid, jsonb) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.log_advertiser_action IS
  'SECDEF append-only writer for public.advertiser_action_log. Called from inside the audited moderation/money/GDPR RPCs; EXECUTE revoked from every client role so only other SECDEF functions reach it. Attributes to jwt sub/role/aal.';

-- ===========================================================================
-- 3. MODERATION — admin (aal1) pre-approval + reject + kill-switch suspend.
--
-- Reviewer tier = app.is_admin() (owner decision: NO separate content_reviewers tier). None is
-- self-scoped (an advertiser can never approve/activate its own creative). A creative reaches
-- status='active' — the only servable state — ONLY through advertiser_approve_creative.
-- ===========================================================================

-- --- approve_creative: pending_review → active + cascade the draft chain --------------------------
CREATE OR REPLACE FUNCTION public.advertiser_approve_creative(p_creative_id uuid)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_status  public.creative_status;
  v_li      uuid;
  v_camp    uuid;
  v_adv     uuid;
  v_line    text;
  v_label   text;
  v_dest    text;
BEGIN
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  -- Resolve the creative + its full chain (advertiser for the audit row), lock the creative.
  SELECT cr.status, cr.line_item_id, li.campaign_id, c.advertiser_id, cr.line, cr.label, cr.dest_url
    INTO v_status, v_li, v_camp, v_adv, v_line, v_label, v_dest
    FROM public.creatives cr
    JOIN public.line_items li ON li.id = cr.line_item_id
    JOIN public.campaigns  c  ON c.id  = li.campaign_id
   WHERE cr.id = p_creative_id
   FOR UPDATE OF cr;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'creative not found' USING errcode = 'P0002';
  END IF;

  IF v_status <> 'pending_review' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_pending_review', 'status', v_status);
  END IF;

  -- Defense: re-validate the stored content at the approval boundary (the content TRIGGER re-checks
  -- on the UPDATE too, but a clean up-front RAISE is a better admin error than a trigger abort).
  -- The disclosure-label allow-list is re-asserted here so a self-serve creative can NEVER reach
  -- status='active' with a deceptive/homoglyph label — the trust invariant is structural, not
  -- dependent on the reviewer eyeballing the label (submit/edit already block it on the way in).
  PERFORM app.validate_disclosure_label(v_label);
  PERFORM app.validate_creative_content(v_line, v_label, v_dest);

  -- Activate the creative; cascade the draft/paused campaign + line_item to active (mirror the
  -- admin-booking activate flow). line_items_selfserve_bids CHECK re-validates cpc/cpva on the UPDATE.
  UPDATE public.creatives  SET status = 'active' WHERE id = p_creative_id;
  UPDATE public.line_items SET status = 'active' WHERE id = v_li   AND status IN ('draft', 'paused');
  UPDATE public.campaigns  SET status = 'active' WHERE id = v_camp AND status IN ('draft', 'paused');

  PERFORM app.log_advertiser_action(v_adv, 'approve_creative', 'creative', p_creative_id,
    jsonb_build_object('line_item_id', v_li, 'campaign_id', v_camp));

  RETURN jsonb_build_object('ok', true, 'creative_id', p_creative_id, 'status', 'active',
                            'line_item_id', v_li, 'campaign_id', v_camp);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_approve_creative(uuid) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_approve_creative(uuid) TO authenticated;

COMMENT ON FUNCTION public.advertiser_approve_creative IS
  'Admin (aal1) creative approval: pending_review→active (the only servable state) + cascade the draft campaign/line_item→active, re-validating content. NOT self-scoped — an advertiser cannot approve its own. Audited. SECDEF; authenticated (in-body is_admin re-check).';

-- --- reject_creative: pending_review → rejected ---------------------------------------------------
CREATE OR REPLACE FUNCTION public.advertiser_reject_creative(p_creative_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_status public.creative_status;
  v_adv    uuid;
BEGIN
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'reason required' USING errcode = '22023';
  END IF;

  SELECT cr.status, c.advertiser_id INTO v_status, v_adv
    FROM public.creatives cr
    JOIN public.line_items li ON li.id = cr.line_item_id
    JOIN public.campaigns  c  ON c.id  = li.campaign_id
   WHERE cr.id = p_creative_id
   FOR UPDATE OF cr;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'creative not found' USING errcode = 'P0002';
  END IF;

  IF v_status <> 'pending_review' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_pending_review', 'status', v_status);
  END IF;

  UPDATE public.creatives SET status = 'rejected' WHERE id = p_creative_id;

  PERFORM app.log_advertiser_action(v_adv, 'reject_creative', 'creative', p_creative_id,
    jsonb_build_object('reason', p_reason));

  RETURN jsonb_build_object('ok', true, 'creative_id', p_creative_id, 'status', 'rejected');
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_reject_creative(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_reject_creative(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_reject_creative IS
  'Admin (aal1) creative rejection: pending_review→rejected with a reason surfaced to the advertiser (audit log). NOT self-scoped. SECDEF; authenticated.';

-- --- suspend_creative: active → paused (KILL SWITCH) ----------------------------------------------
-- The post-approval dest_url bait-and-switch remedy (ad-policy §11): window_open serves ONLY 'active',
-- so pausing stops serving on the very next tick. Idempotent-ish (already-paused → no_op).
CREATE OR REPLACE FUNCTION public.advertiser_suspend_creative(p_creative_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_status public.creative_status;
  v_adv    uuid;
BEGIN
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'reason required' USING errcode = '22023';
  END IF;

  SELECT cr.status, c.advertiser_id INTO v_status, v_adv
    FROM public.creatives cr
    JOIN public.line_items li ON li.id = cr.line_item_id
    JOIN public.campaigns  c  ON c.id  = li.campaign_id
   WHERE cr.id = p_creative_id
   FOR UPDATE OF cr;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'creative not found' USING errcode = 'P0002';
  END IF;

  IF v_status <> 'active' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_active', 'status', v_status);
  END IF;

  UPDATE public.creatives SET status = 'paused' WHERE id = p_creative_id;

  -- Log to BOTH trails: advertiser-visible (why their creative stopped) + the admin destructive trail.
  PERFORM app.log_advertiser_action(v_adv, 'suspend_creative', 'creative', p_creative_id,
    jsonb_build_object('reason', p_reason));
  PERFORM app.log_admin_action('advertiser_suspend_creative', 'creative', p_creative_id,
    jsonb_build_object('advertiser_id', v_adv, 'reason', p_reason));

  RETURN jsonb_build_object('ok', true, 'creative_id', p_creative_id, 'status', 'paused');
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_suspend_creative(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_suspend_creative(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_suspend_creative IS
  'Admin (aal1) creative KILL SWITCH: active→paused, stopping serving on the next window_open tick (post-approval dest_url bait-and-switch remedy). Audited to both the advertiser + admin trails. SECDEF; authenticated.';

-- ===========================================================================
-- 4. ADMIN MONEY (aal2 is_money_admin) — prepay clawback + balance adjust. NO withdrawal (deposits
--    are non-refundable prepaid credit — owner decision). Both gate on AVAILABLE under FOR UPDATE and
--    audit to BOTH app.admin_action_log (the money trail) and the advertiser trail.
-- ===========================================================================

-- --- admin_prepay_clawback: reverse a settled charge; re-credit balance (balance-settled) or delegate
--     the card path (stripe-settled). NEVER double-refunds. Preserves "paid earnings can't be clawed
--     back" via the same active-payout + paid-watermark guards as admin_open_clawback.
CREATE OR REPLACE FUNCTION public.admin_prepay_clawback(p_impression_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_win        uuid;
  v_state      public.impression_state;
  v_gross      bigint;
  v_pub        uuid;
  v_li         uuid;
  v_adv        uuid;
  v_billing    text;
  v_settled    text;
  v_charge_amt bigint;
  v_charge_ok  boolean;
  v_cb         jsonb;
  v_group      uuid;
  v_recredit   bigint := 0;
  v_reserve    bigint;
BEGIN
  -- Money gate: aal2 app.money_admins. A magic-link (aal1) session or read-only admin is refused.
  IF NOT (SELECT app.is_money_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'reason required' USING errcode = '22023';
  END IF;

  -- Lock the impression + resolve its advertiser/billing_mode.
  SELECT i.window_id, i.state, i.gross_micros, i.publisher_id, i.line_item_id, c.advertiser_id, a.billing_mode
    INTO v_win, v_state, v_gross, v_pub, v_li, v_adv, v_billing
    FROM public.impressions i
    JOIN public.line_items  li ON li.id = i.line_item_id
    JOIN public.campaigns   c  ON c.id  = li.campaign_id
    JOIN public.advertisers a  ON a.id  = c.advertiser_id
   WHERE i.id = p_impression_id
   FOR UPDATE OF i;
  IF v_win IS NULL THEN
    RAISE EXCEPTION 'impression not found' USING errcode = 'P0002';
  END IF;

  -- Idempotent: already reversed / never billable.
  IF v_state NOT IN ('provisional', 'cleared') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_clawed_back', 'state', v_state);
  END IF;

  -- Sentinel / house / zero-bid: nothing financial to reverse (audit + clean no-op).
  IF v_gross IS NULL OR v_gross <= 0 THEN
    PERFORM app.log_admin_action('admin_prepay_clawback', 'impression', p_impression_id,
      jsonb_build_object('reason', p_reason, 'no_op', 'gross_zero'));
    RETURN jsonb_build_object('ok', true, 'reason', 'no_op_gross_zero');
  END IF;

  -- Resolve the impression's charge (if any) BEFORE branching.
  SELECT settled_via, amount_micros, (status = 'succeeded')
    INTO v_settled, v_charge_amt, v_charge_ok
    FROM public.advertiser_charges
   WHERE impression_id = p_impression_id
   ORDER BY created_at DESC
   LIMIT 1;

  -- CARD-settled (legacy postpay, or a prepay advertiser billed via Stripe): the existing
  -- admin_open_clawback owns the card path (reversal + refund_required chained to POST /billing/refund).
  -- Delegate so a card charge is refunded via Stripe, NEVER re-credited to a prepay balance.
  IF v_billing <> 'prepay' OR (v_charge_ok IS TRUE AND v_settled = 'stripe') THEN
    v_cb := public.admin_open_clawback(p_impression_id, p_reason);
    RETURN v_cb || jsonb_build_object('settled_via', 'stripe');
  END IF;

  -- BALANCE-settled (or not-yet-billed) prepay path. Serialize + protect paid earnings exactly like
  -- admin_open_clawback: refuse an active payout, and refuse an earning already inside the paid FIFO
  -- tranche (a re-credit + reversal must never reach back into money already paid to the publisher).
  PERFORM 1 FROM public.publishers WHERE id = v_pub FOR UPDATE;
  IF EXISTS (SELECT 1 FROM public.payouts WHERE publisher_id = v_pub AND status IN ('pending', 'in_transit')) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'payout_active');
  END IF;
  IF app.impression_earning_paid(p_impression_id) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'earning_already_paid');
  END IF;

  -- Reverse the whole window (idempotent; flips ledger groups to 'reversed', marks sources clawed_back).
  v_cb := public.clawback('impression', p_impression_id, p_reason);

  -- Release + zero any serve-time reserve still held by this (now clawed-back) window. A
  -- credited-but-undrawn impression's reserve is otherwise STRANDED forever: a clawed_back impression
  -- never enters a charge batch, so advertiser_draw_down_batch never zeroes its window — reserved_micros
  -- would stay permanently inflated, silently reducing the advertiser's AVAILABLE credit. (A window
  -- already drawn reads reserve_micros=0, so this is a no-op there.) advertiser_reconcile_reserved's
  -- clawed_back/void exclusion is the drift safety net; this frees it immediately on the admin path.
  SELECT reserve_micros INTO v_reserve FROM public.ad_windows WHERE window_id = v_win;
  IF COALESCE(v_reserve, 0) > 0 THEN
    PERFORM app.advertiser_release(v_adv, v_reserve);
    UPDATE public.ad_windows SET reserve_micros = 0 WHERE window_id = v_win;
  END IF;

  -- Re-credit the advertiser's balance ONLY for a balance-settled succeeded charge (the advertiser
  -- actually paid via draw-down). A not-yet-drawn impression re-credits 0 (its accrual is simply
  -- reversed before it could ever be drawn). Zero-sum: Dr advertiser_billing +G / Cr advertiser_funds
  -- -G, and balance += G, so balance == -SUM(advertiser_funds) is preserved.
  IF v_charge_ok IS TRUE AND v_settled = 'balance' AND coalesce(v_charge_amt, 0) > 0 THEN
    v_recredit := v_charge_amt;
    v_group := gen_random_uuid();

    INSERT INTO public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
    VALUES (v_adv, v_recredit, 0)
    ON CONFLICT (advertiser_id)
      DO UPDATE SET balance_micros = public.advertiser_balances.balance_micros + EXCLUDED.balance_micros,
                    updated_at = now();

    -- source_type is 'advertiser_clawback_refund' (NOT 'impression') so a subsequent public.clawback
    -- on the same window — which reverses only impression/click-sourced legs — can never flip this
    -- re-credit group to 'reversed' and corrupt the balance (source_id keeps the impression trace).
    INSERT INTO public.ledger_entries
      (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
    VALUES
      (v_group, 'advertiser_clawback_refund', 'advertiser_billing',  v_recredit, 'cleared', 'advertiser_clawback_refund', p_impression_id, v_adv),
      (v_group, 'advertiser_clawback_refund', 'advertiser_funds',    -v_recredit, 'cleared', 'advertiser_clawback_refund', p_impression_id, v_adv);

    INSERT INTO public.advertiser_balance_ledger
      (advertiser_id, kind, amount_micros, entry_group_id)
    VALUES
      (v_adv, 'refund', v_recredit, v_group);
  END IF;

  PERFORM app.log_admin_action('admin_prepay_clawback', 'window', v_win,
    jsonb_build_object('impression_id', p_impression_id, 'advertiser_id', v_adv,
                       'reason', p_reason, 'settled_via', 'balance', 're_credited_micros', v_recredit));
  PERFORM app.log_advertiser_action(v_adv, 'admin_prepay_clawback', 'impression', p_impression_id,
    jsonb_build_object('reason', p_reason, 're_credited_micros', v_recredit));

  RETURN jsonb_build_object('ok', true, 'window_id', v_win, 'settled_via', 'balance',
                            're_credited_micros', v_recredit, 'clawback', v_cb);
END;
$$;
REVOKE ALL ON FUNCTION public.admin_prepay_clawback(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.admin_prepay_clawback(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.admin_prepay_clawback IS
  'Money-admin (aal2) clawback of a settled impression: a card-settled charge delegates to admin_open_clawback (Stripe refund path); a balance-settled charge is reversed via public.clawback AND re-credited to the advertiser''s prepay balance (zero-sum Dr advertiser_billing / Cr advertiser_funds) — NEVER both, so no double-refund. Refuses an active payout / an already-paid earning. Audited to both trails. SECDEF; authenticated (in-body aal2 re-check).';

-- --- admin_advertiser_adjust_balance: manual goodwill credit / AVAILABLE-guarded correction debit --
-- p_delta_micros > 0 credits (Dr platform_cash / Cr advertiser_funds); < 0 debits R=−delta guarded by
-- AVAILABLE = balance − reserved under FOR UPDATE (never pull reserved-but-undrawn spend). Zero-sum;
-- balance == −SUM(advertiser_funds) preserved. NO withdrawal is exposed (deposits non-refundable).
CREATE OR REPLACE FUNCTION public.admin_advertiser_adjust_balance(
  p_advertiser_id uuid, p_delta_micros bigint, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_bal   bigint;
  v_res   bigint;
  v_avail bigint;
  v_debit bigint;
  v_group uuid := gen_random_uuid();
BEGIN
  IF NOT (SELECT app.is_money_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'reason required' USING errcode = '22023';
  END IF;
  IF p_delta_micros IS NULL OR p_delta_micros = 0 THEN
    RAISE EXCEPTION 'delta must be non-zero' USING errcode = '22003';
  END IF;

  -- Lock the balance row (create it for a credit if the advertiser has none yet).
  SELECT balance_micros, reserved_micros INTO v_bal, v_res
    FROM public.advertiser_balances WHERE advertiser_id = p_advertiser_id FOR UPDATE;
  IF NOT FOUND THEN
    IF p_delta_micros < 0 THEN
      RETURN jsonb_build_object('ok', false, 'reason', 'no_balance_row');
    END IF;
    INSERT INTO public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
      VALUES (p_advertiser_id, 0, 0);
    v_bal := 0; v_res := 0;
  END IF;

  IF p_delta_micros > 0 THEN
    -- Credit: Dr platform_cash +delta / Cr advertiser_funds −delta.
    UPDATE public.advertiser_balances
       SET balance_micros = balance_micros + p_delta_micros, updated_at = now()
     WHERE advertiser_id = p_advertiser_id;
    INSERT INTO public.ledger_entries
      (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
    VALUES
      (v_group, 'advertiser_adjustment', 'platform_cash',     p_delta_micros, 'cleared', 'advertiser_adjustment', p_advertiser_id, p_advertiser_id),
      (v_group, 'advertiser_adjustment', 'advertiser_funds', -p_delta_micros, 'cleared', 'advertiser_adjustment', p_advertiser_id, p_advertiser_id);
  ELSE
    -- Debit: guard AVAILABLE = balance − reserved (reserved-but-undrawn spend is off limits).
    v_debit := -p_delta_micros;
    v_avail := v_bal - v_res;
    IF v_debit > v_avail THEN
      RETURN jsonb_build_object('ok', false, 'reason', 'exceeds_available',
                                'available_micros', v_avail, 'requested_micros', v_debit);
    END IF;
    UPDATE public.advertiser_balances
       SET balance_micros = balance_micros - v_debit, updated_at = now()
     WHERE advertiser_id = p_advertiser_id;
    INSERT INTO public.ledger_entries
      (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
    VALUES
      (v_group, 'advertiser_adjustment', 'platform_cash',    -v_debit, 'cleared', 'advertiser_adjustment', p_advertiser_id, p_advertiser_id),
      (v_group, 'advertiser_adjustment', 'advertiser_funds',  v_debit, 'cleared', 'advertiser_adjustment', p_advertiser_id, p_advertiser_id);
  END IF;

  PERFORM app.log_admin_action('admin_adjust_balance', 'advertiser', p_advertiser_id,
    jsonb_build_object('delta_micros', p_delta_micros, 'reason', p_reason));
  PERFORM app.log_advertiser_action(p_advertiser_id, 'admin_adjust_balance', 'advertiser', p_advertiser_id,
    jsonb_build_object('delta_micros', p_delta_micros, 'reason', p_reason));

  RETURN jsonb_build_object('ok', true, 'advertiser_id', p_advertiser_id, 'delta_micros', p_delta_micros,
                            'entry_group_id', v_group);
END;
$$;
REVOKE ALL ON FUNCTION public.admin_advertiser_adjust_balance(uuid, bigint, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.admin_advertiser_adjust_balance(uuid, bigint, text) TO authenticated;

COMMENT ON FUNCTION public.admin_advertiser_adjust_balance IS
  'Money-admin (aal2) manual prepay balance adjustment: credit (Dr platform_cash / Cr advertiser_funds) or AVAILABLE-guarded debit (never pulls reserved-but-undrawn spend), zero-sum, balance == −SUM(advertiser_funds) preserved. NO withdrawal path (deposits non-refundable). Audited to both trails. SECDEF; authenticated (in-body aal2 re-check).';

-- ===========================================================================
-- 5. app.scan_selfdeal_risk() — NON-identity linkage scan (service_role cron).
--
-- The auth.uid() serving-exclusion (window_open, 20260716180000) only catches a SHARED identity; a
-- second email defeats it. This periodic scan catches the non-identity linkage the exclusion misses:
-- a recent impression whose crediting publisher shares a VERIFIED auth email (exact address OR the
-- same domain) with a member of the paying advertiser. Each hit is reversed via the idempotent
-- public.clawback (removing the fraudulent earning) and the publisher's payouts are HELD for manual
-- review — a publisher_payout_holds row PLUS a payout_status 'verified'→'pending' downgrade so
-- payout_batch_reserve's existing eligibility predicate (payout_status='verified',
-- payout_reserve_serialize.sql:63) skips them WITHOUT any edit to the payout transfer/confirm core.
--
-- Documented (spec §12): clean-money self-deal is economically self-limiting (−40% platform cut); the
-- real threat is stolen-card laundering, bounded at the source by first-deposit reserve + deposit
-- velocity caps (owner-tuned at deploy). This scan is the downstream backstop.
-- ===========================================================================
CREATE OR REPLACE FUNCTION app.scan_selfdeal_risk(
  p_window interval DEFAULT interval '30 days')
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  r          record;
  v_flagged  integer := 0;
  v_held     integer := 0;
  v_reserve  bigint;
BEGIN
  -- Linked billable impressions: publisher auth-email (exact or domain) == an advertiser_users
  -- member's auth-email of the PAYING advertiser. Only billable (provisional/cleared), only recent,
  -- only NOT already flagged for self-deal. House/sentinel advertisers have no advertiser_users → skip.
  FOR r IN
    SELECT DISTINCT i.id AS impression_id, i.publisher_id, i.window_id, c.advertiser_id
      FROM public.impressions i
      JOIN public.line_items  li ON li.id = i.line_item_id
      JOIN public.campaigns   c  ON c.id  = li.campaign_id
      JOIN public.advertiser_users au ON au.advertiser_id = c.advertiser_id
      JOIN public.publishers  p  ON p.id = i.publisher_id
      JOIN auth.users pu ON pu.id = p.auth_user_id
      JOIN auth.users vu ON vu.id = au.auth_user_id
     WHERE i.state IN ('provisional', 'cleared')
       AND i.gross_micros > 0
       AND i.created_at > now() - p_window
       AND pu.email IS NOT NULL AND vu.email IS NOT NULL
       AND (
         -- Exact-email match (the identity case; auth emails are unique, so this only coincides with a
         -- shared auth.uid() the provisioning + window_open exclusions already cover — kept as a belt).
         lower(pu.email) = lower(vu.email)
         -- Shared verified DOMAIN — the second-email linkage the identity checks miss. Free/public email
         -- providers (and the reserved test/example domains) are EXCLUDED: two unrelated parties sharing
         -- gmail.com is meaningless, and flagging it would be a mass false-positive. A shared CORPORATE
         -- domain is the actual self-deal signal.
         OR (position('@' in pu.email) > 0
             AND lower(split_part(pu.email, '@', 2)) = lower(split_part(vu.email, '@', 2))
             AND lower(split_part(pu.email, '@', 2)) NOT IN (
               'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
               'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com',
               'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'zoho.com', 'mail.com',
               'example.com', 'example.org', 'example.net', 'test.com', 'test'))
       )
       AND NOT EXISTS (
         SELECT 1 FROM public.risk_flags rf
          WHERE rf.window_id = i.window_id AND rf.reason = 'selfdeal:shared_email')
  LOOP
    -- Reverse the fraudulent earning (idempotent whole-window clawback).
    PERFORM public.clawback('impression', r.impression_id, 'selfdeal:shared_email');
    v_flagged := v_flagged + 1;

    -- Release + zero the window's stranded serve-time reserve (same rationale as
    -- admin_prepay_clawback: a clawed_back impression never enters a charge batch, so its reserve
    -- would otherwise inflate reserved_micros forever). No-op for a postpay/already-drawn window
    -- (reserve_micros=0) or an advertiser with no balance row (the UPDATE matches nothing).
    SELECT reserve_micros INTO v_reserve FROM public.ad_windows WHERE window_id = r.window_id;
    IF COALESCE(v_reserve, 0) > 0 THEN
      PERFORM app.advertiser_release(r.advertiser_id, v_reserve);
      UPDATE public.ad_windows SET reserve_micros = 0 WHERE window_id = r.window_id;
    END IF;

    -- Hold the publisher's payouts for manual review: record a hold + downgrade eligibility so the
    -- existing payout batch predicate skips them (the payout core is untouched).
    INSERT INTO public.publisher_payout_holds (publisher_id, reason)
    SELECT r.publisher_id, 'selfdeal:shared_email'
    WHERE NOT EXISTS (
      SELECT 1 FROM public.publisher_payout_holds h
       WHERE h.publisher_id = r.publisher_id AND h.reason = 'selfdeal:shared_email' AND h.released_at IS NULL);
    IF FOUND THEN
      v_held := v_held + 1;
    END IF;

    UPDATE public.publishers SET payout_status = 'pending'
     WHERE id = r.publisher_id AND payout_status = 'verified';
  END LOOP;

  RETURN jsonb_build_object('impressions_flagged', v_flagged, 'publishers_held', v_held);
END;
$$;
REVOKE ALL ON FUNCTION app.scan_selfdeal_risk(interval) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.scan_selfdeal_risk(interval) TO service_role;

COMMENT ON FUNCTION app.scan_selfdeal_risk IS
  'Service_role cron: reverse (via idempotent public.clawback) any recent billable impression whose crediting publisher shares a verified auth email (exact/domain) with a member of the paying advertiser (the non-identity self-deal linkage the window_open auth.uid() exclusion cannot catch), and hold that publisher''s payouts for review (publisher_payout_holds + payout_status verified→pending, no payout-core edit). service_role only.';

-- publisher_payout_holds — the manual-review hold record the scan writes (payout eligibility is the
-- payout_status downgrade above; this row is the reason/audit the reviewer releases).
CREATE TABLE IF NOT EXISTS public.publisher_payout_holds (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  publisher_id uuid NOT NULL REFERENCES public.publishers (id) ON DELETE CASCADE,
  reason       text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  released_at  timestamptz,
  released_by  uuid
);

COMMENT ON TABLE public.publisher_payout_holds IS
  'Manual-review payout holds (written by app.scan_selfdeal_risk on a self-deal linkage hit). The actual eligibility block is the paired payout_status verified→pending downgrade (payout_batch_reserve skips non-verified); this row records why, for a reviewer to release. Admin-visible only.';

CREATE INDEX IF NOT EXISTS publisher_payout_holds_pub_idx
  ON public.publisher_payout_holds (publisher_id) WHERE released_at IS NULL;

ALTER TABLE public.publisher_payout_holds ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS publisher_payout_holds_admin_read ON public.publisher_payout_holds;
CREATE POLICY publisher_payout_holds_admin_read ON public.publisher_payout_holds
  FOR SELECT TO authenticated USING ((SELECT app.is_admin()));
DROP POLICY IF EXISTS publisher_payout_holds_service ON public.publisher_payout_holds;
CREATE POLICY publisher_payout_holds_service ON public.publisher_payout_holds
  FOR ALL TO service_role USING (true) WITH CHECK (true);

REVOKE ALL    ON public.publisher_payout_holds FROM PUBLIC, anon;
GRANT  SELECT ON public.publisher_payout_holds TO authenticated;   -- admin-gated by RLS
GRANT  SELECT, INSERT, UPDATE ON public.publisher_payout_holds TO service_role;

-- ===========================================================================
-- 6. GDPR erasure (self + admin) + data export.
--
-- Mirrors gdpr_self_delete.sql:28-153: one shared SECDEF body (app.advertiser_gdpr_erase) both entry
-- points delegate to, so the ledger/refusal invariants can never drift. Refuses while ANY money is in
-- flight; anonymizes advertisers.name+stripe_customer_id + tombstones member auth emails; pauses the
-- org's campaigns/line_items (stops serving without touching the protected `status`); PRESERVES the
-- balance ledger + action log as financial records. Idempotent via advertisers.deleted_at.
--
-- PROTECTED-COLUMN NOTE: nulling stripe_customer_id trips app.advertisers_protect_cols (which allows a
-- protected-column change ONLY when the request JWT role is service_role, 20260716150000:316-343). The
-- erase runs for an `authenticated` caller (self or admin), so it briefly injects role=service_role
-- into the request claims (transaction-local set_config) around the advertisers UPDATE, then restores
-- them — the same authority the billing edge fn uses to persist stripe_customer_id, applied narrowly.
-- ===========================================================================
CREATE OR REPLACE FUNCTION app.advertiser_gdpr_erase(p_advertiser_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_adv        public.advertisers%ROWTYPE;
  v_claims     text;
  v_paused_li  integer := 0;
  v_paused_cp  integer := 0;
  v_emails     integer := 0;
BEGIN
  SELECT * INTO v_adv FROM public.advertisers WHERE id = p_advertiser_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'advertiser not found' USING errcode = 'P0002';
  END IF;

  -- Never erase the house/sentinel advertiser.
  IF v_adv.is_house THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'house_advertiser');
  END IF;

  -- Idempotent.
  IF v_adv.deleted_at IS NOT NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_deleted');
  END IF;

  -- Money-safety: refuse while ANY money is in flight (funds + reserve must settle first).
  IF EXISTS (SELECT 1 FROM public.advertiser_balances b
              WHERE b.advertiser_id = p_advertiser_id AND (b.balance_micros > 0 OR b.reserved_micros > 0)) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'balance_or_reserved_nonzero');
  END IF;
  IF EXISTS (SELECT 1 FROM public.advertiser_topup_intents t
              WHERE t.advertiser_id = p_advertiser_id AND t.status = 'pending') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'topup_pending');
  END IF;
  IF EXISTS (SELECT 1 FROM public.advertiser_charges ac
              WHERE ac.advertiser_id = p_advertiser_id AND ac.status = 'pending') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'charge_pending');
  END IF;
  IF EXISTS (SELECT 1 FROM public.uncharged_advertiser_billings u
              WHERE u.advertiser_id = p_advertiser_id) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'uncharged_postpay_billings');
  END IF;

  -- Stop serving: pause the org's active campaigns + line_items (NOT the protected advertiser status).
  UPDATE public.line_items SET status = 'paused'
   WHERE status = 'active'
     AND campaign_id IN (SELECT id FROM public.campaigns WHERE advertiser_id = p_advertiser_id);
  GET DIAGNOSTICS v_paused_li = ROW_COUNT;
  UPDATE public.campaigns SET status = 'paused'
   WHERE advertiser_id = p_advertiser_id AND status = 'active';
  GET DIAGNOSTICS v_paused_cp = ROW_COUNT;

  -- Anonymize the advertiser row IN PLACE (name + stripe_customer_id + deleted_at). stripe_customer_id
  -- is a protected column → briefly present a service_role role claim to the protect trigger.
  v_claims := current_setting('request.jwt.claims', true);
  PERFORM set_config('request.jwt.claims',
    (coalesce(nullif(v_claims, ''), '{}')::jsonb || jsonb_build_object('role', 'service_role'))::text, true);

  UPDATE public.advertisers
     SET name               = 'deleted-' || left(id::text, 8),
         stripe_customer_id = NULL,
         deleted_at         = now()
   WHERE id = p_advertiser_id;

  PERFORM set_config('request.jwt.claims', coalesce(v_claims, ''), true);   -- restore

  -- Tombstone the auth identity of every mapped member (the strongest PII: email). Done in place so
  -- the advertiser_users→auth.users FK is preserved (mappings kept so current_advertiser_id() still
  -- resolves for an idempotent repeat call, mirroring gdpr_self_delete's keep-in-place semantics).
  UPDATE auth.users u SET
    email              = 'deleted-' || left(u.id::text, 8) || '@deleted.invalid',
    phone              = NULL,
    raw_user_meta_data = '{}'::jsonb,
    raw_app_meta_data  = '{}'::jsonb
  WHERE u.id IN (SELECT auth_user_id FROM public.advertiser_users WHERE advertiser_id = p_advertiser_id);
  GET DIAGNOSTICS v_emails = ROW_COUNT;

  -- advertiser_balance_ledger + advertiser_action_log are PRESERVED (financial/audit records; they
  -- carry no user-authored free-text — creative copy lives in creatives, which no longer serves).
  PERFORM app.log_advertiser_action(p_advertiser_id, 'gdpr_erase', 'advertiser', p_advertiser_id,
    jsonb_build_object('emails_tombstoned', v_emails, 'campaigns_paused', v_paused_cp,
                       'line_items_paused', v_paused_li));

  RETURN jsonb_build_object('ok', true, 'advertiser_id', p_advertiser_id,
                            'emails_tombstoned', v_emails,
                            'campaigns_paused', v_paused_cp, 'line_items_paused', v_paused_li);
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_gdpr_erase(uuid) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.advertiser_gdpr_erase IS
  'Private shared body for advertiser GDPR erasure (anonymize name+stripe_customer_id, tombstone member auth emails, pause campaigns/line_items, PRESERVE the balance ledger + action log). Refuses while money is in flight; idempotent via advertisers.deleted_at. Reached only via the SECDEF self/admin wrappers; never callable by client roles.';

-- Self-serve entry point — no argument, target derived from the caller's own session.
CREATE OR REPLACE FUNCTION public.advertiser_gdpr_self_delete()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_adv uuid;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;
  RETURN app.advertiser_gdpr_erase(v_adv);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_gdpr_self_delete() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_gdpr_self_delete() TO authenticated;

COMMENT ON FUNCTION public.advertiser_gdpr_self_delete IS
  'Self-serve GDPR erasure for the advertiser portal. Derives the target from app.current_advertiser_id() (the caller''s own auth.uid()) — no argument, so it cannot target another org. Delegates to app.advertiser_gdpr_erase. Refuses while money is in flight; idempotent.';

-- Admin support entry point — erase an org by id.
CREATE OR REPLACE FUNCTION public.advertiser_gdpr_delete(p_advertiser_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;
  RETURN app.advertiser_gdpr_erase(p_advertiser_id);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_gdpr_delete(uuid) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_gdpr_delete(uuid) TO authenticated;

COMMENT ON FUNCTION public.advertiser_gdpr_delete IS
  'Admin-only GDPR erasure (support path): gates on app.is_admin() then delegates to app.advertiser_gdpr_erase. Idempotent; refuses while money is in flight.';

-- Self-serve data export — the caller's own campaigns/creatives/spend/deposits.
CREATE OR REPLACE FUNCTION public.advertiser_data_export()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_adv uuid;
  v_out jsonb;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  SELECT jsonb_build_object(
    'advertiser',
      (SELECT jsonb_build_object('id', a.id, 'name', a.name, 'status', a.status,
                                 'billing_mode', a.billing_mode, 'created_at', a.created_at)
         FROM public.advertisers a WHERE a.id = v_adv),
    'campaigns',
      COALESCE((SELECT jsonb_agg(jsonb_build_object(
                 'id', c.id, 'name', c.name, 'status', c.status, 'created_at', c.created_at))
                  FROM public.campaigns c WHERE c.advertiser_id = v_adv), '[]'::jsonb),
    'line_items',
      COALESCE((SELECT jsonb_agg(jsonb_build_object(
                 'id', li.id, 'campaign_id', li.campaign_id, 'cpva_bid_micros', li.cpva_bid_micros,
                 'status', li.status, 'budget_total_micros', li.budget_total_micros,
                 'budget_daily_micros', li.budget_daily_micros, 'created_at', li.created_at))
                  FROM public.line_items li
                  JOIN public.campaigns c ON c.id = li.campaign_id
                 WHERE c.advertiser_id = v_adv), '[]'::jsonb),
    'creatives',
      COALESCE((SELECT jsonb_agg(jsonb_build_object(
                 'id', cr.id, 'line_item_id', cr.line_item_id, 'line', cr.line,
                 'dest_url', cr.dest_url, 'label', cr.label, 'status', cr.status, 'created_at', cr.created_at))
                  FROM public.creatives cr
                  JOIN public.line_items li ON li.id = cr.line_item_id
                  JOIN public.campaigns  c  ON c.id  = li.campaign_id
                 WHERE c.advertiser_id = v_adv), '[]'::jsonb),
    'deposits',
      COALESCE((SELECT jsonb_agg(jsonb_build_object(
                 'kind', bl.kind, 'amount_micros', bl.amount_micros, 'created_at', bl.created_at))
                  FROM public.advertiser_balance_ledger bl
                 WHERE bl.advertiser_id = v_adv), '[]'::jsonb),
    'spend', public.advertiser_spend_summary()
  ) INTO v_out;

  RETURN v_out;
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_data_export() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_data_export() TO authenticated;

COMMENT ON FUNCTION public.advertiser_data_export IS
  'Self-serve GDPR data export: the caller''s own advertiser + campaigns/line_items/creatives/deposits + spend summary (self-scoped via app.current_advertiser_id()). SECDEF STABLE; authenticated.';

-- ===========================================================================
-- 7. Migration-tail assertion — anon must hold NO EXECUTE on any function added here.
-- ===========================================================================
DO $$
DECLARE
  v_fn  text;
  v_fns text[] := ARRAY[
    'app.log_advertiser_action(uuid, text, text, uuid, jsonb)',
    'app.advertiser_action_log_immutable()',
    'app.scan_selfdeal_risk(interval)',
    'app.advertiser_gdpr_erase(uuid)',
    'public.advertiser_approve_creative(uuid)',
    'public.advertiser_reject_creative(uuid, text)',
    'public.advertiser_suspend_creative(uuid, text)',
    'public.admin_prepay_clawback(uuid, text)',
    'public.admin_advertiser_adjust_balance(uuid, bigint, text)',
    'public.advertiser_gdpr_self_delete()',
    'public.advertiser_gdpr_delete(uuid)',
    'public.advertiser_data_export()'
  ];
BEGIN
  FOREACH v_fn IN ARRAY v_fns LOOP
    IF has_function_privilege('anon', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    END IF;
  END LOOP;
END;
$$;
