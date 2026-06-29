-- lumaline M2-T6 — Human-gated clawback review queue + publisher disputes + refund path.
--
-- Design: scan_ivt() flags suspicious impressions → risk_flags (already done). This
-- migration wraps that flag in a human review queue (clawback_reviews). No impression is
-- ever automatically reversed — an admin must explicitly approve_clawback() with a
-- documented reason. On approval, public.clawback() executes the reversal. After a Stripe
-- charge has already been issued for the impression, the /billing/refund endpoint uses
-- clawback_reviews.refund_queued to ensure a Stripe refund is issued exactly once.
--
-- TRUST INVARIANTS:
--   1. No auto-reversal — all reversals require human admin approval (logged: who, when, why).
--   2. Sentinel/house (gross_micros=0) clawbacks are structural no-ops: approve_clawback()
--      detects gross=0 and marks approved without calling clawback() (nothing financial to reverse).
--   3. Stripe refund uses payment_intent (pi_*), not charge — matching how T4 stores the id.
--   4. impressions.stripe_charge_id links an impression to its Stripe PaymentIntent for refunds.
--   5. Publisher disputes are RLS-scoped: a publisher can only read/create their own disputes.

-- ---------------------------------------------------------------------------
-- A. stripe_charge_id on impressions — set by /billing/charge after success.
--    Nullable: only impressions that were charged and succeeded have this set.
-- ---------------------------------------------------------------------------
ALTER TABLE public.impressions ADD COLUMN IF NOT EXISTS stripe_charge_id text;

-- ---------------------------------------------------------------------------
-- B. clawback_reviews table — the human review queue.
--
-- One row per flagged impression. scan_ivt() creates rows (status='pending').
-- Admin calls approve_clawback()/reject_clawback() to advance the state.
-- The /billing/refund endpoint uses refund_queued to ensure idempotency.
-- ---------------------------------------------------------------------------
CREATE TABLE public.clawback_reviews (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  risk_flag_id  uuid NOT NULL REFERENCES public.risk_flags (id),
  impression_id uuid REFERENCES public.impressions (id),
  status        text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_by   uuid,         -- auth_user_id of admin who approved/rejected
  review_reason text,         -- admin's documented rationale
  reviewed_at   timestamptz,
  refund_queued boolean NOT NULL DEFAULT false,
  refund_id     text,         -- Stripe refund ID (re_*) once issued
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.clawback_reviews ENABLE ROW LEVEL SECURITY;

-- Admins can read and manage all reviews.
CREATE POLICY clawback_reviews_admin ON public.clawback_reviews
  FOR ALL TO authenticated
  USING ((SELECT app.is_admin()))
  WITH CHECK ((SELECT app.is_admin()));

-- service_role used by billing edge function for refund path.
CREATE POLICY clawback_reviews_service ON public.clawback_reviews
  FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE ON public.clawback_reviews TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.clawback_reviews TO service_role;

-- ---------------------------------------------------------------------------
-- C. disputes table — publisher appeals (RLS-scoped, never admin-only).
--
-- A publisher can dispute a clawback on one of their own impressions. This
-- does NOT automatically undo anything — it creates a record for admin review.
-- ---------------------------------------------------------------------------
CREATE TABLE public.disputes (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  publisher_id  uuid NOT NULL REFERENCES public.publishers (id),
  impression_id uuid REFERENCES public.impressions (id),
  description   text NOT NULL,
  status        text NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'resolved', 'rejected')),
  resolution    text,
  resolved_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.disputes ENABLE ROW LEVEL SECURITY;

-- Publishers can create/read disputes for their own impressions.
-- RLS uses the jwt_claim('publisher_id') so a device JWT naturally scopes here.
CREATE POLICY disputes_publisher ON public.disputes
  FOR ALL TO authenticated
  USING  (publisher_id = (SELECT nullif(app.jwt_claim('publisher_id'), '')::uuid))
  WITH CHECK (publisher_id = (SELECT nullif(app.jwt_claim('publisher_id'), '')::uuid));

-- Admins have full access for dispute resolution.
CREATE POLICY disputes_admin ON public.disputes
  FOR ALL TO authenticated
  USING  ((SELECT app.is_admin()))
  WITH CHECK ((SELECT app.is_admin()));

-- service_role insert from auth-device edge function after ownership check.
CREATE POLICY disputes_service ON public.disputes
  FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

GRANT SELECT, INSERT ON public.disputes TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.disputes TO service_role;

-- ---------------------------------------------------------------------------
-- D. Modified scan_ivt — creates clawback_reviews rows for each flag.
--
-- Change from the T3 version: after inserting into risk_flags, also insert
-- a clawback_review (status='pending') so the impression waits for admin
-- approval rather than being auto-reversed. The NOT EXISTS guard on risk_flags
-- already ensures idempotency — re-runs won't produce duplicate reviews.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.scan_ivt(
  p_window interval DEFAULT interval '60 seconds',
  p_max    integer  DEFAULT 20
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_flagged integer := 0;
  v_rf_id   uuid;
  r         record;
BEGIN
  FOR r IN
    SELECT i.id, i.window_id
    FROM public.impressions i
    WHERE i.state = 'provisional'
      AND i.created_at > now() - p_window
      AND NOT EXISTS (
        SELECT 1 FROM public.risk_flags rf WHERE rf.impression_id = i.id
      )
      AND (
        SELECT count(*)
        FROM public.impressions i2
        WHERE i2.publisher_id = i.publisher_id
          AND i2.created_at   > now() - p_window
          AND i2.state IN ('provisional', 'cleared')
      ) > p_max
  LOOP
    -- Insert the risk flag, capturing its generated id.
    INSERT INTO public.risk_flags (impression_id, window_id, reason)
    VALUES (r.id, r.window_id, 'ivt:rate')
    RETURNING id INTO v_rf_id;

    -- Queue a human review (no auto-reversal; admin must approve_clawback).
    INSERT INTO public.clawback_reviews (risk_flag_id, impression_id, status)
    VALUES (v_rf_id, r.id, 'pending');

    v_flagged := v_flagged + 1;
  END LOOP;

  RETURN v_flagged;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.scan_ivt(interval, integer) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.scan_ivt(interval, integer) TO service_role;

-- ---------------------------------------------------------------------------
-- E. public.approve_clawback — execute a clawback after human review.
--
-- Placed in public (not app) so PostgREST exposes it via /rest/v1/rpc/approve_clawback
-- for direct admin calls. Internally gated by app.is_admin() so only real admins
-- can call it with an authenticated JWT. service_role can also call it via RPC
-- (the function's own admin check uses auth.uid() which is null for service_role,
-- so service_role must bypass the gate — use the /billing/* edge function instead).
--
-- Sentinel/house no-op: if impression.gross_micros <= 0, marks approved without
-- calling clawback() — there is nothing financial to reverse.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.approve_clawback(
  p_review_id uuid,
  p_reason    text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_review    public.clawback_reviews%ROWTYPE;
  v_admin     uuid;
  v_gross     bigint;
  v_cb_result jsonb;
BEGIN
  -- Admin gate — PostgREST installs auth.uid() from the forwarded JWT.
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  -- Lock the review row for update to prevent concurrent double-approvals.
  SELECT * INTO v_review
  FROM public.clawback_reviews
  WHERE id = p_review_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'review not found' USING errcode = 'P0002';
  END IF;

  IF v_review.status <> 'pending' THEN
    -- Idempotent: already acted on — return current state without error.
    RETURN jsonb_build_object('ok', false, 'reason', 'already_reviewed', 'status', v_review.status);
  END IF;

  v_admin := nullif(app.jwt_claim('sub'), '')::uuid;

  -- Sentinel/house no-op: no impression linked or gross_micros <= 0.
  -- Nothing financial to reverse; mark approved and exit cleanly.
  IF v_review.impression_id IS NULL THEN
    UPDATE public.clawback_reviews SET
      status        = 'approved',
      reviewed_by   = v_admin,
      review_reason = p_reason,
      reviewed_at   = now()
    WHERE id = p_review_id;
    RETURN jsonb_build_object('ok', true, 'clawed_back', null, 'reason', 'no_op_no_impression');
  END IF;

  SELECT gross_micros INTO v_gross
  FROM public.impressions
  WHERE id = v_review.impression_id;

  IF v_gross IS NULL OR v_gross <= 0 THEN
    UPDATE public.clawback_reviews SET
      status        = 'approved',
      reviewed_by   = v_admin,
      review_reason = p_reason,
      reviewed_at   = now()
    WHERE id = p_review_id;
    RETURN jsonb_build_object('ok', true, 'clawed_back', null, 'reason', 'no_op_gross_zero');
  END IF;

  -- Execute the reversal — reverses all ledger entries and marks the impression clawed_back.
  v_cb_result := public.clawback('impression', v_review.impression_id, p_reason);

  -- Record the approval with full audit trail.
  UPDATE public.clawback_reviews SET
    status        = 'approved',
    reviewed_by   = v_admin,
    review_reason = p_reason,
    reviewed_at   = now()
  WHERE id = p_review_id;

  RETURN jsonb_build_object(
    'ok',          true,
    'clawed_back', v_review.impression_id,
    'clawback',    v_cb_result
  );
END;
$$;

-- Callable by authenticated admins via PostgREST; anon cannot call it.
REVOKE ALL ON FUNCTION public.approve_clawback(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.approve_clawback(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.approve_clawback IS
  'Admin-only: approve a pending clawback review. Calls clawback() then records the admin decision. Sentinel (gross=0) is a no-op. Exposed via PostgREST RPC.';

-- ---------------------------------------------------------------------------
-- F. public.reject_clawback — dismiss a pending review without reversing anything.
--
-- Same PostgREST-accessible pattern as approve_clawback. Marks the review
-- rejected with the admin's documented reason; the impression state is unchanged.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.reject_clawback(
  p_review_id uuid,
  p_reason    text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_review public.clawback_reviews%ROWTYPE;
  v_admin  uuid;
BEGIN
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  SELECT * INTO v_review
  FROM public.clawback_reviews
  WHERE id = p_review_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'review not found' USING errcode = 'P0002';
  END IF;

  IF v_review.status <> 'pending' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_reviewed', 'status', v_review.status);
  END IF;

  v_admin := nullif(app.jwt_claim('sub'), '')::uuid;

  UPDATE public.clawback_reviews SET
    status        = 'rejected',
    reviewed_by   = v_admin,
    review_reason = p_reason,
    reviewed_at   = now()
  WHERE id = p_review_id;

  RETURN jsonb_build_object(
    'ok',      true,
    'rejected', p_review_id,
    'reason',   p_reason
  );
END;
$$;

REVOKE ALL ON FUNCTION public.reject_clawback(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.reject_clawback(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.reject_clawback IS
  'Admin-only: reject a pending clawback review. The impression state is unchanged; only the review is marked rejected. Exposed via PostgREST RPC.';
