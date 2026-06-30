-- lumaline M3 carry-forward — resolve_dispute admin RPC.
--
-- M2-T6 added the `disputes` table (publisher appeals) with status open/resolved/rejected
-- and resolution/resolved_at columns, but shipped NO RPC to transition open -> resolved.
-- Resolving a dispute was a manual DB action. This migration adds the admin-gated RPC,
-- mirroring approve_clawback/reject_clawback exactly:
--   * SECURITY DEFINER, exposed via PostgREST (public schema)
--   * app.is_admin() gate (anon/non-admin rejected with errcode 28000)
--   * FOR UPDATE row lock + idempotent status<>'open' guard
--   * full audit trail (who resolved, when, the resolution text)

-- ---------------------------------------------------------------------------
-- A. resolved_by audit column (parity with clawback_reviews.reviewed_by).
-- ---------------------------------------------------------------------------
ALTER TABLE public.disputes ADD COLUMN IF NOT EXISTS resolved_by uuid;

-- ---------------------------------------------------------------------------
-- B. public.resolve_dispute — admin transitions a dispute open -> resolved/rejected.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.resolve_dispute(
  p_dispute_id uuid,
  p_status     text,
  p_resolution text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_dispute public.disputes%ROWTYPE;
  v_admin   uuid;
BEGIN
  -- Admin gate — PostgREST installs auth.uid() from the forwarded JWT.
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  -- Only the two terminal states are permitted.
  IF p_status NOT IN ('resolved', 'rejected') THEN
    RAISE EXCEPTION 'invalid status %', p_status USING errcode = '22023';
  END IF;

  -- Lock the dispute to prevent concurrent double-resolution.
  SELECT * INTO v_dispute
  FROM public.disputes
  WHERE id = p_dispute_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'dispute not found' USING errcode = 'P0002';
  END IF;

  IF v_dispute.status <> 'open' THEN
    -- Idempotent: already resolved/rejected — return current state without error.
    RETURN jsonb_build_object('ok', false, 'reason', 'already_resolved', 'status', v_dispute.status);
  END IF;

  v_admin := nullif(app.jwt_claim('sub'), '')::uuid;

  UPDATE public.disputes SET
    status      = p_status,
    resolution  = p_resolution,
    resolved_by = v_admin,
    resolved_at = now()
  WHERE id = p_dispute_id;

  RETURN jsonb_build_object(
    'ok',         true,
    'dispute_id', p_dispute_id,
    'status',     p_status
  );
END;
$$;

REVOKE ALL ON FUNCTION public.resolve_dispute(uuid, text, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.resolve_dispute(uuid, text, text) TO authenticated;

COMMENT ON FUNCTION public.resolve_dispute IS
  'Admin-only: transition a publisher dispute open -> resolved/rejected with an audit trail (resolved_by/resolved_at/resolution). Exposed via PostgREST RPC. Idempotent on already-resolved disputes.';
