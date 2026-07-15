-- lumaline M7 — self-serve GDPR erasure for the publisher web portal.
--
-- The publisher dashboard (a direct Supabase Auth web session) needs an Account
-- "delete my account" action. The existing gdpr_delete_publisher(uuid) is ADMIN-ONLY
-- (it raises 'unauthorized' for a normal session) and takes an arbitrary publisher id
-- — neither shape is safe to expose to a self-serve caller.
--
-- This migration:
--   1. Extracts the erasure BODY (unchanged) into a private helper
--      app.gdpr_erase_publisher(uuid) so both entry points share ONE implementation
--      and the ledger/zero-sum invariants can never drift between them.
--   2. Re-defines public.gdpr_delete_publisher(uuid) with the SAME external contract
--      (admin-gated) — it now just gates then delegates to the helper.
--   3. Adds public.gdpr_self_delete() — NEW self-serve path: it takes NO argument and
--      derives the target strictly from app.current_publisher_id() (the caller's own
--      auth.uid()). There is no attacker-controllable input, so it is structurally
--      impossible to erase another publisher. No admin gate; granted to `authenticated`.
--
-- Erasure semantics (lock, idempotent already_deleted, payout-in-flight refusal,
-- anonymize-in-place, dispute redaction, auth email tombstone, ledger PRESERVED) are
-- byte-identical for both paths — see the original 20260629090000_gdpr_deletion.sql.

-- ---------------------------------------------------------------------------
-- Private erasure helper — the shared body. SECURITY DEFINER so it can touch
-- auth.users; revoked from all client roles so ONLY the two SECURITY DEFINER
-- wrappers below (executing as the function owner) can reach it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.gdpr_erase_publisher(p_publisher_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_pub      public.publishers%ROWTYPE;
  v_devices  integer := 0;
  v_disputes integer := 0;
BEGIN
  -- Lock the publisher.
  SELECT * INTO v_pub FROM public.publishers WHERE id = p_publisher_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'publisher not found' USING errcode = 'P0002';
  END IF;

  -- Idempotent.
  IF v_pub.deleted_at IS NOT NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_deleted');
  END IF;

  -- Money-safety: never erase a publisher with money in flight. The clawback/payout
  -- trail must settle (or fail) first so funds and PII are reconciled before erasure.
  IF EXISTS (
    SELECT 1 FROM public.payouts
    WHERE publisher_id = p_publisher_id AND status IN ('pending', 'in_transit')
  ) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'payout_in_flight');
  END IF;

  -- Remove device PII (no financial value).
  DELETE FROM public.devices WHERE publisher_id = p_publisher_id;
  GET DIAGNOSTICS v_devices = ROW_COUNT;
  DELETE FROM public.device_auth_codes WHERE publisher_id = p_publisher_id;

  -- Scrub free-text PII in disputes but keep the rows for audit.
  UPDATE public.disputes
     SET description = '[redacted: account deleted]'
   WHERE publisher_id = p_publisher_id;
  GET DIAGNOSTICS v_disputes = ROW_COUNT;

  -- Anonymize the publisher row IN PLACE (preserves ledger linkage).
  UPDATE public.publishers SET
    handle            = 'deleted-' || left(id::text, 8),
    country           = NULL,
    stripe_account_id = NULL,
    payout_status     = 'none',
    status            = 'suspended',
    deleted_at        = now()
  WHERE id = p_publisher_id;

  -- Tombstone the auth identity (the strongest PII: email). Done in place so the
  -- on-delete-cascade FK from publishers.auth_user_id does NOT fire.
  UPDATE auth.users SET
    email              = 'deleted-' || left(p_publisher_id::text, 8) || '@deleted.invalid',
    phone              = NULL,
    raw_user_meta_data = '{}'::jsonb,
    raw_app_meta_data  = '{}'::jsonb
  WHERE id = v_pub.auth_user_id;

  -- Best-effort revoke of sessions/identities (auth internals vary by version).
  BEGIN DELETE FROM auth.sessions   WHERE user_id = v_pub.auth_user_id; EXCEPTION WHEN others THEN NULL; END;
  BEGIN DELETE FROM auth.identities WHERE user_id = v_pub.auth_user_id; EXCEPTION WHEN others THEN NULL; END;

  RETURN jsonb_build_object(
    'ok',                true,
    'publisher_id',      p_publisher_id,
    'devices_deleted',   v_devices,
    'disputes_scrubbed', v_disputes
  );
END;
$$;
REVOKE ALL ON FUNCTION app.gdpr_erase_publisher(uuid) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.gdpr_erase_publisher IS
  'Private shared body for GDPR erasure (anonymize-in-place, ledger preserved, idempotent, refuses while a payout is in flight). Reached only via the SECURITY DEFINER wrappers gdpr_delete_publisher()/gdpr_self_delete(); never callable by client roles.';

-- ---------------------------------------------------------------------------
-- Admin entry point — unchanged external contract, now delegates to the helper.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.gdpr_delete_publisher(p_publisher_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;
  RETURN app.gdpr_erase_publisher(p_publisher_id);
END;
$$;
REVOKE ALL ON FUNCTION public.gdpr_delete_publisher(uuid) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.gdpr_delete_publisher(uuid) TO authenticated;

COMMENT ON FUNCTION public.gdpr_delete_publisher IS
  'Admin-only GDPR erasure (support path): gates on app.is_admin() then delegates to app.gdpr_erase_publisher. Idempotent; refuses while a payout is in flight.';

-- ---------------------------------------------------------------------------
-- Self-serve entry point — the publisher deletes THEIR OWN account.
-- No argument: the target is derived from the caller's own session, so it can
-- never be pointed at another publisher.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.gdpr_self_delete()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_pid uuid;
BEGIN
  v_pid := (SELECT app.current_publisher_id());
  IF v_pid IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;
  RETURN app.gdpr_erase_publisher(v_pid);
END;
$$;
REVOKE ALL ON FUNCTION public.gdpr_self_delete() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.gdpr_self_delete() TO authenticated;

COMMENT ON FUNCTION public.gdpr_self_delete IS
  'Self-serve GDPR erasure for the publisher web portal. Derives the target from app.current_publisher_id() (the caller''s own auth.uid()) — no argument, so it cannot target another publisher. Delegates to app.gdpr_erase_publisher. Idempotent; refuses while a payout is in flight.';
