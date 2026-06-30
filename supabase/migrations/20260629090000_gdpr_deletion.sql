-- lumaline M3-T5 — GDPR right-to-erasure: gdpr_delete_publisher().
--
-- Removes a publisher's PERSONAL data while PRESERVING the financial ledger so
-- accounting integrity and the zero-sum invariant survive an erasure request:
--
--   REMOVED / scrubbed (PII):
--     * publishers.handle           -> 'deleted-<id8>'   (chosen handle is PII)
--     * publishers.country          -> null
--     * publishers.stripe_account_id-> null
--     * devices                     -> deleted (labels, attestation, install metadata)
--     * device_auth_codes           -> deleted
--     * disputes.description        -> '[redacted: account deleted]' (free-text PII; row kept for audit)
--     * auth.users email/phone/meta -> tombstoned; sessions + identities revoked
--
--   PRESERVED (financial integrity — NEVER deleted):
--     * impressions / ledger_entries / payouts keyed by publisher_id stay intact.
--       The publishers row is ANONYMIZED IN PLACE (not deleted) so it remains the
--       opaque anchor for those records and the deferred zero-sum trigger never fires.
--
-- Anonymize-in-place is required: publishers.auth_user_id is `on delete cascade`
-- from auth.users, and ledger_entries/payouts/impressions FK publishers(id). Deleting
-- the publisher (or its auth user) would cascade-destroy the financial trail.
--
-- Admin-gated (SECURITY DEFINER + app.is_admin()), idempotent, and refuses to run
-- while a payout is in flight (money-safety).

ALTER TABLE public.publishers ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
COMMENT ON COLUMN public.publishers.deleted_at IS
  'Set by gdpr_delete_publisher() when the account was erased; row is retained (anonymized) to anchor the financial ledger.';

CREATE OR REPLACE FUNCTION public.gdpr_delete_publisher(p_publisher_id uuid)
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
  -- Admin gate.
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

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
    'ok',               true,
    'publisher_id',     p_publisher_id,
    'devices_deleted',  v_devices,
    'disputes_scrubbed', v_disputes
  );
END;
$$;

REVOKE ALL ON FUNCTION public.gdpr_delete_publisher(uuid) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.gdpr_delete_publisher(uuid) TO authenticated;

COMMENT ON FUNCTION public.gdpr_delete_publisher IS
  'Admin-only GDPR erasure: scrubs publisher PII (handle/country/stripe/email), deletes devices, redacts dispute text, anonymizes the publishers row IN PLACE so impressions/ledger_entries/payouts stay intact and balanced. Idempotent; refuses while a payout is in flight.';
