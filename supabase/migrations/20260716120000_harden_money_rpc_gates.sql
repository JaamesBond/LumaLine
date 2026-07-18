-- lumaline M8-T3 — harden the ALREADY-DEPLOYED money/destructive admin gates.
--
-- CREATE OR REPLACE the two live, dangerous admin RPCs so their FIRST-LINE gate moves
-- from app.is_admin() (membership only, aal1-satisfiable) to app.is_money_admin()
-- (app.money_admins membership AND jwt aal='aal2' — 20260716100000). Each also gains a
-- single app.log_admin_action() append-only audit write. The rest of each body is
-- BYTE-IDENTICAL to the shipped version:
--   * public.approve_clawback  — 20260629070000_clawback_review.sql:173-253
--   * public.gdpr_delete_publisher — 20260705120000_gdpr_self_delete.sql:109-121
--
-- WHY: today a stolen aal1 magic-link inbox (or a read/triage-only admin) can reverse
-- money (approve_clawback → public.clawback()) and erase publishers (gdpr_delete_publisher).
-- Re-gating to is_money_admin() closes 'aal1 magic-link session = treasury/GDPR power' and
-- 'any admin is a money admin' for the surfaces that are LIVE today, not merely the new one.
--
-- WHAT IS INTENTIONALLY NOT TOUCHED:
--   * reject_clawback (20260629070000_clawback_review.sql:268) and resolve_dispute
--     (20260629080000_resolve_dispute.sql:20) stay on app.is_admin() — they are non-money
--     / non-destructive, so a triage-only admin (app.admins, NOT app.money_admins) keeps
--     working. Least privilege: routine-admin compromise is not a treasury compromise.
--   * The reversal/erasure bodies are unchanged, so money-safety, idempotency, the
--     sentinel/gross<=0 no-op, the FOR UPDATE locks, and the ledger-preserving erase are
--     preserved BY CONSTRUCTION. The only behavioural change is the gate predicate.
--
-- ===========================================================================================
-- ⚠  DEPLOY-ORDERING HAZARD — LOAD-BEARING, OWNER-GATED. READ BEFORE APPLYING TO PROD.  ⚠
-- ===========================================================================================
-- This migration is a SELF-LOCKOUT risk. Deploy it ONLY AFTER all of the following are true,
-- or the sole admin can no longer approve clawbacks / erase publishers (is_money_admin()
-- would return false for the owner and every money action would RAISE 28000):
--   1. MFA is ENABLED on the project (config.toml auth.mfa.totp enroll_enabled = true) and a
--      TOTP factor is ENROLLED on the owner Auth account.
--   2. The owner auth_user_id is SEEDED into BOTH app.admins AND app.money_admins, out-of-band
--      (service_role / SQL) — never from a client.
--   3. An aal2 session (TOTP verified) has been confirmed to return TRUE from
--      app.is_money_admin() (e.g. select app.is_money_admin() under that session).
-- The foundation migration (20260716100000) is inert until money_admins is seeded, so it is
-- safe to deploy first; THIS migration is the first one that reduces a live gate to aal2 and
-- must not ship until steps 1–3 above are verified.
-- ===========================================================================================

-- MECHANICAL self-lockout guard (replaces the comment-only warning above). Refuse to apply the
-- aal2 re-gate on a database that ALREADY has seeded admins (app.admins non-empty) but NO money
-- admin (app.money_admins empty) — that is exactly the half-configured prod state where the sole
-- admin would be locked out of approve_clawback / gdpr_delete_publisher (is_money_admin() would
-- return false for everyone). It fires ONLY in that dangerous combination:
--   * A fresh local / CI stack (`supabase db reset`) applies migrations BEFORE seed.sql runs, so
--     app.admins is still EMPTY here → the guard is a no-op and the reset proceeds (tests seed
--     their own admins + money_admins at runtime, long after this DO block ran).
--   * In PROD, the live owner is already in app.admins; this guard then forces the T0 step
--     (seed app.money_admins) to have happened before the re-gate can apply.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM app.admins)
     AND NOT EXISTS (SELECT 1 FROM app.money_admins) THEN
    RAISE EXCEPTION USING
      errcode = '55000',
      message = 'SELF-LOCKOUT GUARD: app.admins is seeded but app.money_admins is EMPTY. '
             || 'Seed the owner into app.money_admins (and enroll TOTP + verify an aal2 session) '
             || 'BEFORE applying this migration, or the aal2 re-gate below locks the sole admin '
             || 'out of approve_clawback / gdpr_delete_publisher. See the deploy-ordering note above.';
  END IF;
END $$;
-- ===========================================================================================

-- ---------------------------------------------------------------------------
-- A. public.approve_clawback — gate re-hardened to app.is_money_admin() + audit write.
--    Body BYTE-IDENTICAL to 20260629070000_clawback_review.sql:173-253 except:
--      (1) the first-line gate predicate app.is_admin() → app.is_money_admin();
--      (2) one app.log_admin_action() append-only audit write immediately after the gate.
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
  -- M8 hardening: app.is_admin() → app.is_money_admin() (aal2 + money tier).
  IF NOT (SELECT app.is_money_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  -- M8 tamper-evident audit: record the authorized money action (actor/aal from the JWT)
  -- before the work, so every gate-passing call is enumerable even if it later no-ops.
  PERFORM app.log_admin_action('approve_clawback', 'clawback_review', p_review_id,
                               jsonb_build_object('reason', p_reason));

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
  'Money-admin-only (aal2 + app.money_admins): approve a pending clawback review. M8 hardening re-gated it from app.is_admin() to app.is_money_admin() and added an append-only app.log_admin_action() write; the reversal body is otherwise unchanged. Calls clawback() then records the admin decision. Sentinel (gross=0) is a no-op. Exposed via PostgREST RPC.';

-- ---------------------------------------------------------------------------
-- B. public.gdpr_delete_publisher — gate re-hardened to app.is_money_admin() + audit write.
--    Body BYTE-IDENTICAL to 20260705120000_gdpr_self_delete.sql:109-121 except:
--      (1) the first-line gate predicate app.is_admin() → app.is_money_admin();
--      (2) one app.log_admin_action() audit write before delegating to the shared erase body.
--    The erasure semantics (lock, idempotent already_deleted, payout-in-flight refusal,
--    anonymize-in-place, ledger PRESERVED) live in app.gdpr_erase_publisher and are untouched.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.gdpr_delete_publisher(p_publisher_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  -- M8 hardening: app.is_admin() → app.is_money_admin() (aal2 + money tier).
  IF NOT (SELECT app.is_money_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;
  -- M8 tamper-evident audit: record the authorized destructive action (actor/aal from the JWT).
  PERFORM app.log_admin_action('gdpr_delete_publisher', 'publisher', p_publisher_id, '{}'::jsonb);
  RETURN app.gdpr_erase_publisher(p_publisher_id);
END;
$$;
REVOKE ALL ON FUNCTION public.gdpr_delete_publisher(uuid) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.gdpr_delete_publisher(uuid) TO authenticated;

COMMENT ON FUNCTION public.gdpr_delete_publisher IS
  'Money-admin-only (aal2 + app.money_admins) GDPR erasure (support path). M8 hardening re-gated it from app.is_admin() to app.is_money_admin() and added an append-only app.log_admin_action() write; it then delegates to app.gdpr_erase_publisher. Idempotent; refuses while a payout is in flight; ledger preserved.';
