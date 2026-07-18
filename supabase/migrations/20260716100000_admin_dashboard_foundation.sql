-- lumaline M8-T1 — owner (admin) dashboard authz foundation.
--
-- The substrate the whole owner dashboard shares. Nothing here mutates money; it is the
-- authz + audit floor that lets the money/destructive gates be strengthened (next
-- migration, 20260716120000) and the Phase-2 action RPC (admin_open_clawback) be safe and
-- attributable. It closes three findings the adversarial review raised across every lens:
--   * MFA/assurance is only "advised" — a passwordless magic-link session is aal1 yet
--     app.is_admin()/admin_check() prove MEMBERSHIP only, never authentication assurance
--     (extensions_and_helpers.sql:37-49, admin_booking.sql:17-25). A stolen aal1 magic-link
--     inbox = full treasury/GDPR power.
--   * app.admins is flat + unscoped — every admin (a future triage operator, a stolen
--     session) has identical blast radius: read-all + clawback + GDPR-erase.
--   * no tamper-evident record — the only "audit" today is mutable business-row columns
--     (clawback_reviews.reviewed_by, disputes.resolved_by) that the last writer overwrites.
--
-- WHAT THIS ADDS (four authz primitives + one immutable audit table):
--   1. app.money_admins            — a SECOND, coarse tier (NOT the full capability matrix),
--                                     off the Data API, seeded out-of-band only.
--   2. app.is_money_admin()        — member(money_admins) AND jwt aal='aal2'. The aal2 read
--                                     comes from app.jwt_claim (window_rpcs.sql:31-38), so a
--                                     magic-link (aal1) session fails it — MFA is enforced at
--                                     the DB, not merely enrolled.
--   3. public.money_admin_check()  — Data-API wrapper so the AdminGate can enable/disable the
--                                     money-action UI (mirrors admin_check, admin_booking.sql:17-32).
--   4. app.payout_hold_interval()  — single source of truth for the 7-day payout hold, so the
--                                     Phase-2 clawback guard and payout_batch_reserve's default
--                                     (payout_rails.sql:124) can never diverge.
--   5. app.admin_action_log        — append-only, immutable admin action log (INSERT only via a
--                                     SECDEF writer; a BEFORE UPDATE/DELETE trigger blocks
--                                     mutation even for the owner) + app.log_admin_action().
--
-- CONVENTIONS (per extensions_and_helpers.sql + the M3 secdef_grant_hardening.sql lesson):
--   * SECURITY DEFINER helpers live in `app` (off the Data API) with SET search_path=''
--     (everything fully qualified) and EXECUTE revoked from roles that must not call them.
--   * Supabase default privileges auto-grant anon+authenticated EXECUTE on every NEW public
--     object; each new SECDEF function therefore ships an explicit REVOKE ... FROM PUBLIC, anon
--     in THIS migration (the exact footgun 20260629120000_secdef_grant_hardening.sql fixed
--     after it reached prod). RLS predicates wrap stable calls as (SELECT fn()) for the
--     per-statement initplan cache.
--
-- DEPLOY ORDERING (owner-gated, load-bearing): before any gate that reduces to
-- is_money_admin() ships (the next migration), MFA (config.toml auth.mfa.totp
-- enroll_enabled) must be enabled, the owner must be seeded into BOTH app.admins and
-- app.money_admins out-of-band, and an aal2 session must be verified to return true from
-- is_money_admin() — otherwise the hardened gate self-locks-out the only admin. This
-- migration itself is inert until that seeding happens (money_admins is empty), so it is
-- safe to deploy first.

-- ---------------------------------------------------------------------------
-- 1. app.money_admins — the coarse money tier.
--
-- A second allow-list, distinct from app.admins (extensions_and_helpers.sql:29-32), so a
-- read/triage admin is NOT automatically a treasury admin. Lives in `app` (off the Data
-- API); seeded out-of-band by service_role/SQL ONLY — never from a client, and no dashboard
-- read/write path touches it. No RLS (mirrors app.admins): schema privileges + REVOKE lock it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app.money_admins (
  auth_user_id uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  created_at   timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON app.money_admins FROM PUBLIC, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. app.is_money_admin() — aal2-aware money-admin predicate.
--
-- member(money_admins) AND the verified JWT's aal claim is 'aal2'. app.jwt_claim reads
-- request.jwt.claims (window_rpcs.sql:31-38), which carries Supabase's aal claim; a
-- passwordless magic-link session is aal1 → this returns false, so MFA is enforced at the
-- DB. auth.uid() wrapped in (SELECT ...) for the initplan cache. This is the gate every
-- money-mutating / destructive admin action reduces to (admin_open_clawback, and the
-- re-gated approve_clawback / gdpr_delete_publisher / POST /billing/refund).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.is_money_admin()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM app.money_admins m
    WHERE m.auth_user_id = (SELECT auth.uid())
  )
  AND COALESCE(app.jwt_claim('aal'), 'aal1') = 'aal2';
$$;

REVOKE EXECUTE ON FUNCTION app.is_money_admin() FROM public;
GRANT  EXECUTE ON FUNCTION app.is_money_admin() TO authenticated, service_role;

COMMENT ON FUNCTION app.is_money_admin IS
  'aal2-aware money-admin gate: auth.uid() in app.money_admins AND jwt aal=''aal2''. A magic-link (aal1) session fails it, so MFA is enforced at the DB. Gates every money-mutating/destructive admin action; is_admin() (aal1) still suffices for reads/reject/resolve.';

-- ---------------------------------------------------------------------------
-- 3. public.money_admin_check() — Data-API render probe.
--
-- The AdminGate cannot reach app.is_money_admin() over PostgREST (the `app` schema is off
-- the Data API — config.toml:13), so this public wrapper lets the browser enable/disable the
-- money-action UI. Cosmetic ONLY — the DB re-checks in-body on every action RPC. Mirrors
-- public.admin_check() (admin_booking.sql:17-32) exactly, including the anon REVOKE.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.money_admin_check()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT app.is_money_admin();
$$;

REVOKE ALL ON FUNCTION public.money_admin_check() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.money_admin_check() TO authenticated;

COMMENT ON FUNCTION public.money_admin_check IS
  'Data-API wrapper over app.is_money_admin() so the AdminGate can enable/disable money-action UI. Cosmetic only; every money action re-checks is_money_admin() in-body. Mirrors admin_check(); anon EXECUTE revoked.';

-- ---------------------------------------------------------------------------
-- 4. app.payout_hold_interval() — single source of truth for the payout hold.
--
-- Couples the Phase-2 clawback guard's post-condition
-- (app.publisher_payable_micros(pub, app.payout_hold_interval()) >= 0) to
-- payout_batch_reserve's default p_hold (payout_rails.sql:124), so the two can NEVER use a
-- divergent hold — the money-safety coupling the review flagged as a must-fix. IMMUTABLE so
-- both call sites fold the same literal. Kept in `app` (off the Data API); granted to the
-- roles that run the payout batch (service_role) and the guard (authenticated definer path).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.payout_hold_interval()
RETURNS interval
LANGUAGE sql
IMMUTABLE
SET search_path = ''
AS $$
  SELECT interval '7 days';
$$;

REVOKE EXECUTE ON FUNCTION app.payout_hold_interval() FROM public;
GRANT  EXECUTE ON FUNCTION app.payout_hold_interval() TO authenticated, service_role;

COMMENT ON FUNCTION app.payout_hold_interval IS
  'Single source of truth for the 7-day payout hold. Used by payout_batch_reserve''s default p_hold AND admin_open_clawback''s negative-payable post-condition so they can never diverge.';

-- ---------------------------------------------------------------------------
-- 5. app.admin_action_log — append-only, immutable admin audit trail.
--
-- One row per money-mutating / destructive admin RPC call (actor, actor_aal, action,
-- target, payload). Tamper evidence, not a full hash-chain: NO client role gets
-- INSERT/UPDATE/DELETE — writes flow ONLY through the SECDEF app.log_admin_action (below,
-- runs as owner so it bypasses the missing INSERT grant), and a BEFORE UPDATE/DELETE trigger
-- makes existing rows immutable even to the owner. Admin SELECT is RLS-gated to app.is_admin()
-- (aal1 read is fine); service_role gets SELECT so a future monitor check can read it. Lives
-- in `app` (off the Data API) — the SELECT grant + RLS are defense-in-depth for definer reads.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app.admin_action_log (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  at          timestamptz NOT NULL DEFAULT now(),
  actor       uuid,          -- auth_user_id (jwt sub) of the acting admin
  actor_aal   text,          -- the session's assurance level at action time (expect 'aal2')
  action      text NOT NULL, -- e.g. 'approve_clawback', 'gdpr_delete_publisher', 'admin_open_clawback'
  target_type text,          -- 'clawback_review' | 'publisher' | 'window' | 'impression' | ...
  target_id   uuid,
  payload     jsonb
);

ALTER TABLE app.admin_action_log ENABLE ROW LEVEL SECURITY;

-- Admins may read the trail; no INSERT/UPDATE/DELETE policy (writes are SECDEF-only).
CREATE POLICY admin_action_log_admin_read ON app.admin_action_log
  FOR SELECT TO authenticated
  USING ((SELECT app.is_admin()));

REVOKE ALL   ON app.admin_action_log FROM PUBLIC, anon;
GRANT  SELECT ON app.admin_action_log TO authenticated;   -- admin-gated by RLS; NO write grant
GRANT  SELECT ON app.admin_action_log TO service_role;    -- monitor read only

-- Immutability guard: block any UPDATE/DELETE, even from the table owner / a SECDEF caller.
CREATE OR REPLACE FUNCTION app.admin_action_log_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'admin_action_log is append-only';
END;
$$;

DROP TRIGGER IF EXISTS admin_action_log_no_mutate ON app.admin_action_log;
CREATE TRIGGER admin_action_log_no_mutate
  BEFORE UPDATE OR DELETE ON app.admin_action_log
  FOR EACH ROW EXECUTE FUNCTION app.admin_action_log_immutable();

-- Row-level UPDATE/DELETE is not the only way to erase a trail: a TRUNCATE would wipe every
-- row at once and does NOT fire a row-level trigger. Add a STATEMENT-level BEFORE TRUNCATE
-- guard so the "immutable even to the owner / append-only" claim holds at the statement level
-- too (defense-in-depth: no client role has TRUNCATE, but the owner does). The same RAISE-only
-- trigger function serves both (it never references NEW/OLD).
DROP TRIGGER IF EXISTS admin_action_log_no_truncate ON app.admin_action_log;
CREATE TRIGGER admin_action_log_no_truncate
  BEFORE TRUNCATE ON app.admin_action_log
  FOR EACH STATEMENT EXECUTE FUNCTION app.admin_action_log_immutable();

-- The writer the audited RPCs call. SECURITY DEFINER (owner) so it can INSERT despite no
-- INSERT grant to any client role; EXECUTE revoked from every client role so ONLY other
-- SECDEF functions (running as owner) can reach it. Attributes to the verified JWT
-- (app.jwt_claim('sub'/'aal'), window_rpcs.sql:31-38).
CREATE OR REPLACE FUNCTION app.log_admin_action(
  p_action      text,
  p_target_type text,
  p_target_id   uuid,
  p_payload     jsonb
)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  INSERT INTO app.admin_action_log (actor, actor_aal, action, target_type, target_id, payload)
  VALUES (
    nullif(app.jwt_claim('sub'), '')::uuid,
    app.jwt_claim('aal'),
    p_action,
    p_target_type,
    p_target_id,
    p_payload
  );
$$;

REVOKE ALL ON FUNCTION app.log_admin_action(text, text, uuid, jsonb) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.log_admin_action IS
  'SECDEF append-only writer for app.admin_action_log. Called from inside the audited admin RPCs; EXECUTE revoked from every client role so only other SECDEF functions reach it. Attributes to jwt sub + aal.';
