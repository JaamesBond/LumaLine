-- lumaline M9-T1 — advertiser identity + the DB-as-boundary lockdown for self-serve.
--
-- The fourth surface (an authenticated advertiser portal, Scheme-A magic-link → auth.uid()
-- RLS) needs an identity that maps a web session to an advertiser org, AND it needs the four
-- booking tables (advertisers/campaigns/line_items/creatives) to stop being writable by any
-- authenticated browser session. Today those tables carry a broad
--   GRANT SELECT, INSERT, UPDATE, DELETE ... TO authenticated
-- (advertisers_campaigns.sql:121-124), bounded ONLY by the admin-only *_admin_all RLS
-- predicate. That is exactly the wrong shape for self-serve: the moment an advertiser session
-- is authenticated, a crafted PostgREST write would match the table grant and rely on RLS
-- alone. This migration makes the DATABASE, not edge code, the isolation boundary:
--
--   1. NEW public.advertiser_users(auth_user_id → advertiser_id), MANY-to-one, so a session
--      resolves to an org. app.current_advertiser_id() clones app.current_publisher_id()
--      (publishers_devices.sql:25-37): SECURITY DEFINER + STABLE + search_path='' so RLS
--      predicates resolve it once per statement and it bypasses advertiser_users' own RLS.
--   2. public.advertiser_check() / advertiser_self_id() — Data-API wrappers (the `app` schema
--      is off the Data API, config.toml:13, so app.current_advertiser_id() 404s over
--      PostgREST). advertiser_check gates the AdvertiserGate render; advertiser_self_id lets the
--      funding edge fn resolve the caller's org server-side (never a client-passed id).
--   3. ensure_advertiser_user() — STRICTLY self-creating provisioning: NO advertiser_id
--      argument (always mints a fresh org), and it REFUSES a caller who is already a publisher
--      (the bidirectional self-deal guard; ensure_publisher gets the mirror refusal). Joining an
--      EXISTING org is FROZEN to a server-minted single-use invite token only (deferred team
--      flow) — a client-passed advertiser_id must NEVER be able to map auth.uid() into a
--      foreign org, so this function takes no id at all.
--   4. LOCKDOWN: REVOKE INSERT/UPDATE/DELETE on the four tables FROM authenticated (writes flow
--      ONLY through the self-scoped SECDEF RPCs added in 20260716190000); additive per-advertiser
--      SELECT policies (alongside, never replacing, *_admin_all + *_service); the advertisers
--      read is COLUMN-SCOPED (stripe_customer_id/is_house never reach the client); and a
--      column-diff BEFORE UPDATE trigger keeps is_house/status/stripe_customer_id/billing_mode
--      structurally unwritable except by service_role.
--
-- CONVENTIONS (per extensions_and_helpers.sql + the secdef_grant_hardening.sql lesson):
--   * SECURITY DEFINER helpers in `app` (off the Data API) with SET search_path='' (everything
--     fully qualified) and EXECUTE revoked from roles that must not call them.
--   * Supabase default privileges auto-grant anon+authenticated EXECUTE on every NEW public
--     object; revoking ONLY anon leaves the auto-granted PUBLIC EXECUTE (which anon inherits)
--     callable — the exact footgun 20260629120000_secdef_grant_hardening.sql fixed AFTER it
--     reached prod. So every new public SECDEF fn ships `REVOKE ALL ... FROM PUBLIC, anon`
--     (not just anon), and the migration ends with a DO-block that RAISEs if anon still holds
--     EXECUTE on any function added here.
--   * RLS predicates wrap stable calls as (SELECT fn()) for the per-statement initplan cache.

-- ---------------------------------------------------------------------------
-- 0. billing_mode on advertisers.
--
-- 'postpay' (default) keeps the legacy admin-booked Stripe-PaymentIntent path unchanged for
-- every existing advertiser (incl. the €1.10 first-charge advertiser + the house/sentinel
-- rows). 'prepay' = self-serve: ensure_advertiser_user mints new orgs as 'prepay', and the
-- prepay balance/reserve machinery (later migrations) keys off this flag. Never UPDATEd by any
-- advertiser path — the column-diff trigger below makes it structurally unwritable by them.
-- ---------------------------------------------------------------------------
ALTER TABLE public.advertisers
  ADD COLUMN IF NOT EXISTS billing_mode text NOT NULL DEFAULT 'postpay'
    CHECK (billing_mode IN ('postpay', 'prepay'));

-- ---------------------------------------------------------------------------
-- 1. public.advertiser_users — the session→org identity (MANY-to-one).
--
-- Mirrors publishers' shape but many-to-one (a future team can have several members mapping to
-- one advertiser; single-user-per-org today). Writes flow ONLY through the SECDEF
-- ensure_advertiser_user (below) / service_role — no authenticated INSERT/UPDATE/DELETE grant.
-- RLS: a session reads its OWN mapping (or an admin reads all); anon sees nothing.
-- ---------------------------------------------------------------------------
CREATE TABLE public.advertiser_users (
  auth_user_id  uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  advertiser_id uuid NOT NULL REFERENCES public.advertisers (id),
  role          text NOT NULL DEFAULT 'owner',
  created_at    timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.advertiser_users IS
  'Maps a Supabase Auth web session (auth.uid()) to an advertiser org. MANY-to-one. Populated only by the SECDEF ensure_advertiser_user() (self-creating, no client advertiser_id) or service_role. Joining an existing org is frozen to a server-minted single-use invite token (deferred team flow).';

CREATE INDEX advertiser_users_advertiser_id_idx ON public.advertiser_users (advertiser_id);

ALTER TABLE public.advertiser_users ENABLE ROW LEVEL SECURITY;

-- Read: own mapping, or any row for admins. No authenticated write policy (SECDEF/service only).
CREATE POLICY advertiser_users_select_own ON public.advertiser_users
  FOR SELECT TO authenticated
  USING (auth_user_id = (SELECT auth.uid()) OR (SELECT app.is_admin()));

CREATE POLICY advertiser_users_service ON public.advertiser_users
  FOR ALL TO service_role
  USING (true) WITH CHECK (true);

-- Data API is always-revoked by default: grant explicitly. Authenticated may READ (RLS limits
-- rows) but never write; service_role manages (provisioning / future team flow). The explicit
-- table-level REVOKE ALL FROM PUBLIC, anon mirrors the hardening the 20260716200000 tables ship
-- (belt-and-suspenders against a Supabase default-privilege anon grant; RLS already denies anon).
REVOKE ALL ON public.advertiser_users FROM PUBLIC, anon;
GRANT SELECT ON public.advertiser_users TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.advertiser_users TO service_role;

-- ---------------------------------------------------------------------------
-- 2. app.current_advertiser_id() — auth.uid() → advertiser id.
--
-- Clone of app.current_publisher_id() (publishers_devices.sql:25-37): SECURITY DEFINER + STABLE
-- so RLS policies resolve it once per statement AND it bypasses advertiser_users' own RLS (no
-- recursion). Lives in `app` (off the Data API). Used as (SELECT app.current_advertiser_id())
-- throughout the advertiser RLS + self-scoped RPCs.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.current_advertiser_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT advertiser_id
  FROM public.advertiser_users
  WHERE auth_user_id = (SELECT auth.uid());
$$;
REVOKE ALL ON FUNCTION app.current_advertiser_id() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION app.current_advertiser_id() TO authenticated, service_role;

COMMENT ON FUNCTION app.current_advertiser_id IS
  'auth.uid() → advertiser_id via public.advertiser_users. SECURITY DEFINER + STABLE + search_path='''' so RLS resolves it once per statement and it bypasses advertiser_users'' RLS (no recursion). Clone of app.current_publisher_id(). Off the Data API; reachable in-DB only.';

-- ---------------------------------------------------------------------------
-- 3. public.advertiser_check() — Data-API render probe.
--
-- The AdvertiserGate cannot reach app.current_advertiser_id() over PostgREST (`app` is off the
-- Data API), so this public wrapper lets the browser decide whether to paint the shell.
-- Cosmetic ONLY — every self-scoped RPC re-derives current_advertiser_id() in-body. Mirrors
-- public.admin_check() (admin_booking.sql:17-32) incl. the anon REVOKE. MUST be in `public`.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.advertiser_check()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT app.current_advertiser_id() IS NOT NULL;
$$;
REVOKE ALL ON FUNCTION public.advertiser_check() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_check() TO authenticated;

COMMENT ON FUNCTION public.advertiser_check IS
  'Data-API wrapper: true when the caller''s auth.uid() maps to an advertiser org. Cosmetic gate for the AdvertiserGate render; every action RPC re-checks current_advertiser_id() in-body. Mirrors admin_check(); anon EXECUTE revoked.';

-- ---------------------------------------------------------------------------
-- 4. public.advertiser_self_id() — server-side id resolution for the funding edge fn.
--
-- The advertiser-portal funding/checkout endpoint MUST resolve WHICH org a deposit funds from
-- the caller's own JWT, never from a client-passed advertiser_id (a foreign body id would
-- otherwise fund an attacker's org). This wrapper returns the caller's own advertiser_id (NULL
-- if the session maps to no org). Off the Data API for app.current_advertiser_id(), so expose a
-- public wrapper the edge fn can call via forwardRpc with the caller's bearer.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.advertiser_self_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT app.current_advertiser_id();
$$;
REVOKE ALL ON FUNCTION public.advertiser_self_id() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_self_id() TO authenticated, service_role;

COMMENT ON FUNCTION public.advertiser_self_id IS
  'Returns the caller''s own advertiser_id (auth.uid()→org) or NULL. Used by the advertiser-portal funding/checkout edge fn to resolve the depositing org server-side; a client-passed advertiser_id is ignored. Anon EXECUTE revoked.';

-- ---------------------------------------------------------------------------
-- 5. ensure_advertiser_user() — strictly self-creating provisioning.
--
-- First-login provisioning of an advertiser identity. Takes NO argument: it always mints a
-- FRESH org for the caller, so it is structurally impossible to map auth.uid() into a foreign
-- org (the deferred team/invite flow is frozen to a server-minted single-use invite token,
-- never a client-passed advertiser_id). Refuses a caller who is already a publisher — the
-- bidirectional self-deal guard (ensure_publisher gets the mirror refusal). Idempotent: if a
-- mapping already exists it returns it. New orgs are billing_mode='prepay', is_house forced
-- false, name a placeholder the advertiser edits later (through a moderated profile RPC).
--
-- advertiser_balances (created in 20260716170000) is a FORWARD reference; the codebase idiom
-- for referencing a table that may not exist at CREATE time is dynamic EXECUTE guarded by
-- to_regclass (money_monitoring.sql:230-238) — it also keeps this migration runnable ahead of
-- 170000 and self-contained (the 0/0 seed is backfilled idempotently by the deposit path).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.ensure_advertiser_user()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid uuid;
  v_adv uuid;
BEGIN
  v_uid := (SELECT auth.uid());
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  -- Bidirectional self-deal guard: a publisher identity may NOT also become an advertiser.
  IF (SELECT app.current_publisher_id()) IS NOT NULL THEN
    RAISE EXCEPTION 'identity is already a publisher' USING errcode = '28000';
  END IF;

  -- Idempotent: return the existing mapping if one exists.
  SELECT advertiser_id INTO v_adv
    FROM public.advertiser_users
   WHERE auth_user_id = v_uid;
  IF FOUND THEN
    RETURN jsonb_build_object('advertiser_id', v_adv, 'created', false);
  END IF;

  -- Create a fresh org. Wrapped in a subtransaction so a concurrent double-call that loses the
  -- advertiser_users PK race rolls back its orphan advertisers row and returns the winner's org.
  BEGIN
    INSERT INTO public.advertisers (name, is_house, billing_mode, status)
      VALUES ('New advertiser', false, 'prepay', 'active')
      RETURNING id INTO v_adv;

    INSERT INTO public.advertiser_users (auth_user_id, advertiser_id, role)
      VALUES (v_uid, v_adv, 'owner');

    -- Seed a zero balance row (forward reference to 20260716170000 — dynamic + guarded).
    IF to_regclass('public.advertiser_balances') IS NOT NULL THEN
      EXECUTE 'INSERT INTO public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
               VALUES ($1, 0, 0) ON CONFLICT (advertiser_id) DO NOTHING'
        USING v_adv;
    END IF;

    RETURN jsonb_build_object('advertiser_id', v_adv, 'created', true);
  EXCEPTION WHEN unique_violation THEN
    SELECT advertiser_id INTO v_adv
      FROM public.advertiser_users
     WHERE auth_user_id = v_uid;
    RETURN jsonb_build_object('advertiser_id', v_adv, 'created', false);
  END;
END;
$$;
REVOKE ALL ON FUNCTION public.ensure_advertiser_user() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.ensure_advertiser_user() TO authenticated;

COMMENT ON FUNCTION public.ensure_advertiser_user IS
  'Strictly self-creating advertiser provisioning: NO argument (always mints a fresh org for auth.uid()), refuses a caller already mapped to a publisher, idempotent if a mapping exists. New orgs are billing_mode=''prepay'', is_house=false. Cannot map a session into a foreign org — the deferred team flow is frozen to a server-minted invite token. Granted to authenticated; anon revoked.';

-- ---------------------------------------------------------------------------
-- 5b. ensure_publisher() — the MIRROR of ensure_advertiser_user's self-deal refusal.
--
-- ensure_advertiser_user (above) refuses a caller already mapped to a publisher. The bidirectional
-- self-deal guard is only complete when the publisher provisioning path (public.ensure_publisher,
-- 20260629010000; called by the /activate edge page with the caller's own JWT, auth-device
-- /index.ts:392) SYMMETRICALLY refuses a caller already mapped to an advertiser_user — otherwise the
-- same auth.uid() could be BOTH an advertiser and a publisher (a self-deal identity the window_open
-- shared-auth_user_id exclusion still blocks at serve time, but which should never be provisioned).
-- CREATE OR REPLACE re-defines the function verbatim + the one added guard (app.current_advertiser_id,
-- defined in section 2 above, resolves the caller's org from the request JWT). The ACL is unchanged by
-- CREATE OR REPLACE; we re-emit it for clarity + the migration-tail assertion below.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.ensure_publisher(p_handle text DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_uid     uuid := (SELECT auth.uid());
  v_pid     uuid;
  v_handle  text;
  v_slug    text;
  v_created boolean := false;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  -- Bidirectional self-deal guard: an advertiser identity may NOT also become a publisher
  -- (the mirror of ensure_advertiser_user's publisher refusal).
  IF (SELECT app.current_advertiser_id()) IS NOT NULL THEN
    RAISE EXCEPTION 'identity is already an advertiser' USING errcode = '28000';
  END IF;

  SELECT id, handle INTO v_pid, v_handle FROM public.publishers WHERE auth_user_id = v_uid;
  IF v_pid IS NOT NULL THEN
    RETURN jsonb_build_object('publisher_id', v_pid, 'handle', v_handle, 'created', false);
  END IF;

  -- New publisher. The uid-derived slug is unique by construction; an explicit handle is tried
  -- first but must NEVER error the login — a handle collision (a SEPARATE unique constraint that
  -- `on conflict (auth_user_id)` does not cover) falls back to the slug.
  v_slug   := 'pub_' || substr(replace(v_uid::text, '-', ''), 1, 12);
  v_handle := COALESCE(NULLIF(trim(p_handle), ''), v_slug);
  BEGIN
    INSERT INTO public.publishers (auth_user_id, handle)
      VALUES (v_uid, v_handle)
      ON CONFLICT (auth_user_id) DO NOTHING
      RETURNING id INTO v_pid;
  EXCEPTION WHEN unique_violation THEN     -- requested handle taken by another user
    INSERT INTO public.publishers (auth_user_id, handle)
      VALUES (v_uid, v_slug)
      ON CONFLICT (auth_user_id) DO NOTHING
      RETURNING id INTO v_pid;
  END;

  IF v_pid IS NULL THEN   -- lost an auth_user_id race: the row now exists, read it back
    SELECT id, handle INTO v_pid, v_handle FROM public.publishers WHERE auth_user_id = v_uid;
  ELSE
    v_created := true;
    SELECT handle INTO v_handle FROM public.publishers WHERE id = v_pid;  -- reflect stored handle
  END IF;

  RETURN jsonb_build_object('publisher_id', v_pid, 'handle', v_handle, 'created', v_created);
END;
$$;
REVOKE ALL ON FUNCTION public.ensure_publisher(text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.ensure_publisher(text) TO authenticated, service_role;

COMMENT ON FUNCTION public.ensure_publisher IS
  'Publisher provisioning (M2 device-flow) hardened with the bidirectional self-deal guard: refuses a caller already mapped to an advertiser_user (mirror of ensure_advertiser_user''s publisher refusal), so one auth.uid() can never be both an advertiser and a publisher. Otherwise verbatim (idempotent, uid-slug handle). SECDEF; authenticated + service_role; anon revoked.';

-- ---------------------------------------------------------------------------
-- 6. Additive per-advertiser SELECT policies.
--
-- These sit ALONGSIDE the existing *_admin_all + *_service policies (advertisers_campaigns.sql
-- :97-124) — never replacing them, none USING(true). Multiple permissive SELECT policies are
-- ORed, so an advertiser reads its OWN rows via these while an admin still reads all via
-- *_admin_all. Terminating predicates are EXACT (an EXISTS through the FK chain to
-- current_advertiser_id()), not recursive self-joins.
-- ---------------------------------------------------------------------------
CREATE POLICY advertisers_select_own ON public.advertisers
  FOR SELECT TO authenticated
  USING (id = (SELECT app.current_advertiser_id()));

CREATE POLICY campaigns_select_own ON public.campaigns
  FOR SELECT TO authenticated
  USING (advertiser_id = (SELECT app.current_advertiser_id()));

CREATE POLICY line_items_select_own ON public.line_items
  FOR SELECT TO authenticated
  USING (EXISTS (
    SELECT 1 FROM public.campaigns c
    WHERE c.id = line_items.campaign_id
      AND c.advertiser_id = (SELECT app.current_advertiser_id())
  ));

CREATE POLICY creatives_select_own ON public.creatives
  FOR SELECT TO authenticated
  USING (EXISTS (
    SELECT 1
    FROM public.line_items li
    JOIN public.campaigns  c ON c.id = li.campaign_id
    WHERE li.id = creatives.line_item_id
      AND c.advertiser_id = (SELECT app.current_advertiser_id())
  ));

-- NOTE: advertisers get NO SELECT policy on ledger_entries — per-publisher / per-leg spend is
-- NEVER exposed; spend is aggregate-only via advertiser_spend_summary() (20260716190000).

-- ---------------------------------------------------------------------------
-- 7. The DB-as-boundary lockdown.
--
-- Remove the broad authenticated write grant on the four booking tables (advertisers_campaigns
-- .sql:121-124) so a crafted PostgREST write from an advertiser session matches NO grant. All
-- advertiser mutations flow ONLY through the self-scoped SECDEF RPCs (20260716190000), each of
-- which asserts ownership in-body. service_role keeps full DML (admin-booking's service-role
-- write path, admin_booking.sql — never reused for advertiser writes). Verified: the M8 owner
-- portal has no authenticated-client browser DML to these tables (admin writes are service_role).
-- ---------------------------------------------------------------------------
REVOKE INSERT, UPDATE, DELETE ON public.advertisers FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.campaigns   FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.line_items  FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.creatives   FROM authenticated;

-- Column-scope the advertisers read: stripe_customer_id / is_house must never reach the client.
-- Revoke the whole-table SELECT then grant only the safe columns. (uncharged_advertiser_billings
-- — the only authenticated-visible object that reads those columns — is service_role-only +
-- security_invoker, cpc_billing.sql:50-52, so it is unaffected; v_campaign_delivery reads only
-- campaigns/line_items.) campaigns/line_items/creatives keep their full SELECT grant.
REVOKE SELECT ON public.advertisers FROM authenticated;
GRANT  SELECT (id, name, status, billing_mode, created_at) ON public.advertisers TO authenticated;

-- ---------------------------------------------------------------------------
-- 8. Column-diff protected-column trigger on advertisers.
--
-- is_house / status / stripe_customer_id / billing_mode are trust-sensitive. Section 7 already
-- makes them unwritable by authenticated (no UPDATE grant), and no advertiser RPC exposes them;
-- this BEFORE UPDATE trigger is the structural backstop for ANY future/service path. It is
-- COLUMN-DIFF based (blocks the change only when the value actually differs), NOT caller-based,
-- so the name-only profile RPC (20260716190000) never trips it. The only role allowed to change
-- a protected column is service_role (the billing edge fn persisting stripe_customer_id,
-- billing/index.ts:182-186; the chargeback pause; admin-booking), identified by the request's
-- own JWT role claim — so a definer function running for an authenticated caller cannot smuggle
-- a protected-column change.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertisers_protect_cols()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- service_role (edge fns / admin-booking) may set protected columns.
  IF COALESCE(app.jwt_claim('role'), '') = 'service_role' THEN
    RETURN NEW;
  END IF;

  IF NEW.is_house           IS DISTINCT FROM OLD.is_house
     OR NEW.status          IS DISTINCT FROM OLD.status
     OR NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id
     OR NEW.billing_mode    IS DISTINCT FROM OLD.billing_mode THEN
    RAISE EXCEPTION 'advertisers: protected column change requires service_role'
      USING errcode = '42501';
  END IF;

  RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION app.advertisers_protect_cols() FROM PUBLIC;

DROP TRIGGER IF EXISTS advertisers_protect_cols ON public.advertisers;
CREATE TRIGGER advertisers_protect_cols
  BEFORE UPDATE ON public.advertisers
  FOR EACH ROW EXECUTE FUNCTION app.advertisers_protect_cols();

COMMENT ON FUNCTION app.advertisers_protect_cols IS
  'BEFORE UPDATE guard: blocks a change to is_house/status/stripe_customer_id/billing_mode unless the request JWT role is service_role. Column-diff based (a name-only update passes), so the advertiser profile RPC never trips it; the structural backstop for the protected columns.';

-- ---------------------------------------------------------------------------
-- 9. Migration-tail assertion — anon must hold NO EXECUTE on any function added here.
--
-- The secdef_grant_hardening.sql footgun in code: Supabase auto-grants EXECUTE to PUBLIC (anon
-- inherits) on every new function; revoking only anon leaves it callable. Every fn above ships
-- `REVOKE ALL ... FROM PUBLIC, anon`; this DO-block fails the migration loudly if any slipped.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  v_fn  text;
  v_fns text[] := ARRAY[
    'public.advertiser_check()',
    'public.advertiser_self_id()',
    'public.ensure_advertiser_user()',
    'public.ensure_publisher(text)',
    'app.current_advertiser_id()',
    'app.advertisers_protect_cols()'
  ];
BEGIN
  FOREACH v_fn IN ARRAY v_fns LOOP
    IF has_function_privilege('anon', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    END IF;
  END LOOP;
END;
$$;
