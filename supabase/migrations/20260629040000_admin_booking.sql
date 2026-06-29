-- lumaline M2-T3 — admin-booking edge function helper.
--
-- RLS policies for advertisers, campaigns, line_items, creatives are already defined
-- in 20260627022223_advertisers_campaigns.sql (*_admin_all policies for authenticated
-- and *_service policies for service_role). This migration adds ONLY the public-schema
-- wrapper needed by the admin-booking edge function's auth gate.
--
-- DESIGN: app.is_admin() reads from request.jwt.claims (set by PostgREST from the JWT).
-- It is not callable from an edge function's Deno context (no claims GUC there). The
-- edge function instead calls public.admin_check() via forwardRpc — PostgREST verifies
-- the caller's JWT and installs claims as GUCs, then admin_check() delegates to
-- app.is_admin() which reads app.admins. No SUPABASE_JWT_SECRET dependency in the edge
-- function runtime. This matches the "forward, don't re-verify" pattern in _shared/jwt.ts.

-- public.admin_check(): no-arg, SECURITY DEFINER wrapper callable by authenticated via
-- PostgREST RPC. Returns true if the current JWT sub is in app.admins.
CREATE OR REPLACE FUNCTION public.admin_check()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT app.is_admin();
$$;

-- Least-privilege: the Supabase default-privilege auto-grant gives anon EXECUTE on all
-- new public functions at creation time. Revoke it here (same pattern as
-- 20260627040000_harden_function_grants.sql, which only covers functions that existed
-- before this migration). Only authenticated callers should be able to query admin status.
REVOKE EXECUTE ON FUNCTION public.admin_check() FROM public, anon;
GRANT EXECUTE ON FUNCTION public.admin_check() TO authenticated;
