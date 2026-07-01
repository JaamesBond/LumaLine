-- lumaline M3 deploy — SECURITY DEFINER / anon-grant hardening.
--
-- Surfaced by get_advisors during the M3 remote deploy: M2 (PR #6, merged but never
-- advisor-checked on the remote) shipped three anon-reachable, RLS-bypassing surfaces.
-- Supabase's default privileges auto-grant anon + authenticated on every new public
-- object, so a migration that only "GRANT … TO service_role" (without an explicit
-- REVOKE of anon/authenticated, the pattern 20260627040000_harden_function_grants.sql
-- established) leaves the default grant in place. Fix-forward (never edit applied
-- migrations); local `supabase db reset` and the remote converge on this hardened state.
--
--   ERROR  uncharged_advertiser_billings — a SECURITY DEFINER VIEW with full anon +
--          authenticated grants. The public anon key could GET /rest/v1/uncharged_advertiser_billings
--          and read advertiser billing entries, bypassing RLS. The view is only read by
--          the billing edge fn (service_role). Lock to service_role AND make it run as
--          invoker so base-table RLS always applies even if a grant is reintroduced.
--   WARN   billing_recon_totals(timestamptz,timestamptz) — SECURITY DEFINER, anon-executable
--          via /rest/v1/rpc. service_role-only by design (billing edge fn).
--   WARN   check_house_bids(uuid,bigint,bigint) — SECURITY DEFINER CHECK-constraint helper,
--          anon-executable. line_items writes run as service_role, so anon never needs it.

-- 1. The definer view → service_role-only + security_invoker.
REVOKE ALL ON public.uncharged_advertiser_billings FROM anon, authenticated;
ALTER VIEW public.uncharged_advertiser_billings SET (security_invoker = on);

-- 2. Recon totals → service_role-only (matches the payout/billing RPC hardening pattern).
REVOKE EXECUTE ON FUNCTION public.billing_recon_totals(timestamptz, timestamptz) FROM anon, authenticated;

-- 3. House-bids CHECK helper → drop anon (keep authenticated + service_role so the
--    CHECK constraint on line_items is never starved of EXECUTE on the write path).
REVOKE EXECUTE ON FUNCTION public.check_house_bids(uuid, bigint, bigint) FROM anon;
