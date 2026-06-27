-- Least-privilege hardening of the SECURITY DEFINER RPCs.
--
-- WHY THIS EXISTS: Supabase installs a schema-level DEFAULT PRIVILEGE that auto-grants
-- EXECUTE on every `public` function to `anon` AND `authenticated` at creation time (so
-- PostgREST can expose RPCs). That default silently overrides the explicit per-function
-- grants in the earlier migrations, leaving the money/ops RPCs reachable by anyone holding
-- the public anon key. SECURITY DEFINER functions run as their OWNER (bypassing RLS), so an
-- anon-EXECUTE-able clawback/clear_events is a genuine privilege-escalation surface once the
-- public API takes real traffic.
--
-- This migration is ordered LAST, so on a fresh `db reset` it strips the unintended grants
-- back to least privilege AFTER every function (and its default-priv auto-grant) exists.
-- Re-runnable: REVOKE of an absent grant is a NOTICE, not an error.
--
-- Verified 2026-06-27 against the live project: cron jobs (clear_events / scan_ivt /
-- sweep_stale_windows) run as `postgres`, and `postgres` + `service_role` retain EXECUTE, so
-- the scheduled clearing/ledger path is unaffected; the edge function calls window_* with a
-- role=authenticated sentinel JWT, which is retained.

-- Ops / money RPCs: NEVER reachable from the public API (cron=postgres + service_role only).
revoke execute on function public.clawback(text, uuid, text)             from anon, authenticated, public;
revoke execute on function public.clear_events(interval)                 from anon, authenticated, public;
revoke execute on function public.scan_ivt(interval, integer)            from anon, authenticated, public;
revoke execute on function public.sweep_stale_windows(interval)          from anon, authenticated, public;

-- Hot-path RPCs: keep `authenticated` (edge fn mints a role=authenticated sentinel JWT) +
-- service_role; drop anon + PUBLIC so the public anon key cannot call them directly.
revoke execute on function public.window_open(text)                      from anon, public;
revoke execute on function public.window_beat(uuid, integer, text, text) from anon, public;
revoke execute on function public.close_window(uuid)                     from anon, public;

-- click_resolve: the self-promo MVP serves a DIRECT clickUrl, so the tokenized /c/:token
-- redirect is dormant. Drop anon now (it was granted anon in 20260627025330). When the
-- redirect returns at GA, re-grant the MINIMAL role (prefer service_role from the click
-- edge function) rather than anon.
revoke execute on function public.click_resolve(text)                    from anon, public;
