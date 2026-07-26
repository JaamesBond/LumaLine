-- 20260728100000_revoke_grant_drift.sql
-- Corrective: make PRODUCTION's table ACLs match what THIS repo's migrations have always granted.
--
-- ---------------------------------------------------------------------------
-- THE DRIFT
-- ---------------------------------------------------------------------------
-- An audit of production (prmsonskzrubqsazmpwd) found `anon` and `authenticated` holding
-- `arwdDxtm` — SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN — on 25
-- tables in schema `public`. The migrations in this repo never granted that. They grant, at most,
-- SELECT to `authenticated`, and NO DML to `anon` anywhere. A stack built purely from these
-- migrations (`supabase db reset`) reproduces the CORRECT, narrow ACLs. The migrations were always
-- right; production acquired the extra privileges from somewhere else.
--
-- ROOT CAUSE (as far as it can be established without touching prod): Supabase ships TWO
-- default-privilege entries for schema `public`, keyed by the role that CREATES the object:
--
--   pg_default_acl: supabase_admin / public / r -> anon=arwdDxtm, authenticated=arwdDxtm
--   pg_default_acl: postgres       / public / r -> anon=Dxtm,     authenticated=Dxtm
--
-- Anything created (or re-granted) under `supabase_admin` — an older project's defaults, a
-- dashboard SQL-editor action, a Management-API apply — silently receives FULL DML for both
-- public roles. Under `postgres` it does not. This is the same class of footgun already recorded in
-- 20260629120000_secdef_grant_hardening.sql, where Supabase's default privileges auto-granted
-- `anon` EXECUTE on every new public function.
--
-- ---------------------------------------------------------------------------
-- WHY IT MATTERS: SELF-SERVICE PAYOUT REDIRECTION
-- ---------------------------------------------------------------------------
-- With a table-level UPDATE grant in place, row-level security is the ONLY thing left containing a
-- publisher — and on `public.publishers` the `publishers_update_own` policy PERMITS UPDATE of your
-- own row (`auth.uid() = auth_user_id`, same predicate in USING and WITH CHECK). There is no
-- protect-columns trigger. RLS restricts WHICH ROWS you may write; only the column grants restrict
-- WHICH COLUMNS. 20260627022222_publishers_devices.sql says so in as many words:
--
--     "Publishers may read the table (RLS limits rows) but may only edit profile fields;
--      trust-sensitive columns (payout_status, status, stripe_account_id) are mutated only by
--      service_role (Stripe webhook / admin fn)."
--
-- The production grant erased that boundary. An authenticated publisher could PATCH any column of
-- their own row through the Data API:
--
--   * payout_status    = 'verified'    -- self-verify, skipping Stripe Connect KYC
--   * stripe_account_id = '<any acct>' -- REDIRECT THEIR OWN PAYOUT to an arbitrary account
--   * status            = 'active'     -- un-suspend themselves
--   * deleted_at / handle              -- undo a GDPR erasure
--
-- `payout_batch_reserve` selects candidates on exactly `payout_status = 'verified'` AND
-- `stripe_account_id is not null` AND `status = 'active'` AND `deleted_at is null`. On production,
-- all four of those were self-settable by the payee. That is real money.
--
-- The same blanket grant let `anon` — the public API key baked into every client — INSERT, UPDATE
-- and DELETE wherever a permissive RLS policy did not explicitly say no.
--
-- ---------------------------------------------------------------------------
-- WHAT THIS MIGRATION DOES
-- ---------------------------------------------------------------------------
-- Revokes DML **and the drifted SELECT** from `anon` and `authenticated` across `public`, then
-- restores — explicitly — only what the migrations DO intend.
--
-- After this runs the security-relevant surface is byte-exact with `main`. Measured by simulating
-- the full production drift (`grant all ... to anon, authenticated`) on a migrations-only stack and
-- then applying this file: `anon` can read 0 relations and write 0; `authenticated` reads the 26
-- `main` grants it and writes exactly 2 (clawback_reviews, disputes). Test D10 pins those numbers.
--
-- One honest caveat: on relations where the drift CREATED an ACL entry that `main` does not have at
-- all, a residual `xtm` — REFERENCES, TRIGGER, MAINTAIN — survives, because this file revokes reads
-- and writes rather than every privilege. Neither is a read nor a write, and `main` itself carries
-- `xtm` on most tables as the same Supabase default-privilege residue. It is noted rather than
-- chased so that this migration stays a surgical fix for the hole that mattered.
--
-- On a clean stack built from these migrations this is very nearly a no-op: the only privilege it
-- removes that `main` previously left in place is TRUNCATE. That removal is deliberate. TRUNCATE
-- BYPASSES RLS ENTIRELY — no policy is consulted — so a TRUNCATE grant to `anon` is not contained
-- by anything. It arrived purely as Supabase default-privilege residue; no code path in this repo
-- truncates anything, and 20260716100000_admin_dashboard_foundation.sql already asserts as design
-- intent that "no client role has TRUNCATE". This makes that sentence true.
--
-- `service_role` is deliberately NOT named below and is therefore untouched: it keeps the full DML
-- it needs for the edge functions. `service_role` is not a member of `anon` or `authenticated`
-- (only `authenticator` is a member of all three), so revoking from those two cannot reach it.
--
-- SCOPE: grants only. No RLS policy, function, trigger or table definition is altered here.
--
-- ---------------------------------------------------------------------------
-- THE COLUMN-LEVEL TRAP (why the re-grant below is mandatory, not belt-and-braces)
-- ---------------------------------------------------------------------------
-- PostgreSQL: "When revoking privileges on a table, the corresponding column privileges (if any)
-- are automatically revoked on each column of the table, as well." A table-level REVOKE UPDATE
-- therefore DESTROYS `grant update (handle, country) on public.publishers to authenticated` —
-- verified empirically on the local stack: `pg_attribute.attacl` for publishers.handle/country goes
-- from `{authenticated=w/postgres}` to NULL, and `has_column_privilege` flips to false. Without the
-- re-grant, the publisher dashboard's profile edit silently breaks.
--
-- The column-scoped SELECT on `public.advertisers` (20260716150000, which deliberately revoked
-- whole-table SELECT there) survives untouched because SELECT is not revoked below.
--
-- ---------------------------------------------------------------------------
-- OWNER FOLLOW-UP (NOT done here)
-- ---------------------------------------------------------------------------
-- This migration corrects the tables that exist TODAY. If production's `pg_default_acl` still
-- carries the `supabase_admin -> anon/authenticated = arwdDxtm` entry AND migrations are applied
-- under a role covered by it, every FUTURE table re-acquires the hole. The durable fix is
--
--     alter default privileges for role supabase_admin in schema public
--       revoke insert, update, delete, truncate on tables from anon, authenticated;
--
-- which is NOT included here because it cannot be executed by `postgres` ("permission denied to
-- change default privileges" — `postgres` is not a member of `supabase_admin`), so shipping it
-- would break `supabase db reset` locally and the deploy on prod. It needs an owner with
-- supabase_admin. Until then, treat this file's REVOKE as a recurring checklist item.

-- ---------------------------------------------------------------------------
-- 1. Strip DML from the two public-facing roles, everywhere in `public`.
--    ON ALL TABLES IN SCHEMA covers views and foreign tables too; no view in `public` carries a
--    DML grant for these roles, so nothing depends on one.
-- ---------------------------------------------------------------------------
revoke insert, update, delete, truncate on all tables in schema public from anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2. Restore the grants the migrations DO intend for `authenticated`.
--    These three are the complete set — derived from the migrations, not from production.
-- ---------------------------------------------------------------------------

-- 20260627022222_publishers_devices.sql:66 — profile-only edit surface. MUST be re-granted: step 1
-- cascaded into the column ACL (see THE COLUMN-LEVEL TRAP above). This is the boundary that keeps
-- payout_status / status / stripe_account_id service_role-only.
grant update (handle, country) on public.publishers to authenticated;

-- 20260629070000_clawback_review.sql:59 — publishers file and amend their own clawback appeals.
grant insert, update on public.clawback_reviews to authenticated;

-- 20260629070000_clawback_review.sql:101 — publishers file disputes; they may not edit them after.
grant insert on public.disputes to authenticated;

-- ---------------------------------------------------------------------------
-- 3. The READ half of the same drift.
--
-- `arwdDxtm` contains `r` — SELECT. Steps 1-2 strip only DML, so without this section the read
-- surface stays wide open and "production matches main" would be false.
--
-- `main` grants `anon` SELECT on NOTHING in `public` (verified: zero relations in a
-- migrations-only stack return true for has_table_privilege('anon', ..., 'SELECT')). Every
-- surviving `anon` read on production is therefore divergence. Two of them are not cosmetic:
--
--   * public.uncharged_advertiser_billings is service_role-only in main AND is a SECURITY DEFINER
--     view — `20260716170000_advertiser_prepay_balance.sql:231` re-creates it with CREATE OR
--     REPLACE VIEW and no WITH clause, which silently resets the `security_invoker = on` set by
--     20260701090000_cpc_billing.sql:51. A surviving SELECT therefore BYPASSES base-table RLS and
--     exposes stripe_customer_id, advertiser_name, is_house and per-publisher billing amounts to
--     the public anon key. That is verbatim the advisor ERROR 20260629120000_secdef_grant_
--     hardening.sql already closed once. (The lost security_invoker is a separate pre-existing
--     defect on main — recorded for follow-up, not fixed here; the grant is what contains it.)
--   * public.advertisers has whole-table SELECT deliberately revoked and column-scoped by
--     20260716150000_advertiser_identity_rls.sql:377-378, precisely so stripe_customer_id and
--     is_house never reach a client. A surviving table-level read defeats that for the caller's
--     own row.
--
-- The nine tables below are exactly those on which a migrations-only stack grants `authenticated`
-- no SELECT — derived from that stack, not from production.
-- ---------------------------------------------------------------------------
revoke select on all tables in schema public from anon;

revoke select on
  public.ad_windows,
  public.advertisers,
  public.billing_run_lock,
  public.device_auth_codes,
  public.device_code_approve_attempts,
  public.rl_buckets,
  public.signup_throttle_buckets,
  public.stripe_webhook_events,
  public.uncharged_advertiser_billings
from authenticated;

-- Mandatory re-grant, same cascade trap as publishers(handle, country) above: the table-level
-- REVOKE SELECT destroys the five column ACLs 20260716150000 established. Without this line the
-- advertiser portal cannot read its own org at all.
grant select (id, name, status, billing_mode, created_at) on public.advertisers to authenticated;
