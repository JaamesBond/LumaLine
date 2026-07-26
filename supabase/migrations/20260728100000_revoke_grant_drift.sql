-- 20260728100000_revoke_grant_drift.sql
-- Corrective: make PRODUCTION's table ACLs match what THIS repo's migrations have always granted.
--
-- ---------------------------------------------------------------------------
-- THE DRIFT
-- ---------------------------------------------------------------------------
-- An audit of production found `anon` and `authenticated` holding `arwdDxtm` — SELECT, INSERT,
-- UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN — on 25 tables in schema `public`. The
-- migrations in this repo never granted that. They grant, at most, SELECT to `authenticated`, and
-- NO SELECT and NO DML to `anon` anywhere. A stack built purely from these migrations
-- (`supabase db reset`) reproduces the correct, narrow ACLs. THE MIGRATIONS WERE ALWAYS RIGHT;
-- production acquired the extra privileges from somewhere else.
--
-- ROOT CAUSE: Supabase's DEFAULT PRIVILEGES. `pg_default_acl` carries one entry per role that
-- creates objects in the schema, and on production BOTH entries for schema `public` hand
-- anon/authenticated the full `arwdDxtm`:
--
--   pg_default_acl: supabase_admin / public / r -> anon=arwdDxtm, authenticated=arwdDxtm
--   pg_default_acl: postgres       / public / r -> anon=arwdDxtm, authenticated=arwdDxtm
--
-- All 35 relations in `public` on production are owned by `postgres`, so the `postgres` entry is
-- the operative one: every table these migrations create is stamped wide open at CREATE time, and
-- only an explicit REVOKE narrows it. (A local `supabase start` stack does NOT reproduce this — its
-- newer CLI image ships the `postgres` entry as `Dxtm`, which is why a `db reset` looks clean and
-- why this drift was invisible to the test suite. Do not re-derive this from local state.)
--
-- This is the same class of footgun already recorded in 20260629120000_secdef_grant_hardening.sql,
-- where Supabase's default privileges auto-granted `anon` EXECUTE on every new public function.
--
-- ---------------------------------------------------------------------------
-- WHY IT MATTERS: SELF-SERVICE PAYOUT REDIRECTION
-- ---------------------------------------------------------------------------
-- With a table-level UPDATE grant in place, row-level security is the ONLY thing left containing a
-- publisher — and on `public.publishers` the `publishers_update_own` policy PERMITS UPDATE of your
-- own row (`auth.uid() = auth_user_id`, the same predicate in USING and WITH CHECK). There is no
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
--   * payout_status     = 'verified'    -- self-verify, skipping Stripe Connect KYC
--   * stripe_account_id = '<any acct>'  -- REDIRECT THEIR OWN PAYOUT to an arbitrary account
--   * status            = 'active'      -- un-suspend themselves
--   * deleted_at                        -- undo a GDPR erasure
--
-- `payout_batch_reserve` selects candidates on exactly `payout_status = 'verified'` AND
-- `stripe_account_id is not null` AND `status = 'active'` AND `deleted_at is null`. On production
-- all four of those were self-settable by the payee. That is real money.
--
-- The same blanket grant let `anon` — the public API key shipped in every client — SELECT, INSERT,
-- UPDATE and DELETE wherever a permissive RLS policy did not explicitly say no.
--
-- ---------------------------------------------------------------------------
-- SCOPE NOTE: SELECT IS PART OF THE DRIFT
-- ---------------------------------------------------------------------------
-- The drift is `arwdDxtm`, so revoking only the DML bits (`awdD`) would leave `r` in place and
-- production still would NOT match `main`. Two concrete read regressions ride on that `r`:
--
--   * `public.advertisers` — 20260716150000_advertiser_identity_rls.sql DELIBERATELY revoked
--     whole-table SELECT and replaced it with a column-scoped grant on
--     (id, name, status, billing_mode, created_at). A blanket `r` re-exposes every other column.
--   * Nine relations grant `authenticated` no SELECT at all by design — including
--     `device_auth_codes` (device-login codes) and `stripe_webhook_events`.
--
-- So SELECT is revoked here too. It is revoked from `anon` schema-wide (baseline: `anon` holds no
-- SELECT anywhere in `public`), but from `authenticated` only on the nine relations that are meant
-- to have none. Revoking SELECT from `authenticated` schema-wide and re-granting the ~26 tables it
-- legitimately reads would fail LOUD (a missed re-grant breaks a dashboard); enumerating the
-- complement fails SAFE (a missed entry merely leaves an extra read). Given this runs against live
-- production, fail-safe wins.
--
-- ---------------------------------------------------------------------------
-- WHAT IS AND IS NOT TOUCHED
-- ---------------------------------------------------------------------------
-- `service_role` is deliberately never named below and is therefore untouched: it keeps the full
-- DML the edge functions need. `service_role` is not a member of `anon` or `authenticated` (only
-- `authenticator` is a member of all three), so revoking from those two cannot reach it.
--
-- SCOPE: grants only. No RLS policy, function, trigger or table definition is altered here.
--
-- On a clean stack built from these migrations this is very nearly a no-op. The only privilege it
-- removes that `main` previously left in place is TRUNCATE. That removal is deliberate: TRUNCATE
-- BYPASSES RLS ENTIRELY — no policy is consulted — so a TRUNCATE grant to `anon` is contained by
-- nothing. It arrived purely as Supabase default-privilege residue; no code path in this repo
-- truncates anything, and 20260716100000_admin_dashboard_foundation.sql already asserts as design
-- intent that "no client role has TRUNCATE". This makes that sentence true.
--
-- ---------------------------------------------------------------------------
-- THE COLUMN-LEVEL TRAP (why the re-grants below are mandatory, not belt-and-braces)
-- ---------------------------------------------------------------------------
-- PostgreSQL: "When revoking privileges on a table, the corresponding column privileges (if any)
-- are automatically revoked on each column of the table, as well." A table-level REVOKE therefore
-- DESTROYS the column-scoped grants. Verified empirically on the local stack: after
-- `revoke update ... from authenticated`, `pg_attribute.attacl` for publishers.handle/country goes
-- from `{authenticated=w/postgres}` to NULL and `has_column_privilege` flips to false. Without the
-- re-grants below, the publisher dashboard's profile edit and the advertiser portal's org read both
-- silently break.
--
-- ---------------------------------------------------------------------------
-- WHY STEP 5 (THE DEFAULT PRIVILEGES) IS NOT OPTIONAL
-- ---------------------------------------------------------------------------
-- Steps 1-4 correct the relations that exist TODAY. Left at that, the fix decays: `pg_default_acl`
-- would still stamp every table added by a FUTURE migration wide open, and the hole comes back
-- silently, one new table at a time. Step 5 closes the source.
--
-- The form matters. `ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin ...` fails with 42501
-- "permission denied to change default privileges" — `postgres` is not a member of
-- `supabase_admin`. With no FOR ROLE clause the statement targets the CURRENT role, `postgres`,
-- which is both alterable and the operative entry here (all 35 relations are postgres-owned). The
-- `supabase_admin` entry is left as-is: nothing in `public` is created under it, and it is not ours
-- to change.
--
-- Revoking ALL (not just DML) at the default matches this repo's existing convention, stated in
-- 20260627022222_publishers_devices.sql: "Data API is 'always revoked' by default … grant
-- explicitly." Every migration already grants what it needs, and an explicit GRANT still works
-- normally after this — default privileges only govern the ACL an object is born with.

-- ---------------------------------------------------------------------------
-- 1. `anon` holds NOTHING in `public`. It never legitimately did — every anonymous code path in
--    this system goes through an edge function on `service_role`, never the Data API.
--    ON ALL TABLES IN SCHEMA covers views and foreign tables too.
--    REVOKE ALL rather than an enumerated list: it also clears the REFERENCES/TRIGGER/MAINTAIN
--    residue that Supabase's default privileges leave behind (TRIGGER on a table you do not own is
--    a real privilege), and it names no version-specific keyword — MAINTAIN only exists on PG17+,
--    so spelling it out would fail on an older production instance.
-- ---------------------------------------------------------------------------
revoke all on all tables in schema public from anon;

-- ---------------------------------------------------------------------------
-- 2. `authenticated` holds no DML anywhere in `public` …
-- ---------------------------------------------------------------------------
revoke insert, update, delete, truncate on all tables in schema public from authenticated;

-- ---------------------------------------------------------------------------
-- 3. … except these three, which the migrations do intend. Derived from the migrations, not from
--    production. This is the complete set.
-- ---------------------------------------------------------------------------

-- 20260627022222_publishers_devices.sql:66 — the profile-only edit surface. MUST be re-granted:
-- step 2 cascaded into the column ACL (see THE COLUMN-LEVEL TRAP above). This is the boundary that
-- keeps payout_status / status / stripe_account_id service_role-only.
grant update (handle, country) on public.publishers to authenticated;

-- 20260629070000_clawback_review.sql:59 — publishers file and amend their own clawback appeals.
grant insert, update on public.clawback_reviews to authenticated;

-- 20260629070000_clawback_review.sql:101 — publishers file disputes; they may not edit them after.
grant insert on public.disputes to authenticated;

-- ---------------------------------------------------------------------------
-- 4. `authenticated` reads most of `public` under RLS, but these eight relations grant it nothing
--    at all by design. Enumerating the complement (rather than revoke-all-SELECT + re-grant the
--    ~26 tables it does read) is the fail-safe direction: a mistake here leaves an extra read in
--    place, whereas a missed re-grant would break a dashboard on live production.
-- ---------------------------------------------------------------------------
revoke all on
  public.ad_windows,                    -- serving internals; publishers read impressions, not windows
  public.billing_run_lock,              -- single-flight advisory row
  public.device_auth_codes,             -- RFC 8628 device-login codes
  public.device_code_approve_attempts,  -- brute-force counters for the above
  public.rl_buckets,                    -- rate-limit counters
  public.signup_throttle_buckets,       -- Sybil-signup counters
  public.stripe_webhook_events,         -- webhook dedup ledger
  public.uncharged_advertiser_billings  -- view; 20260629120000 revoked ALL on it
from authenticated;

-- 20260716150000_advertiser_identity_rls.sql:377-378 — whole-table SELECT stays revoked; the
-- advertiser portal reads exactly these five columns of its own org. The grant must follow the
-- revoke: a table-level revoke cascades into the column ACL (see THE COLUMN-LEVEL TRAP above).
revoke all on public.advertisers from authenticated;
grant select (id, name, status, billing_mode, created_at) on public.advertisers to authenticated;

-- ---------------------------------------------------------------------------
-- 5. Close the source, so the drift cannot recur on the next table anyone adds.
--    No FOR ROLE clause: targets `postgres`, the role that owns every relation in `public` and the
--    one whose default-ACL entry is actually stamping new tables on production. See
--    "WHY STEP 5 IS NOT OPTIONAL" above.
-- ---------------------------------------------------------------------------
alter default privileges in schema public revoke all on tables from anon, authenticated;
