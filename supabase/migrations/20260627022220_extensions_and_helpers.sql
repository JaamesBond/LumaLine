-- lumaline Phase 1 schema — extensions, private `app` schema, and shared helpers.
--
-- Conventions enforced across all Phase 1 migrations:
--   * Money is ALWAYS bigint micro-USD (1_000_000 = $1).
--   * RLS is enabled on every table in the `public` schema; policies name `to`.
--   * SECURITY DEFINER helpers live in the private `app` schema with
--     `set search_path = ''` (everything fully qualified) and have EXECUTE
--     revoked from roles that must not call them directly.
--   * RLS predicates wrap volatile/stable calls as `(select fn())` so the
--     planner evaluates them once per statement (Supabase RLS perf rule).

-- pgcrypto: gen_random_uuid() is native in pg_catalog on PG17, but later
-- migrations/RPCs use digest()/hmac() for the heartbeat hash-chain, so enable it.
create extension if not exists pgcrypto with schema extensions;

-- Private schema for admin checks + helpers. NOT added to the PostgREST
-- `[api].schemas` list (config exposes only public + graphql_public), so it is
-- never reachable through the Data API.
create schema if not exists app;

-- Lock the schema down: only the table owner (postgres) and service_role get in
-- by default. `authenticated` is granted USAGE below *solely* so RLS policies can
-- call the whitelisted helper functions; it gets no table privileges here.
revoke all on schema app from public;
grant usage on schema app to authenticated, service_role;

-- Admin allow-list. Lives in `app` (off the Data API). Seed real admins out of
-- band (service_role / SQL), never from a client.
create table app.admins (
  auth_user_id uuid primary key references auth.users (id) on delete cascade,
  created_at   timestamptz not null default now()
);

-- is_admin(): true when the current JWT subject is in app.admins. SECURITY
-- DEFINER so it can read app.admins even though callers cannot. Wrapped
-- auth.uid() inside for the per-statement initplan cache.
create or replace function app.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from app.admins a
    where a.auth_user_id = (select auth.uid())
  );
$$;

-- Generic updated_at maintainer. Trigger functions fire with the table owner's
-- privileges, so no EXECUTE grant is needed by clients.
create or replace function app.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Functions default to EXECUTE for PUBLIC on creation — revoke, then grant only
-- where a role legitimately needs to call them.
revoke execute on function app.is_admin() from public;
revoke execute on function app.set_updated_at() from public;
grant execute on function app.is_admin() to authenticated, service_role;
