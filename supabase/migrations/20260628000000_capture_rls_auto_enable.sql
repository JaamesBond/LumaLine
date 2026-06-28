-- 20260628000000_capture_rls_auto_enable.sql
--
-- DRIFT CAPTURE (M0-T1): codify an object that was hand-applied to the live project
-- (prmsonskzrubqsazmpwd) during security hardening but never committed as a migration.
--
-- The object: a defense-in-depth event trigger `ensure_rls` (+ its function
-- `public.rls_auto_enable`) that auto-enables ROW LEVEL SECURITY on any newly-created
-- table in the `public` schema. It backstops the "RLS on all tables" trust invariant so a
-- future table added without an explicit `enable row level security` cannot silently ship
-- unprotected. Verified live: function `public.rls_auto_enable()` (SECURITY DEFINER,
-- search_path=pg_catalog) + event trigger `ensure_rls` ON ddl_command_end WHEN TAG IN
-- ('CREATE TABLE','CREATE TABLE AS','SELECT INTO').
--
-- Fully IDEMPOTENT (create-or-replace fn + drop-if-exists/create event trigger +
-- naturally-idempotent revoke), so applying it to the already-converged remote is a no-op
-- and a fresh `supabase db reset` reproduces the live object set exactly.

create or replace function public.rls_auto_enable()
  returns event_trigger
  language plpgsql
  security definer
  set search_path to 'pg_catalog'
as $function$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN
    SELECT *
    FROM pg_event_trigger_ddl_commands()
    WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
      AND object_type IN ('table','partitioned table')
  LOOP
     IF cmd.schema_name IS NOT NULL AND cmd.schema_name IN ('public') AND cmd.schema_name NOT IN ('pg_catalog','information_schema') AND cmd.schema_name NOT LIKE 'pg_toast%' AND cmd.schema_name NOT LIKE 'pg_temp%' THEN
      BEGIN
        EXECUTE format('alter table if exists %s enable row level security', cmd.object_identity);
        RAISE LOG 'rls_auto_enable: enabled RLS on %', cmd.object_identity;
      EXCEPTION
        WHEN OTHERS THEN
          RAISE LOG 'rls_auto_enable: failed to enable RLS on %', cmd.object_identity;
      END;
     ELSE
        RAISE LOG 'rls_auto_enable: skip % (either system schema or not in enforced list: %.)', cmd.object_identity, cmd.schema_name;
     END IF;
  END LOOP;
END;
$function$;

-- Least privilege: an event-trigger function is invoked by the DDL machinery as its owner,
-- never via EXECUTE — so strip the default PUBLIC grant (matches the live posture: only the
-- owner + service_role retain it). Naturally idempotent.
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;

drop event trigger if exists ensure_rls;
create event trigger ensure_rls
  on ddl_command_end
  when tag in ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
  execute function public.rls_auto_enable();
