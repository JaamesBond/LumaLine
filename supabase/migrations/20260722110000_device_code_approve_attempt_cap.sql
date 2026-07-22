-- lumaline security-audit (Cluster E / C3-D3) — attempt cap on device_code_approve (defense-in-depth
-- vs user_code brute force).
--
-- device_code_approve() is authenticated-only but callable directly via PostgREST; a caller could
-- brute-force the low-entropy 8-char user_code to approve a foreign pending grant (binds the victim's
-- device to the attacker's publisher). Add a per-caller (auth.uid()) FAILED-attempt fixed-window
-- limiter (mirrors public.rl_hit / rl_buckets): touched ONLY through the SECDEF RPC.

create table if not exists public.device_code_approve_attempts (
  auth_user_id uuid        not null,
  window_start timestamptz not null,
  attempts     integer     not null default 0,
  primary key (auth_user_id, window_start)
);
alter table public.device_code_approve_attempts enable row level security;
-- No anon/authenticated table access; the SECDEF RPC (owner priv) is the only writer, exactly like
-- rl_buckets. service_role retains full access for ops/prune.
drop policy if exists device_code_approve_attempts_service on public.device_code_approve_attempts;
create policy device_code_approve_attempts_service
  on public.device_code_approve_attempts for all to service_role using (true) with check (true);
grant select, insert, update, delete on public.device_code_approve_attempts to service_role;

-- Recreate device_code_approve with a per-caller failed-attempt cap. Body is the CURRENT definition
-- (20260629010000_device_code_flow.sql L143-172) with the rate gate + failure counter added; the
-- happy path (matched pending -> approved) is unchanged and does NOT increment the counter.
create or replace function public.device_code_approve(p_user_code text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid   uuid := (select auth.uid());
  v_pub   uuid := (select app.current_publisher_id());
  v_code  text := upper(regexp_replace(coalesce(p_user_code, ''), '[^A-Za-z0-9]', '', 'g'));
  v_ws    timestamptz := date_trunc('minute', now());
  v_max   integer := 10;      -- max FAILED approvals per caller per minute
  v_fails integer := 0;
  r public.device_auth_codes;
begin
  if v_pub is null then
    raise exception 'no publisher for this user (call ensure_publisher first)' using errcode = '28000';
  end if;

  -- Rate gate BEFORE any code lookup (no validity oracle): refuse once this caller has burned
  -- v_max failed guesses in the current minute. Fixed-window refusal = the backoff.
  select attempts into v_fails
    from public.device_code_approve_attempts
   where auth_user_id = v_uid and window_start = v_ws;
  if coalesce(v_fails, 0) >= v_max then
    return jsonb_build_object('ok', false, 'reason', 'rate_limited');
  end if;

  select * into r from public.device_auth_codes where user_code = v_code for update;
  if not found then
    perform app.device_code_approve_note_fail(v_uid, v_ws);
    return jsonb_build_object('ok', false, 'reason', 'unknown_code');
  end if;
  if r.expires_at <= now() then
    update public.device_auth_codes set status = 'expired' where id = r.id and status = 'pending';
    perform app.device_code_approve_note_fail(v_uid, v_ws);
    return jsonb_build_object('ok', false, 'reason', 'expired');
  end if;
  if r.status <> 'pending' then
    perform app.device_code_approve_note_fail(v_uid, v_ws);
    return jsonb_build_object('ok', false, 'reason', 'already_' || r.status);
  end if;
  update public.device_auth_codes
     set status = 'approved', publisher_id = v_pub, approved_at = now()
   where id = r.id;
  return jsonb_build_object('ok', true, 'handle', (select handle from public.publishers where id = v_pub));
end;
$$;
revoke execute on function public.device_code_approve(text) from anon, public;
grant  execute on function public.device_code_approve(text) to authenticated, service_role;

-- Private counter bump (SECDEF, app schema, off the Data API). Kept separate so the counter write
-- is a single upsert reused by every failure branch.
create or replace function app.device_code_approve_note_fail(p_uid uuid, p_ws timestamptz)
returns void
language sql
security definer
set search_path = ''
as $$
  insert into public.device_code_approve_attempts (auth_user_id, window_start, attempts)
       values (p_uid, p_ws, 1)
  on conflict (auth_user_id, window_start)
       do update set attempts = public.device_code_approve_attempts.attempts + 1;
$$;
revoke execute on function app.device_code_approve_note_fail(uuid, timestamptz) from public, anon, authenticated;
grant  execute on function app.device_code_approve_note_fail(uuid, timestamptz) to service_role;

-- Prune old buckets (only the current minute matters) — mirrors lumaline-rl-prune.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule(
      'lumaline-device-approve-prune', '*/5 * * * *',
      $cron$ delete from public.device_code_approve_attempts where window_start < now() - interval '5 minutes' $cron$
    );
  else
    raise warning 'pg_cron absent (local?); prune public.device_code_approve_attempts externally in prod';
  end if;
end $$;

-- Migration-tail assertion — anon holds NO EXECUTE (authenticated keeps device_code_approve).
do $$
declare
  v_fn  text;
  v_fns text[] := array[
    'public.device_code_approve(text)',
    'app.device_code_approve_note_fail(uuid, timestamptz)'
  ];
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — REVOKE ... FROM anon missing', v_fn;
    end if;
  end loop;
end $$;
