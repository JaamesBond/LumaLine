-- lumaline security-audit pass-2 (Cluster P3 / SYBIL) — signup + device-creation throttle.
--
-- Raises the Sybil bar for a SINGLE host spinning up many accounts/devices fast. Two enforceable
-- chokepoints:
--   (A) auth-device /device/code issuance — a DURABLE per-trusted-IP + GLOBAL fixed-window counter
--       (public.signup_throttle_hit, called by the edge fn under service_role), beyond the existing
--       per-isolate memory limiter which a distributed caller trivially evades.
--   (B) ensure_publisher — a GLOBAL new-publisher-per-minute cap in-DB (no client IP is available in
--       this SECDEF path; the browser calls it directly on PostgREST). Bounds fleet-wide burst
--       provisioning; the returning-user (idempotent) path is never throttled.
-- Residual Sybil across distinct KYC identities/IPs is operational (KYC + 7d hold + review), NOT
-- code-eliminable — see the function comments.
-- DEPENDS ON: 20260716150000 (the current ensure_publisher body with the self-deal guard).

-- ---- (A) durable fixed-window counter (service-role only; == rl_buckets shape) --------------------
create table if not exists public.signup_throttle_buckets (
  scope        text        not null,   -- e.g. 'devcode_global' | 'devcode_ip:<salted-hash>'
  window_start timestamptz not null,
  count        integer     not null default 0,
  primary key (scope, window_start)
);
alter table public.signup_throttle_buckets enable row level security;
drop policy if exists signup_throttle_buckets_service on public.signup_throttle_buckets;
create policy signup_throttle_buckets_service on public.signup_throttle_buckets
  for all to service_role using (true) with check (true);
revoke all on public.signup_throttle_buckets from public, anon, authenticated;
grant  select, insert, update, delete on public.signup_throttle_buckets to service_role;

-- Atomic hit: bump (scope, current-minute) and report still-in-budget. Fail-CLOSED on a null/empty
-- scope (unlike rl_hit's fail-open — a creation event with no scope must not be silently admitted);
-- the caller always passes a concrete scope (global is never null).
create or replace function public.signup_throttle_hit(p_scope text, p_max integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_ws    timestamptz := date_trunc('minute', now());
  v_count integer;
begin
  if p_scope is null or length(p_scope) = 0 then
    return false;                      -- fail-closed: no scope => deny (creation must be scoped)
  end if;
  insert into public.signup_throttle_buckets (scope, window_start, count)
       values (p_scope, v_ws, 1)
  on conflict (scope, window_start)
       do update set count = public.signup_throttle_buckets.count + 1
    returning count into v_count;
  return v_count <= greatest(p_max, 1);
end;
$$;
revoke execute on function public.signup_throttle_hit(text, integer) from public, anon, authenticated;
grant  execute on function public.signup_throttle_hit(text, integer) to service_role;

comment on function public.signup_throttle_hit is
  'Durable fixed-window signup/device throttle counter (== rl_hit shape, but fail-CLOSED on empty scope). '
  'Called by auth-device under service_role for /device/code (global + per-trusted-IP scopes). service_role only.';

-- ---- (B) ensure_publisher — recreate 20260716150000 VERBATIM + a GLOBAL new-publisher cap ----------
-- The ONLY change vs 20260716150000: a global velocity gate placed in the NEW-publisher branch,
-- AFTER the idempotent existing-row return (so returning users are never throttled) and AFTER the
-- self-deal advertiser refusal, BEFORE the first INSERT. Everything else (self-deal guard, uid-slug
-- handle, race handling, ACL, comment) is byte-identical to 20260716150000.
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
  v_recent  integer;
  MAX_NEW_PUB_PER_MIN constant integer := 20;   -- fleet-wide new-publisher ceiling / minute
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

  -- *** P3 SYBIL: GLOBAL new-publisher velocity cap (only reached on the CREATE path) ***
  SELECT count(*) INTO v_recent
    FROM public.publishers WHERE created_at > now() - interval '1 minute';
  IF v_recent >= MAX_NEW_PUB_PER_MIN THEN
    RAISE EXCEPTION 'signup rate limit: too many new publishers created recently, retry shortly'
      USING errcode = '53400';                 -- configuration_limit_exceeded (retryable)
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
  'Publisher provisioning + bidirectional self-deal guard (refuses an advertiser identity) + P3 GLOBAL '
  'new-publisher-per-minute cap on the CREATE path only (returning users never throttled). Per-IP signup '
  'throttling is not possible here (browser calls PostgREST directly, no client IP); the device-code '
  'edge throttle carries the per-IP dimension. Residual cross-identity Sybil is operational (KYC/hold/review). '
  'SECDEF; authenticated + service_role; anon revoked.';

-- Prune (only the current minute matters) — mirrors lumaline-rl-prune.
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('lumaline-signup-throttle-prune', '*/5 * * * *',
      $cron$ delete from public.signup_throttle_buckets where window_start < now() - interval '5 minutes' $cron$);
  else
    raise warning 'pg_cron absent (local?); prune public.signup_throttle_buckets externally in prod';
  end if;
end $$;

-- Migration-tail assertion — anon holds NO EXECUTE.
do $$
declare v_fn text; v_fns text[] := array[
  'public.signup_throttle_hit(text, integer)',
  'public.ensure_publisher(text)'
];
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — REVOKE ... FROM public, anon missing', v_fn;
    end if;
  end loop;
end $$;
