-- lumaline M1 — RFC 8628 device-code flow + publisher provisioning + device refresh/revoke.
--
-- The publishers / devices / device_auth_codes TABLES already exist (Phase 1,
-- 20260627022222). M0 shipped a rotation-safe client and a sentinel feed where EVERY install
-- runs as one shared, never-billed identity. This migration adds the SQL the `auth-device`
-- edge function drives so a REAL developer can log in (device-code grant), get attributed
-- credit, and revoke a device — without changing the trust-critical window RPCs at all.
--
-- HOW IT BINDS (the load-bearing detail):
--   * window_open/window_beat/close_window credit by the `publisher_id`/`device_id` JWT CLAIMS
--     (20260627025330_window_rpcs.sql). They already re-check devices.revoked_at on EVERY call
--     (open + mid-session beat + close), so revocation is instant on the hot path — no change.
--   * the earnings VIEWS (v_publisher_balance / v_publisher_window_clearing) RLS-scope via
--     app.current_publisher_id() => auth.uid() => publishers.auth_user_id, i.e. the JWT `sub`.
--   So a minted device JWT MUST carry a CONSISTENT identity: sub = publishers.auth_user_id AND
--   publisher_id = publishers.id AND device_id = the device row, or a publisher would be
--   credited under one id yet read a balance under another. The edge fn mints all three from
--   device_code_redeem's reply; this migration is the source of that reply.
--
-- TRUST INVARIANTS preserved:
--   * Honest billing — the sentinel (gross=0) stays the fallback for anon/revoked/expired; this
--     migration never introduces a non-zero sentinel bid and books no ledger leg itself.
--   * Secret custody — only HASHES of the device_code and the refresh token are stored; the raw
--     secrets exist only transiently in the edge fn and on the client. user_code is low-entropy
--     by design (typed by a human) and is single-use + short-TTL.
--   * Least privilege — Supabase's default privilege AUTO-GRANTS EXECUTE on every new public
--     function to anon + authenticated. These RPCs are SECURITY DEFINER (they bypass RLS), so
--     this migration REVOKEs that auto-grant and re-grants the MINIMAL role, exactly like
--     20260627040000_harden_function_grants.sql. A missing REVOKE here would expose device
--     issuance to the public anon key. (cf. [[lumaline-secdef-grant-hardening]].)

-- ---------------------------------------------------------------------------
-- schema deltas (additive; existing columns/constraints untouched)
-- ---------------------------------------------------------------------------
-- device_auth_codes gains: which device was minted on consume (audit trail), the poll
-- interval advertised to the client, and approve/consume timestamps.
alter table public.device_auth_codes
  add column if not exists device_id        uuid references public.devices (id) on delete set null,
  add column if not exists interval_seconds integer not null default 5,
  add column if not exists approved_at       timestamptz,
  add column if not exists consumed_at       timestamptz;

-- devices gains a HASH of the current refresh token (raw token never stored). NULL = no active
-- refresh credential (fresh device before first mint, or after revoke). Rotated on every refresh.
alter table public.devices
  add column if not exists refresh_token_hash text;

-- ---------------------------------------------------------------------------
-- ensure_publisher(handle?) -> { publisher_id, handle, created }
-- Idempotently provisions THIS authenticated user's publishers row. Called by the /activate
-- page right after a developer signs in (Supabase Auth) and before they approve a device code,
-- so app.current_publisher_id() resolves. Handle defaults to a uid-derived, collision-free slug;
-- an explicit handle is honored only when creating (never lets one user rename over another).
-- ---------------------------------------------------------------------------
create or replace function public.ensure_publisher(p_handle text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid     uuid := (select auth.uid());
  v_pid     uuid;
  v_handle  text;
  v_slug    text;
  v_created boolean := false;
begin
  if v_uid is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;

  select id, handle into v_pid, v_handle from public.publishers where auth_user_id = v_uid;
  if v_pid is not null then
    return jsonb_build_object('publisher_id', v_pid, 'handle', v_handle, 'created', false);
  end if;

  -- New publisher. The uid-derived slug is unique by construction; an explicit handle is tried
  -- first but must NEVER error the login — a handle collision (a SEPARATE unique constraint that
  -- `on conflict (auth_user_id)` does not cover, and that a pre-check cannot see for an
  -- uncommitted concurrent row) falls back to the slug. The slug fallback's own auth_user_id
  -- conflict (a lost race) is absorbed by `do nothing` -> v_pid null -> re-read below.
  v_slug   := 'pub_' || substr(replace(v_uid::text, '-', ''), 1, 12);
  v_handle := coalesce(nullif(trim(p_handle), ''), v_slug);
  begin
    insert into public.publishers (auth_user_id, handle)
      values (v_uid, v_handle)
      on conflict (auth_user_id) do nothing
      returning id into v_pid;
  exception when unique_violation then     -- requested handle taken by another user
    insert into public.publishers (auth_user_id, handle)
      values (v_uid, v_slug)
      on conflict (auth_user_id) do nothing
      returning id into v_pid;
  end;

  if v_pid is null then   -- lost an auth_user_id race: the row now exists, read it back
    select id, handle into v_pid, v_handle from public.publishers where auth_user_id = v_uid;
  else
    v_created := true;
    select handle into v_handle from public.publishers where id = v_pid;  -- reflect stored handle
  end if;

  return jsonb_build_object('publisher_id', v_pid, 'handle', v_handle, 'created', v_created);
end;
$$;
revoke execute on function public.ensure_publisher(text) from anon, public;
grant  execute on function public.ensure_publisher(text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- device_code_start(device_code_hash, user_code, ttl?, interval?) -> { expires_in, interval }
-- service_role ONLY (called by the auth-device edge fn). Records a pending grant. The raw
-- device_code + user_code are generated in the edge fn; only the device_code HASH is stored.
-- ---------------------------------------------------------------------------
create or replace function public.device_code_start(
  p_device_code_hash text,
  p_user_code        text,
  p_ttl_seconds      integer default 600,
  p_interval         integer default 5)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_ttl timestamptz := now() + make_interval(secs => greatest(p_ttl_seconds, 60));
begin
  if p_device_code_hash is null or p_user_code is null then
    raise exception 'device_code_hash and user_code required' using errcode = 'P0001';
  end if;
  insert into public.device_auth_codes (device_code_hash, user_code, status, expires_at, interval_seconds)
    values (p_device_code_hash, p_user_code, 'pending', v_ttl, greatest(p_interval, 1));
  return jsonb_build_object('expires_in', greatest(p_ttl_seconds, 60), 'interval', greatest(p_interval, 1));
end;
$$;
revoke execute on function public.device_code_start(text, text, integer, integer) from anon, authenticated, public;
grant  execute on function public.device_code_start(text, text, integer, integer) to service_role;

-- ---------------------------------------------------------------------------
-- device_code_approve(user_code) -> { ok, reason?, handle? }
-- authenticated ONLY. Called from the /activate page by the signed-in developer; binds the
-- pending grant to THEIR publisher (app.current_publisher_id()). One-way pending -> approved.
-- ---------------------------------------------------------------------------
create or replace function public.device_code_approve(p_user_code text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pub uuid := (select app.current_publisher_id());
  v_code text := upper(regexp_replace(coalesce(p_user_code, ''), '[^A-Za-z0-9]', '', 'g'));
  r public.device_auth_codes;
begin
  if v_pub is null then
    raise exception 'no publisher for this user (call ensure_publisher first)' using errcode = '28000';
  end if;
  select * into r from public.device_auth_codes where user_code = v_code for update;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'unknown_code');
  end if;
  if r.expires_at <= now() then
    update public.device_auth_codes set status = 'expired' where id = r.id and status = 'pending';
    return jsonb_build_object('ok', false, 'reason', 'expired');
  end if;
  if r.status <> 'pending' then
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

-- ---------------------------------------------------------------------------
-- device_code_redeem(device_code_hash, label?, client_version?, refresh_token_hash?) -> jsonb
-- service_role ONLY (the auth-device /device/token poll). Maps the grant to an RFC 8628 status;
-- on 'approved' it CREATES the device row (storing the refresh-token hash) and returns the full
-- identity the edge fn needs to mint the device JWT. One-shot: approved -> consumed.
--   statuses returned: authorization_pending | expired | denied | consumed | invalid | approved
-- ---------------------------------------------------------------------------
create or replace function public.device_code_redeem(
  p_device_code_hash   text,
  p_label              text default null,
  p_client_version     text default null,
  p_refresh_token_hash text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r       public.device_auth_codes;
  v_dev   uuid;
  v_user  uuid;
  v_handle text;
begin
  select * into r from public.device_auth_codes where device_code_hash = p_device_code_hash for update;
  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;
  -- Expire lazily so a never-polled-after-approval grant cannot linger.
  if r.expires_at <= now() and r.status in ('pending', 'approved') then
    update public.device_auth_codes set status = 'expired' where id = r.id;
    return jsonb_build_object('status', 'expired');
  end if;
  if r.status = 'pending' then return jsonb_build_object('status', 'authorization_pending'); end if;
  if r.status = 'denied'  then return jsonb_build_object('status', 'denied'); end if;
  if r.status = 'expired' then return jsonb_build_object('status', 'expired'); end if;
  if r.status = 'consumed' then return jsonb_build_object('status', 'consumed'); end if;
  -- status = 'approved' -> mint exactly once.
  insert into public.devices (publisher_id, label, client_version, attested, refresh_token_hash)
    values (r.publisher_id, p_label, p_client_version, false, p_refresh_token_hash)
    returning id into v_dev;
  update public.device_auth_codes
     set status = 'consumed', device_id = v_dev, consumed_at = now()
   where id = r.id;
  select auth_user_id, handle into v_user, v_handle from public.publishers where id = r.publisher_id;
  return jsonb_build_object(
    'status', 'approved',
    'publisher_id', r.publisher_id,
    'device_id', v_dev,
    'auth_user_id', v_user,
    'handle', v_handle);
end;
$$;
revoke execute on function public.device_code_redeem(text, text, text, text) from anon, authenticated, public;
grant  execute on function public.device_code_redeem(text, text, text, text) to service_role;

-- ---------------------------------------------------------------------------
-- device_refresh(refresh_token_hash, new_refresh_token_hash) -> { status, identity... }
-- service_role ONLY (the auth-device /device/refresh). Validates the hash against an ACTIVE
-- (revoked_at IS NULL) device, ROTATES the stored hash, and returns the identity to re-mint a
-- fresh short-lived access JWT. A revoked device fails here AND on the window RPCs' revoked_at
-- check — defence in depth.
-- ---------------------------------------------------------------------------
create or replace function public.device_refresh(
  p_refresh_token_hash     text,
  p_new_refresh_token_hash text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  d        public.devices;
  v_user   uuid;
  v_handle text;
begin
  if p_refresh_token_hash is null or p_new_refresh_token_hash is null then
    return jsonb_build_object('status', 'invalid');
  end if;
  select * into d from public.devices
   where refresh_token_hash = p_refresh_token_hash and revoked_at is null
   for update;
  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;
  update public.devices set refresh_token_hash = p_new_refresh_token_hash where id = d.id;
  select auth_user_id, handle into v_user, v_handle from public.publishers where id = d.publisher_id;
  return jsonb_build_object(
    'status', 'ok',
    'publisher_id', d.publisher_id,
    'device_id', d.id,
    'auth_user_id', v_user,
    'handle', v_handle);
end;
$$;
revoke execute on function public.device_refresh(text, text) from anon, authenticated, public;
grant  execute on function public.device_refresh(text, text) to service_role;

-- ---------------------------------------------------------------------------
-- device_revoke(device_id) -> { ok }
-- authenticated ONLY. `lumaline logout` (and account management) revokes a device the caller
-- owns. Sets revoked_at (instant on the hot path) and clears the refresh hash. Scoped to the
-- caller's own publisher_id, so one publisher can never revoke another's device.
-- ---------------------------------------------------------------------------
create or replace function public.device_revoke(p_device_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pub uuid := (select app.current_publisher_id());
  v_hit boolean;
begin
  if v_pub is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;
  update public.devices
     set revoked_at = coalesce(revoked_at, now()), refresh_token_hash = null
   where id = p_device_id and publisher_id = v_pub
  returning true into v_hit;
  return jsonb_build_object('ok', coalesce(v_hit, false));
end;
$$;
revoke execute on function public.device_revoke(uuid) from anon, public;
grant  execute on function public.device_revoke(uuid) to authenticated, service_role;
