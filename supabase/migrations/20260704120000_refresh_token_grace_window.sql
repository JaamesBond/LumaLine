-- lumaline — refresh-token rotation GRACE WINDOW (crash-mid-rotation lockout fix).
--
-- BUG (confirmed): device_refresh is a NON-ATOMIC single-use rotation. The server durably kills
-- the old refresh token (commits `refresh_token_hash := new`) BEFORE the client durably persists
-- the successor (src/client/auth.mjs saveToken). On the statusline hot path the client routinely
-- abandons the in-flight response — killed by `statusLine.refreshInterval:1` at ~1s, or self-aborts
-- at FETCH_TIMEOUT_MS=3s against a cold edge function. Result: the successor is lost, the old token
-- is already dead, the token file is left unchanged, and the publisher silently falls to the
-- anonymous sentinel feed (earns €0) until a manual `lumaline login`.
--
-- FIX (Auth0/Okta "reuse interval"): honor the IMMEDIATELY-PREVIOUS refresh token for a short
-- bounded grace T after rotation. A client killed before persisting the successor recovers on its
-- next tick with the token still on its disk. NO client release needed — existing installs self-heal
-- (the file still holds the previous token). Exposure is bounded by three invariants, all enforced
-- below and asserted by test/device-refresh-grace.integration.mjs:
--   (a) ONLY the immediately-previous token is honored (never older — a 2nd rotation drops it);
--   (b) BOTH arms gate on `revoked_at IS NULL`, and device_revoke NULLs prev (no logout bypass);
--   (c) the grace timer NEVER re-arms on a grace use (bounded to one T per NORMAL rotation), while
--       a repeatedly-killed recovery tick may retry with the same prev until T elapses.
--
-- ACCEPTED RISK (corrected — do NOT understate the blast radius): within T the immediately-previous
-- token is a LIVE credential. An attacker who CAPTURES a superseded token (a server-side request-body
-- log/APM/proxy on /device/refresh, a synced token file, a disk image taken just before rotation) can,
-- within T, rotate the device onto an attacker-chosen hash — PERMANENTLY locking out the legit client
-- (until a manual `lumaline login`) and taking over the refresh chain. Fund movement stays gated
-- (payout changes require email OTP), so the residual blast radius is silent earnings-displacement +
-- read/accrual impersonation, NOT theft. T is kept SMALL (30s) to bound the capture window, and every
-- Arm-2 hit emits a `raise log` for reuse-detection. This is the industry-standard reuse-interval
-- tradeoff, accepted by the owner 2026-07-04 to fix an ACTIVE revenue-loss bug (crash-mid-rotation =>
-- publisher silently earns €0 until a manual re-login).

set local lock_timeout = '2s';
set local statement_timeout = '15s';

-- Two nullable columns = metadata-only add on PG11+ (brief ACCESS EXCLUSIVE, no table rewrite).
-- Existing devices backfill to NULL/NULL: their next NORMAL rotation arms the window; no disruption.
alter table public.devices
  add column if not exists prev_refresh_token_hash text,
  add column if not exists prev_rotated_at         timestamptz;

comment on column public.devices.prev_refresh_token_hash is
  'Immediately-previous refresh-token hash. device_refresh honors it within GRACE of prev_rotated_at '
  '(crash-mid-rotation recovery). NULLed on revoke. Only ever the single immediately-previous token.';
comment on column public.devices.prev_rotated_at is
  'When prev_refresh_token_hash was armed (the last NORMAL rotation). Grace is measured from here and '
  'is NEVER re-armed by a grace-arm use, so exposure is bounded to one window per normal rotation.';

-- Index the credential-lookup columns: device_refresh does an equality probe on each per call
-- (Arm-2 adds a second probe on every Arm-1 miss). UNIQUE partial (NULLs — revoked/fresh rows —
-- excluded) also makes the non-STRICT `select * into` collision-safe by construction.
create unique index if not exists devices_refresh_token_hash_key
  on public.devices (refresh_token_hash) where refresh_token_hash is not null;
create unique index if not exists devices_prev_refresh_token_hash_key
  on public.devices (prev_refresh_token_hash) where prev_refresh_token_hash is not null;

-- ---------------------------------------------------------------------------
-- device_refresh(refresh_token_hash, new_refresh_token_hash) -> { status, identity... }
-- Two arms. Arm 1 (NORMAL): the presented token is CURRENT → slide prev forward, arm the timer,
-- rotate. Arm 2 (GRACE): the presented token is the IMMEDIATELY-PREVIOUS one, still within T of the
-- last normal rotation → rotate WITHOUT touching prev/prev_rotated_at (non-re-arming, retryable).
-- Both arms require revoked_at IS NULL. `for update` serializes concurrent redemptions of one row.
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
  -- T: >= 2x the client refresh lock stale window (LOCK_STALE_MS=15s) so a crashed holder's lock is
  -- reclaimed and the retry still lands inside the grace — but kept SMALL to bound the reuse window
  -- (see ACCEPTED RISK above). test/grace-invariant.test.mjs pins T*1000 >= LOCK_STALE_MS*2.
  c_grace  constant interval := interval '30 seconds';
begin
  if p_refresh_token_hash is null or p_new_refresh_token_hash is null then
    return jsonb_build_object('status', 'invalid');
  end if;

  -- Arm 1 — NORMAL rotation (presented = current).
  select * into d from public.devices
   where refresh_token_hash = p_refresh_token_hash and revoked_at is null
   for update;
  if found then
    update public.devices
       set prev_refresh_token_hash = d.refresh_token_hash,  -- the token just superseded
           prev_rotated_at         = now(),                 -- (re-)arm the grace timer
           refresh_token_hash      = p_new_refresh_token_hash
     where id = d.id;
  else
    -- Arm 2 — GRACE recovery (presented = immediately-previous, within T, not revoked).
    select * into d from public.devices
     where prev_refresh_token_hash = p_refresh_token_hash
       and prev_rotated_at is not null
       and prev_rotated_at > now() - c_grace
       and revoked_at is null
     for update;
    if not found then
      return jsonb_build_object('status', 'invalid');
    end if;
    -- Observability: a grace-arm hit is EITHER a legit crash recovery OR a superseded-token reuse.
    -- Emit a log line so ops can alert on per-device Arm-2 frequency (reuse-detection).
    raise log 'lumaline device_refresh grace-arm recovery: device_id=% publisher_id=%', d.id, d.publisher_id;
    -- Rotate the current hash but DELIBERATELY leave prev/prev_rotated_at unchanged: the timer must
    -- not re-arm, and a recovery tick that is itself killed must be able to retry with the same prev.
    update public.devices
       set refresh_token_hash = p_new_refresh_token_hash
     where id = d.id;
  end if;

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
-- device_revoke(device_id) — MUST also clear prev, else a revoked/ logged-out device could still
-- refresh via the grace arm for up to T seconds. Behaviour otherwise unchanged.
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
     set revoked_at              = coalesce(revoked_at, now()),
         refresh_token_hash      = null,
         prev_refresh_token_hash = null   -- close the grace window on logout/revoke
   where id = p_device_id and publisher_id = v_pub
  returning true into v_hit;
  return jsonb_build_object('ok', coalesce(v_hit, false));
end;
$$;
revoke execute on function public.device_revoke(uuid) from anon, public;
grant  execute on function public.device_revoke(uuid) to authenticated, service_role;
