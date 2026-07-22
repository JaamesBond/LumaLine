-- lumaline security-audit hardening (Cluster A: farming/DoS/dwell-honesty; folds in Cluster E / A12).
--
-- Recreates public.window_open from 20260716180000_advertiser_serving_guardrails.sql VERBATIM
-- except FIVE marked changes:
--   (B2) IN-DB per-device concurrency + per-device/per-publisher velocity caps (the REAL fraud gate —
--        the edge rate-limit is bypassable via direct /rest/v1/rpc/window_open). Sentinel publisher is
--        EXEMPT (all anon traffic shares it; it is gross=0 and never bills).
--   (B4) window_open no longer MINTS or RETURNS the raw click token. The edge (lumaline-feed) mints it,
--        embeds it ONLY in the Ed25519-signed adData.clickUrl, and passes us its sha256 hex as
--        p_click_token_hash. click_resolve still resolves via the stored hash. A direct RPC caller is no
--        longer handed a ready-to-use click token.
--   (ip) ad_windows.ip_hash is stamped from p_client_ip_hash (the edge's salted-IP hash) so scan_ivt
--        can be per-device + per-IP aware WITHOUT touching close_window or the client->server envelope.
-- Everything else — the M9 reserve/self-deal/prepay hot path, close_window, sweep_stale_windows — is
-- UNCHANGED. Money invariants (backed reserve == SUM(ad_windows.reserve_micros), sentinel gross=0,
-- idempotent crediting) are preserved: none of the five changes touch reserve/serve/insert-idempotency.
--
-- This is the ONE authoritative window_open recreate for the audit (Cluster A caps + B4/ip + the
-- Cluster E / A12 budget soft-cap COMMENT). MUST run BEFORE 20260722130000 (scan_ivt reads ip_hash).
-- DEPENDS ON: 20260716180000 (the M9 window_open this replaces).

-- ---------------------------------------------------------------------------
-- ip_hash column + supporting indexes on the UNLOGGED hot table. All indexed columns (device_id,
-- publisher_id, started_at, ip_hash) are set at INSERT and never UPDATEd, so the per-beat UPDATE pays
-- NO index maintenance — the new indexes cost only at window_open insert.
-- ---------------------------------------------------------------------------
alter table public.ad_windows add column if not exists ip_hash text;

create index if not exists ad_windows_device_started_idx
  on public.ad_windows (device_id, started_at);
create index if not exists ad_windows_publisher_started_idx
  on public.ad_windows (publisher_id, started_at);
create index if not exists ad_windows_ip_started_idx
  on public.ad_windows (ip_hash, started_at) where ip_hash is not null;

-- ---------------------------------------------------------------------------
-- window_open — DROP the old 1-arg signature, recreate with the 3-arg signature. CREATE OR REPLACE
-- cannot change the arg list; without the DROP a single-arg call becomes ambiguous.
-- ---------------------------------------------------------------------------
drop function if exists public.window_open(text);

create or replace function public.window_open(
  p_activity_snapshot text default null,
  p_click_token_hash  text default null,   -- B4: sha256 hex of the edge-minted click token
  p_client_ip_hash    text default null    -- salted IP hash (edge-computed) for IVT; NULL ok
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  SENTINEL_PUB constant uuid := '5e470000-0000-4000-8000-0000000000b1';

  -- B2 cap tunables. Sized to NOT reject honest multi-session power users while still bounding a
  -- direct-RPC farm. Honest ceiling per session = 5s dwell + 15s cooldown ~= 3 opens/min, and one
  -- machine (device) rarely runs > ~4 concurrent Claude sessions.
  MAX_OPEN_CONCURRENT   constant integer := 6;    -- concurrent state='open' windows per device
  MAX_OPENS_MIN_DEVICE  constant integer := 30;   -- window opens / minute / device
  MAX_OPENS_MIN_PUB     constant integer := 120;  -- window opens / minute / publisher

  v_pub        uuid := nullif(app.jwt_claim('publisher_id'), '')::uuid;
  v_dev        uuid := nullif(app.jwt_claim('device_id'), '')::uuid;
  v_creative   record;
  v_window_id  uuid;
  v_challenge  text := encode(extensions.gen_random_bytes(16), 'hex');
  v_nonce      text := encode(extensions.gen_random_bytes(8), 'hex');
  -- (B4) v_token REMOVED — the edge mints the token now.
  v_dwell      integer := 5000;
  v_hb         integer := 1000;
  v_clearing   bigint := 0;
  v_reserve    bigint := 0;
  v_serve      boolean := false;
  v_cnt        integer;
begin
  if v_pub is null or v_dev is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;

  perform 1 from public.devices d
   where d.id = v_dev and d.publisher_id = v_pub and d.revoked_at is null;
  if not found then
    raise exception 'device revoked or unknown' using errcode = '28000';
  end if;

  -- ----- B2 IN-DB VELOCITY + CONCURRENCY CAP (the real fraud gate) ----------------
  -- Sentinel is EXEMPT: every anonymous machine shares SENTINEL_PUB / one device, and it is gross=0
  -- (never bills), so capping it would black out the honest anon feed for zero fraud benefit. Real
  -- publishers/devices are capped. The concurrency count is scoped to started_at > now()-2min so a
  -- crashed client's stale 'open' rows (swept after 10min) cannot permanently lock a device out.
  if v_pub is distinct from SENTINEL_PUB then
    select count(*) into v_cnt
      from public.ad_windows w
     where w.device_id = v_dev and w.state = 'open'
       and w.started_at > now() - interval '2 minutes';
    if v_cnt >= MAX_OPEN_CONCURRENT then
      raise exception 'window_open rate limit: too many concurrent open windows for this device (%).', v_cnt
        using errcode = '53400';   -- configuration_limit_exceeded
    end if;

    select count(*) into v_cnt
      from public.ad_windows w
     where w.device_id = v_dev and w.started_at > now() - interval '1 minute';
    if v_cnt >= MAX_OPENS_MIN_DEVICE then
      raise exception 'window_open rate limit: device open rate exceeded (%/min).', v_cnt
        using errcode = '53400';
    end if;

    select count(*) into v_cnt
      from public.ad_windows w
     where w.publisher_id = v_pub and w.started_at > now() - interval '1 minute';
    if v_cnt >= MAX_OPENS_MIN_PUB then
      raise exception 'window_open rate limit: publisher open rate exceeded (%/min).', v_cnt
        using errcode = '53400';
    end if;
  end if;

  -- ----- SERVING ALGORITHM (VERBATIM from 20260716180000) --------------------------
  if v_pub = SENTINEL_PUB then
    -- *** SENTINEL / ANONYMOUS PATH *** (zero-cost HOUSE creatives only)
    select c.id as creative_id, c.line_item_id, c.line, c.dest_url, c.label,
           li.cpva_bid_micros, li.cpc_bid_micros, a.id as advertiser_id, a.billing_mode
      into v_creative
      from public.creatives c
      join public.line_items li  on li.id = c.line_item_id
      join public.campaigns  cm  on cm.id = li.campaign_id
      join public.advertisers a  on a.id  = cm.advertiser_id
     where c.status = 'active' and li.status = 'active'
       and cm.status = 'active' and a.status = 'active'
       and (li.start_at is null or li.start_at <= now())
       and (li.end_at   is null or li.end_at   >= now())
       and a.is_house = true
       and li.cpva_bid_micros = 0 and li.cpc_bid_micros = 0
     order by random()
     limit 1;
  else
    -- *** REAL PUBLISHER PATH *** (Efraimidis-Spirakis weighted reservoir; VERBATIM)
    select creative_id, line_item_id, line, dest_url, label, cpva_bid_micros, cpc_bid_micros,
           advertiser_id, billing_mode
      into v_creative
      from (
        with candidates as (
          select
            c.id as creative_id, c.line_item_id, c.line, c.dest_url, c.label,
            li.cpva_bid_micros, li.cpc_bid_micros, a.id as advertiser_id, a.billing_mode,
            li.weight, (random() ^ (1.0 / greatest(li.weight, 1))) as score
          from public.creatives c
          join public.line_items li  on li.id = c.line_item_id
          join public.campaigns  cm  on cm.id = li.campaign_id
          join public.advertisers a  on a.id  = cm.advertiser_id
          left join public.serve_counters sc
            on sc.publisher_id = v_pub and sc.line_item_id = li.id and sc.day = current_date
          left join public.line_item_daily_stats lid
            on lid.line_item_id = li.id and lid.day = current_date
          where c.status = 'active' and li.status = 'active'
            and cm.status = 'active' and a.status = 'active'
            and (li.start_at is null or li.start_at <= now())
            and (li.end_at   is null or li.end_at   >= now())
            and (li.targeting = '{}'::jsonb or li.targeting is null)
            and (li.frequency_cap_per_day is null
                 or coalesce(sc.served, 0) < li.frequency_cap_per_day)
            and (li.budget_daily_micros is null
                 or (case li.pacing_mode
                       when 'asap' then coalesce(lid.spent_micros, 0) < li.budget_daily_micros
                       when 'even' then coalesce(lid.spent_micros, 0) < li.budget_daily_micros *
                         least(1.0,
                           extract(epoch from (now() - date_trunc('day', now()::timestamptz)))
                           / 86400.0 + 0.1)
                       else true end))
            -- total budget guard: cumulative LIFETIME spend, counting only CLOSED (provisional +
            -- cleared) impressions. This is a SOFT cap — see the trailing COMMENT ON FUNCTION (A12).
            and (li.budget_total_micros is null
                 or (select coalesce(sum(i.gross_micros), 0)
                       from public.impressions i
                      where i.line_item_id = li.id
                        and i.state in ('provisional', 'cleared')) < li.budget_total_micros)
            and not exists (
              select 1 from public.advertiser_users au
              join public.publishers p on p.auth_user_id = au.auth_user_id
              where au.advertiser_id = a.id and p.id = v_pub)
            and (a.billing_mode <> 'prepay'
                 or exists (select 1 from public.advertiser_balances ab
                             where ab.advertiser_id = a.id
                               and ab.balance_micros - ab.reserved_micros
                                     >= ceil(v_dwell / 1000.0)::bigint * li.cpva_bid_micros))
        )
        select * from candidates order by score desc limit 1
      ) sub;
  end if;

  -- ----- M9 PREPAY SERVE-TIME RESERVE (VERBATIM) -----------------------------------
  v_serve := v_creative.creative_id is not null;
  if v_serve and v_creative.billing_mode = 'prepay' then
    v_reserve := ceil(v_dwell / 1000.0)::bigint * coalesce(v_creative.cpva_bid_micros, 0);
    if not app.advertiser_reserve(v_creative.advertiser_id, v_reserve) then
      v_serve   := false;
      v_reserve := 0;
    end if;
  end if;

  -- ----- SERVE COUNTERS (VERBATIM) -------------------------------------------------
  if v_serve then
    insert into public.serve_counters(publisher_id, line_item_id, day, served)
      values (v_pub, v_creative.line_item_id, current_date, 1)
      on conflict (publisher_id, line_item_id, day) do update
        set served = serve_counters.served + 1;
    insert into public.line_item_daily_stats(line_item_id, day, spent_micros)
      values (v_creative.line_item_id, current_date, 0)
      on conflict (line_item_id, day) do nothing;
  end if;

  -- ----- AD_WINDOWS INSERT ---------------------------------------------------------
  -- (B4) click_token_hash = p_click_token_hash (edge-minted); (ip) ip_hash = p_client_ip_hash.
  v_clearing := case when v_serve then coalesce(v_creative.cpva_bid_micros, 0) else 0 end;

  insert into public.ad_windows(
      publisher_id, device_id, line_item_id, creative_id, challenge, nonce,
      prev_hash, click_token_hash, dwell_ms, hb_interval_ms, state, clearing_price_micros,
      reserve_micros, ip_hash)
    values (
      v_pub, v_dev,
      case when v_serve then v_creative.line_item_id else null end,
      case when v_serve then v_creative.creative_id  else null end,
      v_challenge, v_nonce,
      null,
      p_click_token_hash,                 -- (B4) edge-minted hash; NULL => window is not clickable
      v_dwell, v_hb, 'open', v_clearing,
      v_reserve, p_client_ip_hash)        -- (ip)
    returning window_id into v_window_id;

  return jsonb_build_object(
    'window_id', v_window_id,
    'challenge', v_challenge,
    'nonce', v_nonce,
    'dwell_ms', v_dwell,
    'hb_interval_ms', v_hb,
    -- (B4) 'click_token' REMOVED — never returned to the caller.
    'ad', case when v_serve
      then jsonb_build_object('line', v_creative.line, 'label', v_creative.label,
                              'has_dest', v_creative.dest_url is not null)
      else jsonb_build_object('house', true) end
  );
end;
$$;
revoke execute on function public.window_open(text, text, text) from public, anon;
grant  execute on function public.window_open(text, text, text) to authenticated, service_role;

-- (A12) DOCUMENT the residual soft-cap. budget_total_micros sums only CLOSED impressions, so
-- concurrent opens can overshoot; bounded per device by the B2 concurrency cap, and PREPAY advertisers
-- are HARD-protected by the backed serve-time app.advertiser_reserve() balance hold.
comment on function public.window_open(text, text, text) is
  'Serving + per-tick reserve. B2: in-DB per-device velocity + concurrency caps (the real fraud gate; '
  'the edge RL is bypassable) — sentinel publisher EXEMPT. B4: no longer mints/returns a click token '
  '(the edge mints it into the signed adData; only its hash is stored). Stamps a salted IP hash for IVT. '
  'A12: budget_total_micros is a SOFT lifetime cap — it sums only CLOSED (provisional/cleared) '
  'impressions, so concurrent opens can overshoot by up to (in-flight-1) impressions; bounded per device '
  'by the concurrency cap; PREPAY advertisers are HARD-protected by the backed serve-time '
  'app.advertiser_reserve() balance hold; POSTPAY budget_total is soft by design (final charge reflects '
  'actual cleared delivery).';

-- ---------------------------------------------------------------------------
-- B1/B3 honesty: correct the DB-object semantics of the heartbeat chain. The per-window `challenge` IS
-- the HMAC key and is handed to the client, so the chain is NOT an anti-forgery / attention proof
-- against the PUBLISHER (who holds the key) — it only SEQUENCES beats and makes THIRD-PARTY tamper
-- evident. The real anti-farm gate is server-side: in-DB velocity/concurrency caps (window_open) +
-- scan_ivt (per device/IP) + the 72h clawback. window_beat itself is UNCHANGED.
comment on function public.window_beat(uuid, integer, text, text) is
  'Extends the per-window heartbeat hash-chain. NOTE: the chain SEQUENCES beats and is third-party '
  'tamper-evident ONLY — the per-window challenge is the HMAC key and is shared with the client, so '
  'the chain is NOT proof of attention against the publisher. Anti-farm enforcement lives in '
  'window_open velocity/concurrency caps + scan_ivt + the 72h clawback, not here.';

-- Migration-tail assertion — anon holds NO EXECUTE on the recreated serving RPC.
do $$
begin
  if has_function_privilege('anon', 'public.window_open(text, text, text)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.window_open — REVOKE ... FROM public, anon missing';
  end if;
end $$;
