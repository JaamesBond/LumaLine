-- lumaline M2-T1 — weighted rotation + reserve-floor + paid-demand sentinel gate.
--
-- Replaces the Phase 1 placeholder `order by random()` in window_open with:
--   1. A sentinel guard: the "anon, never paid" publisher (sentinel UUID) ONLY receives
--      house/zero-cost creatives (cpva_bid_micros=0 AND cpc_bid_micros=0). This is
--      the core paid-demand auth gate — real money flows ONLY to authenticated,
--      non-sentinel publishers. An anonymous or revoked-device window NEVER receives
--      a gross>0 creative.
--   2. A weighted reservoir selection (Efraimidis-Spirakis) for real publishers:
--      score = random()^(1/weight), pick highest — statistically correct weighted
--      sampling in one pass, with budget pacing + frequency cap filters.
--   3. clearing_price_micros locked at serve time: close_window uses the locked price
--      rather than re-fetching from line_items, so a mid-flight bid change cannot
--      retroactively alter an in-flight window.
--   4. serve_counters incremented at window_open (drives frequency cap in future calls).
--   5. line_item_daily_stats.spent_micros incremented at close_window (drives budget pacing).
--
-- SENTINEL UUID: '5e470000-0000-4000-8000-0000000000b1' — matches seed.prod.sql and the
-- LUMALINE_SENTINEL_PUBLISHER_ID env var used by the lumaline-feed edge function.
-- This constant is the ONLY hard-coded UUID in our serving logic; the edge function uses
-- the same value from its environment so they stay in sync.

-- ---------------------------------------------------------------------------
-- Add clearing_price_micros to ad_windows (lock CPVA bid at serve time)
-- ---------------------------------------------------------------------------
alter table public.ad_windows
  add column if not exists clearing_price_micros bigint not null default 0;

-- ---------------------------------------------------------------------------
-- window_open — sentinel gate + weighted rotation
-- Replaces the Phase 1 placeholder (order by random()) with:
--   * Sentinel path: cpva=cpc=0 house creatives only; random() is fine (only one).
--   * Real publisher path: Efraimidis-Spirakis weighted reservoir sampling with
--     budget pacing (asap/even) + frequency cap + targeting + date-range filters.
-- ---------------------------------------------------------------------------
create or replace function public.window_open(p_activity_snapshot text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  -- Sentinel = the shared "anon, never paid" publisher baked into seed.prod.sql and the
  -- lumaline-feed edge function. Any window opened under this identity is house-only.
  SENTINEL_PUB constant uuid := '5e470000-0000-4000-8000-0000000000b1';

  v_pub        uuid := nullif(app.jwt_claim('publisher_id'), '')::uuid;
  v_dev        uuid := nullif(app.jwt_claim('device_id'), '')::uuid;
  v_creative   record;           -- fields: creative_id, line_item_id, line, dest_url, label, cpva_bid_micros
  v_window_id  uuid;
  v_challenge  text := encode(extensions.gen_random_bytes(16), 'hex');
  v_nonce      text := encode(extensions.gen_random_bytes(8), 'hex');
  v_token      text := encode(extensions.gen_random_bytes(24), 'hex');
  v_dwell      integer := 5000;
  v_hb         integer := 1000;
  v_clearing   bigint := 0;
begin
  -- Auth gate: both publisher_id and device_id must be present in the JWT.
  if v_pub is null or v_dev is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;

  -- Device check: also validates publisher ownership and instant revocation.
  perform 1 from public.devices d
   where d.id = v_dev and d.publisher_id = v_pub and d.revoked_at is null;
  if not found then
    raise exception 'device revoked or unknown' using errcode = '28000';
  end if;

  -- ----- SERVING ALGORITHM -------------------------------------------------------

  if v_pub = SENTINEL_PUB then
    -- *** SENTINEL / ANONYMOUS PATH ***
    -- Paid-demand auth gate: the sentinel publisher ONLY receives house creatives
    -- (cpva_bid_micros=0 AND cpc_bid_micros=0). This ensures anonymous/revoked
    -- publishers NEVER receive a gross>0 creative. order by random() is sufficient
    -- since there is typically only one self-promo creative.
    select c.id         as creative_id,
           c.line_item_id,
           c.line,
           c.dest_url,
           c.label,
           li.cpva_bid_micros,
           li.cpc_bid_micros
      into v_creative
      from public.creatives c
      join public.line_items li  on li.id = c.line_item_id
      join public.campaigns  cm  on cm.id = li.campaign_id
      join public.advertisers a  on a.id  = cm.advertiser_id
     where c.status = 'active' and li.status = 'active'
       and cm.status = 'active' and a.status = 'active'
       and (li.start_at is null or li.start_at <= now())
       and (li.end_at   is null or li.end_at   >= now())
       -- *** SENTINEL GATE: zero-cost house creatives only ***
       and li.cpva_bid_micros = 0 and li.cpc_bid_micros = 0
     order by random()
     limit 1;

  else
    -- *** REAL PUBLISHER PATH ***
    -- Weighted reservoir selection (Efraimidis-Spirakis):
    --   score = random() ^ (1 / weight)
    -- This gives statistically correct proportional selection in a single pass;
    -- an item with weight W is selected W× more often than an item with weight 1.
    --
    -- Candidate filters (all applied before scoring):
    --   • active status chain (creative, line_item, campaign, advertiser)
    --   • date window (start_at / end_at)
    --   • targeting v1: li.targeting = '{}' matches every publisher (global)
    --   • frequency cap: exclude if served >= frequency_cap_per_day today
    --   • budget pacing:
    --       asap: exclude if daily spend >= budget_daily_micros
    --       even: exclude if daily spend >= budget * (elapsed_fraction + 0.1 headroom)
    --   • total budget: exclude if all-time daily spend >= budget_total_micros
    select creative_id, line_item_id, line, dest_url, label, cpva_bid_micros, cpc_bid_micros
      into v_creative
      from (
        with candidates as (
          select
            c.id         as creative_id,
            c.line_item_id,
            c.line,
            c.dest_url,
            c.label,
            li.cpva_bid_micros,
            li.cpc_bid_micros,
            li.weight,
            -- Efraimidis-Spirakis score: items with higher weight float to the top
            (random() ^ (1.0 / greatest(li.weight, 1))) as score
          from public.creatives c
          join public.line_items li  on li.id = c.line_item_id
          join public.campaigns  cm  on cm.id = li.campaign_id
          join public.advertisers a  on a.id  = cm.advertiser_id
          -- Frequency cap counter for today (left join = 0 if not yet served)
          left join public.serve_counters sc
            on sc.publisher_id = v_pub
           and sc.line_item_id = li.id
           and sc.day = current_date
          -- Budget pacing stats for today (left join = 0 if not yet spent)
          left join public.line_item_daily_stats lid
            on lid.line_item_id = li.id
           and lid.day = current_date
          where
            c.status  = 'active' and li.status = 'active'
            and cm.status = 'active' and a.status = 'active'
            and (li.start_at is null or li.start_at <= now())
            and (li.end_at   is null or li.end_at   >= now())
            -- targeting: v1 = global (empty targeting matches every publisher)
            and (li.targeting = '{}'::jsonb or li.targeting is null)
            -- frequency cap: skip if today's serve count >= cap
            and (
              li.frequency_cap_per_day is null
              or coalesce(sc.served, 0) < li.frequency_cap_per_day
            )
            -- budget pacing per mode
            and (
              li.budget_daily_micros is null
              or (
                case li.pacing_mode
                  when 'asap' then
                    coalesce(lid.spent_micros, 0) < li.budget_daily_micros
                  when 'even' then
                    coalesce(lid.spent_micros, 0) < li.budget_daily_micros *
                      least(1.0,
                        extract(epoch from (now() - date_trunc('day', now()::timestamptz)))
                        / 86400.0 + 0.1)
                  else true
                end
              )
            )
            -- total budget guard (uses daily stats as running proxy for v1)
            and (
              li.budget_total_micros is null
              or coalesce(lid.spent_micros, 0) < li.budget_total_micros
            )
        )
        select * from candidates order by score desc limit 1
      ) sub;
  end if;

  -- ----- SERVE COUNTERS (frequency cap + pacing init) ----------------------------
  -- Only when a real creative was selected (house / no-fill skips counters).
  if v_creative.creative_id is not null then
    -- Increment frequency cap counter for today.
    insert into public.serve_counters(publisher_id, line_item_id, day, served)
      values (v_pub, v_creative.line_item_id, current_date, 1)
      on conflict (publisher_id, line_item_id, day) do update
        set served = serve_counters.served + 1;

    -- Ensure a daily-stats row exists (spend is updated later in close_window).
    insert into public.line_item_daily_stats(line_item_id, day, spent_micros)
      values (v_creative.line_item_id, current_date, 0)
      on conflict (line_item_id, day) do nothing;
  end if;

  -- ----- AD_WINDOWS INSERT -------------------------------------------------------
  -- Lock the CPVA bid at serve time (clearing_price_micros). close_window uses this
  -- stored value instead of re-fetching from line_items, so a later bid change cannot
  -- retroactively alter an already-served impression.
  v_clearing := coalesce(v_creative.cpva_bid_micros, 0);

  insert into public.ad_windows(
      publisher_id, device_id, line_item_id, creative_id, challenge, nonce,
      prev_hash, click_token_hash, dwell_ms, hb_interval_ms, state, clearing_price_micros)
    values (
      v_pub, v_dev,
      v_creative.line_item_id, v_creative.creative_id,
      v_challenge, v_nonce,
      null,
      encode(extensions.digest(v_token, 'sha256'), 'hex'),
      v_dwell, v_hb, 'open', v_clearing)
    returning window_id into v_window_id;

  return jsonb_build_object(
    'window_id', v_window_id,
    'challenge', v_challenge,
    'nonce', v_nonce,
    'dwell_ms', v_dwell,
    'hb_interval_ms', v_hb,
    'click_token', v_token,
    'ad', case when v_creative.creative_id is not null
      then jsonb_build_object(
        'line',     v_creative.line,
        'label',    v_creative.label,
        'has_dest', v_creative.dest_url is not null)
      else jsonb_build_object('house', true) end
  );
end;
$$;
revoke execute on function public.window_open(text) from public;
grant execute on function public.window_open(text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- close_window — use clearing_price_micros (locked at serve) + spend tracking.
-- Idempotent: only fires while state='open'; impressions.window_id UNIQUE is the
-- durable single-credit backstop.
-- ---------------------------------------------------------------------------
create or replace function public.close_window(p_window_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pub       uuid := nullif(app.jwt_claim('publisher_id'), '')::uuid;
  w           public.ad_windows;
  v_elapsed   numeric;
  v_att       integer;
  v_gross     bigint := 0;
begin
  select * into w from public.ad_windows where window_id = p_window_id for update;
  if not found then
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'unknown window');
  end if;
  if v_pub is null or w.publisher_id <> v_pub then
    raise exception 'not your window' using errcode = '28000';
  end if;
  if w.state <> 'open' then   -- idempotent: already closed/credited/abandoned
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already closed');
  end if;

  -- Instant revocation: a device revoked after open cannot collect an impression.
  perform 1 from public.devices d where d.id = w.device_id and d.revoked_at is null;
  if not found then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'device revoked');
  end if;

  -- Dwell quality gates.
  if w.beats_count < 3 then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', format('too few beats (%s)', w.beats_count));
  end if;
  if not w.activity_progress then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'no activity progress');
  end if;
  v_elapsed := extract(epoch from (now() - w.started_at)) * 1000;
  if v_elapsed < w.dwell_ms then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'dwell too short');
  end if;

  v_att := round(least(v_elapsed, w.dwell_ms) / 1000.0);

  -- House / no-fill: a valid dwell with no booked creative is recorded void, never billed.
  if w.creative_id is null then
    update public.ad_windows set state = 'void' where window_id = p_window_id;
    insert into public.impressions(window_id, publisher_id, line_item_id, creative_id, attention_seconds, gross_micros, state)
      values (w.window_id, w.publisher_id, null, null, v_att, 0, 'void')
      on conflict (window_id) do nothing;
    return jsonb_build_object('credited', false, 'attention_seconds', v_att, 'gross_micros', 0, 'reason', 'house');
  end if;

  -- Use the bid locked at serve time (clearing_price_micros), NOT the current line_items bid.
  -- This preserves the reserve-floor invariant: the price was fixed when the ad was served
  -- and cannot be retroactively changed by a bid update on the line_item.
  v_gross := v_att * w.clearing_price_micros;   -- CPVA: micros per attention-second

  insert into public.impressions(window_id, publisher_id, line_item_id, creative_id, attention_seconds, gross_micros, state)
    values (w.window_id, w.publisher_id, w.line_item_id, w.creative_id, v_att, v_gross, 'provisional')
    on conflict (window_id) do nothing;
  if not found then
    -- Row already existed (concurrent/replayed close): do not re-credit.
    update public.ad_windows set state = 'credited' where window_id = p_window_id;
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already credited');
  end if;

  update public.ad_windows set state = 'credited' where window_id = p_window_id;

  -- Track spend in line_item_daily_stats for budget pacing (paid impressions only).
  -- This row was initialized to 0 at window_open; here we add the actual gross.
  if v_gross > 0 then
    insert into public.line_item_daily_stats(line_item_id, day, spent_micros)
      values (w.line_item_id, w.started_at::date, v_gross)
      on conflict (line_item_id, day) do update
        set spent_micros = line_item_daily_stats.spent_micros + excluded.spent_micros;
  end if;

  return jsonb_build_object('credited', true, 'attention_seconds', v_att, 'gross_micros', v_gross, 'reason', 'ok');
end;
$$;
revoke execute on function public.close_window(uuid) from public;
grant execute on function public.close_window(uuid) to authenticated, service_role;
