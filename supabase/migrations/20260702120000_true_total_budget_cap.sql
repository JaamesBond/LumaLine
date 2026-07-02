-- lumaline — true cumulative total-budget cap.
-- Replaces window_open's approximate total-budget guard (which compared budget_total_micros
-- against TODAY's daily-stats spend) with a cumulative sum across all days. Everything else in
-- window_open is unchanged. Source of truth for the copied body: 20260629020000_serving_algorithm.sql.
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
            -- total budget guard: cumulative LIFETIME spend, counting only VALID (non-clawed-back)
            -- delivery. Sums impressions.gross_micros in billable states (provisional + cleared), so
            -- clawed-back/reversed spend is NOT charged against the budget — a refunded flight regains
            -- its budget and keeps delivering. (void impressions have gross 0.) Matches the CPVA-only
            -- semantics of the prior spent_micros accumulator, minus clawbacks. Indexed by
            -- impressions_line_item_id_idx (20260627022224).
            and (
              li.budget_total_micros is null
              or (
                select coalesce(sum(i.gross_micros), 0)
                from public.impressions i
                where i.line_item_id = li.id
                  and i.state in ('provisional', 'cleared')
              ) < li.budget_total_micros
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
