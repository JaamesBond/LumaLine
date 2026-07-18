-- lumaline M9-T3 — advertiser serving guard rails: the PER-TICK BILLING HOT PATH.
--
-- This is the highest-blast-radius migration of the advertiser portal: it patches the three
-- functions that decide what serves and what bills — window_open (per-tick serve + reserve),
-- close_window (per-tick settle + reserve true-up) and sweep_stale_windows (stranded-hold GC) —
-- plus the structural CPVA-only + min-bid CHECK on line_items. A bug here bills wrong or breaks
-- serving, so EVERY existing behavior is preserved and ONLY guarded prepay/self-deal/sentinel
-- logic is added. clear_events + app.accrue are NOT touched (loud-fail contract preserved).
--
-- WHAT CHANGES (additive, minimal diffs over the CURRENT definitions):
--
--   1. public.check_selfserve_line_item(campaign_id, cpva, cpc)  — a STABLE SECDEF helper +
--      a CHECK constraint on line_items, symmetric to check_house_bids (sentinel_never_bills.sql
--      :49-79). For a NON-house, billing_mode='prepay' advertiser it requires cpc_bid_micros=0 AND
--      cpva_bid_micros >= app.advertiser_min_bid_micros() — so CPVA-only + the positive min-bid
--      floor hold STRUCTURALLY on the real-publisher serving path (true_total_budget_cap.sql
--      :84-157 has NO min-bid predicate), regardless of which write path (RPC / service_role /
--      future code) created the row. Legacy postpay / house / CPC line_items are UNCONSTRAINED.
--
--   2. public.window_open  (CREATE OR REPLACE of 20260702120000_true_total_budget_cap.sql —
--      the CURRENT definition — with FOUR guarded additions, everything else verbatim):
--        (a) SENTINEL candidate filter gains `and a.is_house = true` — a self-serve approved
--            non-house zero-bid creative can never leak into the anon/sentinel pool.
--        (b) REAL candidate query gains a SELF-DEAL exclusion: never serve an advertiser to a
--            publisher that shares its auth.uid() (defense beyond the provisioning refusal).
--        (c) REAL candidate query gains a PREPAY AVAILABILITY pre-filter: a prepay advertiser is
--            only eligible when AVAILABLE (balance-reserved) covers the reserve estimate; postpay
--            is untouched (soft budget cap + Stripe-PI path unchanged).
--        (d) After a PREPAY creative is chosen, take a BACKED serve-time hold via
--            app.advertiser_reserve(advertiser, estimate) under a per-advertiser row lock. If it is
--            NOT covered (a concurrent burst consumed the balance after the pre-filter), the tick
--            becomes a TRUE NO-FILL (no serve_counters, no stamped creative, reserve_micros 0) so
--            close_window never bills an unfunded impression. On a real prepay serve,
--            ad_windows.reserve_micros is stamped with the estimate (0 for postpay/house/no-fill),
--            making advertiser_balances.reserved_micros exactly reconstructable as
--            SUM(ad_windows.reserve_micros) — the BACKED-reserve money invariant.
--
--   3. public.close_window  (CREATE OR REPLACE of 20260703010000_close_window_dwell_tolerance.sql
--      — the CURRENT definition, NOT the older sentinel_never_bills.sql copy — so the edge-latency
--      dwell TOLERANCE fix (v_tolerance) is PRESERVED verbatim). Adds reserve accounting on every
--      terminal path: release the full hold + zero reserve_micros on abandon/void/house/revoked/
--      dwell-fail; on a credited window release the over-estimate (estimate-gross ≥ 0) and keep
--      reserve_micros = gross (the credited-undrawn hold) until draw-down zeroes it. Postpay/house/
--      no-fill windows carry reserve_micros = 0, so every release no-ops (delta 0) and behavior is
--      byte-identical. The is_house belt-and-suspenders gross=0 guard is preserved.
--
--   4. public.sweep_stale_windows  (CREATE OR REPLACE of clearing_and_ledger.sql:256-279): the
--      abandon path now RELEASES each stranded window's prepay reserve on the hot path (claimed
--      row-by-row with FOR UPDATE SKIP LOCKED like clear_events, so only the txn that flips
--      open->abandoned frees the hold — no double release), instead of leaving reserved_micros
--      inflated until the reconcile cron. Net effect on windows/clicks is identical.
--
-- DEPENDS ON: 20260716150000 (advertisers.billing_mode, advertiser_users, publishers self-deal
-- join), 20260716160000 (ledger enum — not referenced here), 20260716170000 (advertiser_balances,
-- ad_windows.reserve_micros, app.advertiser_reserve/_release, app.advertiser_min_bid_micros()).
--
-- CONVENTIONS: window_open/close_window/sweep_stale_windows stay SECURITY DEFINER search_path=''.
-- CREATE OR REPLACE preserves each function's existing ACL, but every REVOKE/GRANT is re-asserted
-- verbatim (the migration-secdef-lint requires a same-file REVOKE for each public SECDEF fn, and
-- the anon-EXECUTE footgun means we spell PUBLIC, anon explicitly).

-- ---------------------------------------------------------------------------
-- 1. CPVA-only + positive min-bid as a STRUCTURAL CHECK on line_items.
--
-- A CHECK constraint cannot subquery other tables, so (like check_house_bids) the cross-table
-- predicate lives in a SECURITY DEFINER helper. For a NON-house prepay advertiser: cpc must be 0
-- (CPVA-only — OSC-8 clicks are IDE-only and self-serve is view-billed) AND cpva must clear the
-- single-source floor app.advertiser_min_bid_micros(). Every other advertiser (legacy postpay,
-- house/sentinel, existing CPC) is unconstrained, so this adds NO regression to the €1.10 postpay
-- advertiser or the house rows and validates clean against all existing line_items (none are
-- non-house prepay at this migration — the self-serve create/edit RPCs land later in 190000).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.check_selfserve_line_item(
  p_campaign_id uuid, p_cpva bigint, p_cpc bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
AS $$
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM public.campaigns cm
      JOIN public.advertisers a ON a.id = cm.advertiser_id
      WHERE cm.id = p_campaign_id
        AND a.is_house = false
        AND a.billing_mode = 'prepay'
    ) THEN (p_cpc = 0 AND p_cpva >= app.advertiser_min_bid_micros())
    ELSE true
  END;
$$;
REVOKE ALL ON FUNCTION public.check_selfserve_line_item(uuid, bigint, bigint) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.check_selfserve_line_item(uuid, bigint, bigint)
  TO authenticated, service_role;

COMMENT ON FUNCTION public.check_selfserve_line_item IS
  'CHECK-constraint helper (symmetric to check_house_bids): for a NON-house billing_mode=''prepay'' advertiser require cpc=0 AND cpva >= app.advertiser_min_bid_micros(); every other advertiser is unconstrained. Makes CPVA-only + the positive min-bid floor structural on the real-publisher serving path regardless of write path.';

-- Add the constraint idempotently (ADD CONSTRAINT has no IF NOT EXISTS). Validates existing rows:
-- all current line_items are postpay/house/CPC -> the helper returns true -> validation passes.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'line_items_selfserve_bids') THEN
    ALTER TABLE public.line_items
      ADD CONSTRAINT line_items_selfserve_bids
      CHECK (public.check_selfserve_line_item(campaign_id, cpva_bid_micros, cpc_bid_micros));
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. window_open — CREATE OR REPLACE of the CURRENT definition (true_total_budget_cap.sql) with
--    the sentinel is_house fix, the self-deal exclusion, the prepay availability pre-filter, the
--    backed reserve + NULL-on-fail, and the ad_windows.reserve_micros stamp. Everything else is
--    a VERBATIM copy of 20260702120000_true_total_budget_cap.sql.
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
  -- v_creative fields: creative_id, line_item_id, line, dest_url, label, cpva_bid_micros,
  -- cpc_bid_micros, advertiser_id, billing_mode (advertiser_id/billing_mode added for the reserve).
  v_creative   record;
  v_window_id  uuid;
  v_challenge  text := encode(extensions.gen_random_bytes(16), 'hex');
  v_nonce      text := encode(extensions.gen_random_bytes(8), 'hex');
  v_token      text := encode(extensions.gen_random_bytes(24), 'hex');
  v_dwell      integer := 5000;
  v_hb         integer := 1000;
  v_clearing   bigint := 0;
  v_reserve    bigint := 0;         -- prepay serve-time hold stamped on ad_windows (0 otherwise)
  v_serve      boolean := false;    -- a REAL creative is actually served this tick (survives reserve)
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
    -- Paid-demand auth gate: the sentinel publisher ONLY receives HOUSE creatives
    -- (is_house=true AND cpva=cpc=0). The is_house predicate is the M9 fix: under self-serve an
    -- approved NON-house zero-bid creative would otherwise leak into the anon pool. order by
    -- random() is sufficient since there is typically only one self-promo creative.
    select c.id         as creative_id,
           c.line_item_id,
           c.line,
           c.dest_url,
           c.label,
           li.cpva_bid_micros,
           li.cpc_bid_micros,
           a.id          as advertiser_id,
           a.billing_mode
      into v_creative
      from public.creatives c
      join public.line_items li  on li.id = c.line_item_id
      join public.campaigns  cm  on cm.id = li.campaign_id
      join public.advertisers a  on a.id  = cm.advertiser_id
     where c.status = 'active' and li.status = 'active'
       and cm.status = 'active' and a.status = 'active'
       and (li.start_at is null or li.start_at <= now())
       and (li.end_at   is null or li.end_at   >= now())
       -- *** SENTINEL GATE: zero-cost HOUSE creatives only (M9: add is_house=true) ***
       and a.is_house = true
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
    --   • budget pacing (asap / even) + cumulative total budget
    --   • M9 self-deal exclusion: never serve an advertiser to a publisher sharing its auth.uid()
    --   • M9 prepay availability: a prepay advertiser must have AVAILABLE credit for the estimate
    select creative_id, line_item_id, line, dest_url, label, cpva_bid_micros, cpc_bid_micros,
           advertiser_id, billing_mode
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
            a.id         as advertiser_id,
            a.billing_mode,
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
            -- *** M9 SELF-DEAL EXCLUSION ***: never serve an advertiser whose org shares an
            -- auth.uid() with the viewing publisher (defense-in-depth beyond the provisioning
            -- refusal; a normal advertiser with no shared identity is unaffected).
            and not exists (
              select 1
              from public.advertiser_users au
              join public.publishers p on p.auth_user_id = au.auth_user_id
              where au.advertiser_id = a.id and p.id = v_pub
            )
            -- *** M9 PREPAY AVAILABILITY ***: a prepay advertiser is eligible only when AVAILABLE
            -- credit (balance - reserved) covers the reserve estimate = ceil(dwell_s) * cpva. This
            -- is a best-effort pre-filter; app.advertiser_reserve below is the authoritative guard.
            -- Postpay advertisers (incl. house) are UNAFFECTED (first disjunct true).
            and (
              a.billing_mode <> 'prepay'
              or exists (
                select 1 from public.advertiser_balances ab
                where ab.advertiser_id = a.id
                  and ab.balance_micros - ab.reserved_micros
                        >= ceil(v_dwell / 1000.0)::bigint * li.cpva_bid_micros
              )
            )
        )
        select * from candidates order by score desc limit 1
      ) sub;
  end if;

  -- ----- M9 PREPAY SERVE-TIME RESERVE (backed hold; fail => TRUE NO-FILL) ---------
  -- A real creative was selected iff creative_id is not null. For a PREPAY advertiser, take a
  -- serve-time hold of estimate = ceil(dwell_s) * clearing under a per-advertiser row lock
  -- (app.advertiser_reserve). If AVAILABLE cannot cover it — e.g. a concurrent burst drained the
  -- balance after the availability pre-filter above — mark this tick a NO-FILL (v_serve := false)
  -- so it falls through to the house/no-fill path BEFORE serve_counters and the ad_windows insert,
  -- exactly like a genuine no-fill: close_window never bills it and reserve_micros stays 0 (never a
  -- stamped window with no reserve backing). Postpay, house/sentinel and no-fill take NO hold.
  v_serve := v_creative.creative_id is not null;
  if v_serve and v_creative.billing_mode = 'prepay' then
    v_reserve := ceil(v_dwell / 1000.0)::bigint * coalesce(v_creative.cpva_bid_micros, 0);
    if not app.advertiser_reserve(v_creative.advertiser_id, v_reserve) then
      v_serve   := false;   -- uncovered: a true no-fill that never bills
      v_reserve := 0;
    end if;
  end if;

  -- ----- SERVE COUNTERS (frequency cap + pacing init) ----------------------------
  -- Only when a real creative is actually served (house / no-fill / failed-reserve skips counters).
  if v_serve then
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
  -- Lock the CPVA bid at serve time (clearing_price_micros). close_window uses this stored value
  -- instead of re-fetching from line_items, so a later bid change cannot retroactively alter an
  -- already-served impression. A failed-reserve tick serves nothing (v_serve=false): line_item_id/
  -- creative_id/clearing/reserve all null-or-zero, so it is a true no-fill.
  v_clearing := case when v_serve then coalesce(v_creative.cpva_bid_micros, 0) else 0 end;

  insert into public.ad_windows(
      publisher_id, device_id, line_item_id, creative_id, challenge, nonce,
      prev_hash, click_token_hash, dwell_ms, hb_interval_ms, state, clearing_price_micros,
      reserve_micros)
    values (
      v_pub, v_dev,
      case when v_serve then v_creative.line_item_id else null end,
      case when v_serve then v_creative.creative_id  else null end,
      v_challenge, v_nonce,
      null,
      encode(extensions.digest(v_token, 'sha256'), 'hex'),
      v_dwell, v_hb, 'open', v_clearing,
      v_reserve)
    returning window_id into v_window_id;

  return jsonb_build_object(
    'window_id', v_window_id,
    'challenge', v_challenge,
    'nonce', v_nonce,
    'dwell_ms', v_dwell,
    'hb_interval_ms', v_hb,
    'click_token', v_token,
    'ad', case when v_serve
      then jsonb_build_object(
        'line',     v_creative.line,
        'label',    v_creative.label,
        'has_dest', v_creative.dest_url is not null)
      else jsonb_build_object('house', true) end
  );
end;
$$;
revoke execute on function public.window_open(text) from public, anon;
grant execute on function public.window_open(text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 3. close_window — CREATE OR REPLACE of the CURRENT definition
--    (20260703010000_close_window_dwell_tolerance.sql, which carries BOTH the is_house
--    belt-and-suspenders gross=0 guard AND the edge-latency dwell TOLERANCE fix). Both are
--    preserved VERBATIM. The ONLY additions are prepay reserve accounting: resolve the window's
--    advertiser (only when it holds a reserve), release the full hold + zero reserve_micros on
--    every abandon/void/house terminal path, and on a credited window release the over-estimate
--    (estimate-gross) while keeping reserve_micros = gross until draw-down zeroes it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.close_window(p_window_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_pub       uuid := nullif(app.jwt_claim('publisher_id'), '')::uuid;
  w           public.ad_windows;
  v_elapsed   numeric;
  v_att       integer;
  v_gross     bigint := 0;
  v_adv       uuid;          -- advertiser holding this window's prepay reserve (NULL if none)
  -- Slack for edge round-trip latency between the client's dwell-start and the server's
  -- started_at stamp. 1000ms comfortably covers the observed shortfall; the beat + activity
  -- gates remain the real attention proof.
  v_tolerance integer := 1000;
BEGIN
  SELECT * INTO w FROM public.ad_windows WHERE window_id = p_window_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'unknown window');
  END IF;
  IF v_pub IS NULL OR w.publisher_id <> v_pub THEN
    RAISE EXCEPTION 'not your window' USING ERRCODE = '28000';
  END IF;
  IF w.state <> 'open' THEN   -- idempotent: already closed/credited/abandoned (reserve already handled)
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already closed');
  END IF;

  -- Resolve the advertiser holding this window's prepay reserve. ONLY when there is one — postpay/
  -- house/no-fill windows carry reserve_micros = 0, so the hot path skips this lookup and every
  -- app.advertiser_release(v_adv, ...) below no-ops on delta 0 (v_adv stays NULL, never used).
  IF w.reserve_micros > 0 THEN
    SELECT c.advertiser_id INTO v_adv
      FROM public.line_items li
      JOIN public.campaigns c ON c.id = li.campaign_id
     WHERE li.id = w.line_item_id;
  END IF;

  -- Instant revocation: a device revoked after open cannot collect an impression.
  PERFORM 1 FROM public.devices d WHERE d.id = w.device_id AND d.revoked_at IS NULL;
  IF NOT FOUND THEN
    PERFORM app.advertiser_release(v_adv, w.reserve_micros);
    UPDATE public.ad_windows SET state = 'abandoned', reserve_micros = 0 WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'device revoked');
  END IF;

  -- Dwell quality gates.
  IF w.beats_count < 3 THEN
    PERFORM app.advertiser_release(v_adv, w.reserve_micros);
    UPDATE public.ad_windows SET state = 'abandoned', reserve_micros = 0 WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', format('too few beats (%s)', w.beats_count));
  END IF;
  IF NOT w.activity_progress THEN
    PERFORM app.advertiser_release(v_adv, w.reserve_micros);
    UPDATE public.ad_windows SET state = 'abandoned', reserve_micros = 0 WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'no activity progress');
  END IF;
  v_elapsed := EXTRACT(EPOCH FROM (NOW() - w.started_at)) * 1000;
  IF v_elapsed < w.dwell_ms - v_tolerance THEN
    PERFORM app.advertiser_release(v_adv, w.reserve_micros);
    UPDATE public.ad_windows SET state = 'abandoned', reserve_micros = 0 WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'dwell too short');
  END IF;

  v_att := round(least(v_elapsed, w.dwell_ms) / 1000.0);

  -- House / no-fill: a valid dwell with no booked creative is recorded void, never billed.
  -- (reserve_micros is 0 here by construction — no-fill/house never stamps a hold — so the release
  --  is a defensive no-op that keeps the invariant reserve_micros == 0 on void windows explicit.)
  IF w.creative_id IS NULL THEN
    PERFORM app.advertiser_release(v_adv, w.reserve_micros);
    UPDATE public.ad_windows SET state = 'void', reserve_micros = 0 WHERE window_id = p_window_id;
    INSERT INTO public.impressions(window_id, publisher_id, line_item_id, creative_id,
        attention_seconds, gross_micros, state)
      VALUES (w.window_id, w.publisher_id, NULL, NULL, v_att, 0, 'void')
      ON CONFLICT (window_id) DO NOTHING;
    RETURN jsonb_build_object('credited', false, 'attention_seconds', v_att, 'gross_micros', 0, 'reason', 'house');
  END IF;

  -- Use the bid locked at serve time (clearing_price_micros), NOT the current line_items bid.
  -- This preserves the reserve-floor invariant: the price was fixed when the ad was served
  -- and cannot be retroactively changed by a bid update on the line_item.
  v_gross := v_att * w.clearing_price_micros;   -- CPVA: micros per attention-second

  -- Belt-and-suspenders: if this window's line_item belongs to a house advertiser,
  -- zero the gross regardless of what clearing_price_micros says. The CHECK constraint
  -- on line_items should have prevented a non-zero bid from being stored, but billing
  -- is the last line of defence for the trust invariant.
  PERFORM 1
    FROM public.line_items li
    JOIN public.campaigns cm ON cm.id = li.campaign_id
    JOIN public.advertisers a ON a.id = cm.advertiser_id
    WHERE li.id = w.line_item_id AND a.is_house = true;
  IF FOUND THEN
    v_gross := 0;  -- structural: house impression never accrues, ever
  END IF;

  INSERT INTO public.impressions(window_id, publisher_id, line_item_id, creative_id,
      attention_seconds, gross_micros, state)
    VALUES (w.window_id, w.publisher_id, w.line_item_id, w.creative_id, v_att, v_gross, 'provisional')
    ON CONFLICT (window_id) DO NOTHING;
  IF NOT FOUND THEN
    -- Row already existed (concurrent/replayed close): do not re-credit AND do not re-release the
    -- reserve (the winning close already trued it up).
    UPDATE public.ad_windows SET state = 'credited' WHERE window_id = p_window_id;
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already credited');
  END IF;

  -- M9 prepay reserve TRUE-UP (genuine credit only): release the over-estimate (estimate - gross ≥ 0
  -- since v_att ≤ dwell_s) and keep reserve_micros = gross as the credited-undrawn hold until
  -- draw-down zeroes it. reserve_micros > 0 ⟹ a prepay window; postpay/house never enter this block.
  IF w.reserve_micros > 0 THEN
    PERFORM app.advertiser_release(v_adv, w.reserve_micros - v_gross);
  END IF;

  UPDATE public.ad_windows
     SET state = 'credited',
         reserve_micros = CASE WHEN w.reserve_micros > 0 THEN v_gross ELSE reserve_micros END
   WHERE window_id = p_window_id;

  -- Track spend in line_item_daily_stats for budget pacing (paid impressions only).
  -- This row was initialized to 0 at window_open; here we add the actual gross.
  IF v_gross > 0 THEN
    INSERT INTO public.line_item_daily_stats(line_item_id, day, spent_micros)
      VALUES (w.line_item_id, w.started_at::date, v_gross)
      ON CONFLICT (line_item_id, day) DO UPDATE
        SET spent_micros = line_item_daily_stats.spent_micros + excluded.spent_micros;
  END IF;

  RETURN jsonb_build_object('credited', true, 'attention_seconds', v_att,
    'gross_micros', v_gross, 'reason', 'ok');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.close_window(uuid) FROM public, anon;
GRANT EXECUTE ON FUNCTION public.close_window(uuid) TO authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 4. sweep_stale_windows — CREATE OR REPLACE of clearing_and_ledger.sql:256-279. The abandon
--    path now RELEASES each stranded window's prepay reserve on the hot path so reserved_micros
--    cannot inflate with every crashed/never-closed session until the reconcile cron runs. Claims
--    each window row-by-row with FOR UPDATE SKIP LOCKED + a guarded open->abandoned transition
--    (the clear_events idiom), so only the txn that actually abandons a window frees its hold —
--    no double release vs a concurrent close_window, and no contention on locked rows. The
--    windows-abandoned / clicks-voided outcome is identical to the original bulk sweep.
-- ---------------------------------------------------------------------------
create or replace function public.sweep_stale_windows(p_older interval default interval '10 minutes')
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_win integer := 0;
  v_clk integer := 0;
  r     record;
  v_adv uuid;
begin
  for r in
    select w.window_id, w.line_item_id, w.reserve_micros
      from public.ad_windows w
     where w.state = 'open' and w.started_at < now() - p_older
     for update of w skip locked
  loop
    -- Guarded transition: only the txn that actually flips open->abandoned counts + releases.
    update public.ad_windows set state = 'abandoned', reserve_micros = 0
     where window_id = r.window_id and state = 'open';
    if not found then continue; end if;
    v_win := v_win + 1;

    -- Free any prepay hold this stranded window carried (no-op for postpay/house = 0).
    if r.reserve_micros > 0 then
      select c.advertiser_id into v_adv
        from public.line_items li
        join public.campaigns c on c.id = li.campaign_id
       where li.id = r.line_item_id;
      perform app.advertiser_release(v_adv, r.reserve_micros);
    end if;
  end loop;

  update public.clicks set state = 'void', gross_micros = 0
   where state = 'provisional'
     and window_id in (select window_id from public.ad_windows where state = 'abandoned');
  get diagnostics v_clk = row_count;

  return jsonb_build_object('windows_abandoned', v_win, 'clicks_voided', v_clk);
end;
$$;
revoke execute on function public.sweep_stale_windows(interval) from public, anon, authenticated;
grant execute on function public.sweep_stale_windows(interval) to service_role;
