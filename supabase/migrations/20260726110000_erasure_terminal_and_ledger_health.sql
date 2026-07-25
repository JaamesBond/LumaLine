-- lumaline GDPR Phase 2 fix-round — erasure is terminal + ledger-health accrual identity survives
-- an opt-in credit write-off.
--
-- THREE independent defects found reviewing 20260726100000_advertiser_erasure_split.sql:
--
-- A. REGRESSION (this branch caused it). admin_ledger_health() (20260716110000:70-72) sums ALL
--    cleared platform_revenue with no event_type filter, on the then-true assumption that only
--    accruals ever book that account. advertiser_writeoff_credit() now books platform_revenue too,
--    while the other two legs of the identity ARE filtered to ('cpva_accrual','cpc_accrual') — so
--    one write-off makes accrual_identity_ok permanently false on the owner dashboard, reading as
--    ledger corruption. Fixed by filtering the third leg the same way.
--
-- B. ERASURE WAS NOT TERMINAL. app.advertiser_gdpr_erase pauses campaigns/line_items but leaves
--    advertisers.status = 'active' and keeps the advertiser_users mappings, and NOTHING checked
--    deleted_at at serve time. A still-mapped member could therefore call the self-serve status
--    RPCs, flip everything back to 'active', and spend the residual credit of an erased account.
--    Fixed at BOTH layers: window_open refuses structurally (the load-bearing one — it holds even
--    if a row is flipped directly in the DB), and the two self-serve status RPCs refuse resume.
--
-- C/D. Documentation: ToS §7/§9 contradicted §3.1 on when credit is forfeited (fixed in
--    docs/legal/advertiser-tos.md), and two comments in 20260726100000 went stale.
--
-- Every function below is a byte-verbatim copy of its CURRENT live definition with ONLY the
-- delta described in its own section. Signatures are unchanged, so CREATE OR REPLACE already
-- preserves each function's ACL; the REVOKE/GRANT pairs are nonetheless re-declared BYTE-FOR-BYTE
-- from the defining migration, because test/migration-secdef-lint.test.mjs requires a same-file
-- REVOKE for every SECURITY DEFINER function (the secdef_grant_hardening footgun that once reached
-- prod). Re-declaring an identical ACL is idempotent — the same thing A9 did when it recreated
-- these exact functions. The migration tail then asserts anon really has no EXECUTE.

-- ---------------------------------------------------------------------------------------------
-- A. public.admin_ledger_health() — VERBATIM from 20260716110000:30-98; the ONLY change is the
--    event_type filter on the platform_revenue leg (+ the now-false comment above it).
-- ---------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.admin_ledger_health()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v jsonb;
BEGIN
  -- The real gate: re-check admin membership in-body on every call (RAISE 28000 = 403 over
  -- the Data API). The GRANT to authenticated only lets the request reach this line.
  IF NOT (SELECT app.is_admin()) THEN
    RAISE EXCEPTION 'unauthorized' USING errcode = '28000';
  END IF;

  SELECT jsonb_build_object(
    -- Zero-sum: every committed group balances, so the global signed sum is always 0.
    'global_sum_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.ledger_entries), 0),
    -- HAVING expressiveness: count groups whose legs do NOT sum to 0 (expect 0).
    'unbalanced_group_count',
      (SELECT count(*) FROM (
         SELECT entry_group_id
         FROM public.ledger_entries
         GROUP BY entry_group_id
         HAVING sum(amount_micros) <> 0
       ) g),
    -- Cleared accrual receivable from advertisers (+, event_type = the two accrual kinds).
    'cleared_advertiser_billing_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'advertiser_billing' AND state = 'cleared'
                  AND event_type IN ('cpva_accrual', 'cpc_accrual')), 0),
    -- Cleared owed-to-publishers (negated to a positive magnitude).
    'cleared_publisher_earnings_micros',
      COALESCE((SELECT -sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'publisher_earnings' AND state = 'cleared'
                  AND event_type IN ('cpva_accrual', 'cpc_accrual')), 0),
    -- Cleared platform take (negated). platform_revenue is NO LONGER accrual-only: the opt-in
    -- credit write-off (public.advertiser_writeoff_credit, 20260726100000) also books a
    -- platform_revenue leg (event_type = 'advertiser_adjustment'). That recognition is real
    -- revenue but it is NOT an accrual, so it is deliberately EXCLUDED here — the identity below
    -- is the CLEARED-ACCRUAL identity (advertiser_billing = publisher_earnings + platform_revenue)
    -- and the other two legs are already filtered to the same two event kinds. Without this
    -- filter a single write-off inflates one side forever and accrual_identity_ok reads false,
    -- which on the owner dashboard is indistinguishable from ledger corruption.
    'cleared_platform_revenue_micros',
      COALESCE((SELECT -sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'platform_revenue' AND state = 'cleared'
                  AND event_type IN ('cpva_accrual', 'cpc_accrual')), 0),
    -- Provisional receivable still inside the 72h clawback window.
    'provisional_advertiser_billing_micros',
      COALESCE((SELECT sum(amount_micros) FROM public.ledger_entries
                WHERE account = 'advertiser_billing' AND state = 'provisional'), 0),
    -- Reversed (clawed-back) publisher earnings, ever (negated to a positive magnitude).
    'reversed_publisher_earnings_micros',
      COALESCE((SELECT -sum(amount_micros) FROM public.ledger_entries
                WHERE state = 'reversed' AND account = 'publisher_earnings'), 0)
  ) INTO v;

  -- Derived transparency booleans / ratio, computed from the aggregate above.
  RETURN v || jsonb_build_object(
    'zero_sum_ok',
      (v->>'global_sum_micros')::bigint = 0 AND (v->>'unbalanced_group_count')::int = 0,
    'accrual_identity_ok',
      (v->>'cleared_advertiser_billing_micros')::bigint
        = (v->>'cleared_publisher_earnings_micros')::bigint
        + (v->>'cleared_platform_revenue_micros')::bigint,
    'publisher_split_bps',
      CASE WHEN (v->>'cleared_advertiser_billing_micros')::bigint > 0
           THEN round((v->>'cleared_publisher_earnings_micros')::numeric
                      / (v->>'cleared_advertiser_billing_micros')::numeric * 10000)::int
           ELSE NULL END
  );
END;
$$;

REVOKE ALL     ON FUNCTION public.admin_ledger_health() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.admin_ledger_health() TO authenticated;

COMMENT ON FUNCTION public.admin_ledger_health IS
  'Admin-only global ledger-health aggregate for the owner-dashboard Overview: {global_sum_micros, unbalanced_group_count, cleared/provisional/reversed totals, zero_sum_ok, accrual_identity_ok, publisher_split_bps}. First-line app.is_admin() RAISE 28000; STABLE; reads only public.ledger_entries. All three legs of the cleared-accrual identity are filtered to event_type IN (cpva_accrual, cpc_accrual): platform_revenue is also booked by the opt-in credit write-off (advertiser_writeoff_credit), which is real revenue but not an accrual and must not skew the identity. Rationale: aggregate/HAVING expressiveness + fewer rows, not a PII fix (ledger_entries has no email/IP/cost/token).';

-- ---------------------------------------------------------------------------------------------
-- B1. public.window_open(text, text, text) — VERBATIM from 20260722200000:159-362 (the live pass-2
--     definition), plus EXACTLY ONE predicate: "and a.deleted_at is null" in the real-publisher
--     candidates CTE, alongside the A9 dispute-hold guard.
--
--     Added to that candidate block ONLY, following the precedent A9 set for dispute_hold_at: the
--     other advertiser-joining block is the sentinel/anonymous path, which serves is_house
--     advertisers exclusively, and app.advertiser_gdpr_erase refuses the house advertiser outright
--     ('house_advertiser') — so a house advertiser can never carry deleted_at. Gating it there
--     would be dead code on the per-tick serving hot path.
-- ---------------------------------------------------------------------------------------------
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
            and a.dispute_hold_at is null   -- *** A9: never serve a dispute-held advertiser ***
            and a.deleted_at is null        -- *** GDPR P2: never serve an ERASED advertiser ***
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

comment on function public.window_open(text, text, text) is
  'Serving + per-tick reserve. B2: in-DB per-device velocity + concurrency caps (the real fraud gate; '
  'the edge RL is bypassable) — sentinel publisher EXEMPT. B4: no longer mints/returns a click token '
  '(the edge mints it into the signed adData; only its hash is stored). Stamps a salted IP hash for IVT. '
  'A9: the real-publisher serve path excludes any advertiser with dispute_hold_at set (postpay chargeback). '
  'GDPR P2: it also excludes any advertiser with deleted_at set — erasure is terminal, and this is the '
  'structural enforcement (it holds even if campaigns/line_items are flipped back to active directly). '
  'A12: budget_total_micros is a SOFT lifetime cap — it sums only CLOSED (provisional/cleared) '
  'impressions, so concurrent opens can overshoot by up to (in-flight-1) impressions; bounded per device '
  'by the concurrency cap; PREPAY advertisers are HARD-protected by the backed serve-time '
  'app.advertiser_reserve() balance hold; POSTPAY budget_total is soft by design (final charge reflects '
  'actual cleared delivery).';

-- ---------------------------------------------------------------------------------------------
-- B2. The self-serve status RPCs — VERBATIM from 20260722200000:382-415 / 422-455 (the live
--     definitions; 20260716190000 was superseded by A9), plus the erased-account resume refusal.
--     These functions signal refusal by RAISE ... USING errcode = '55000' (not {ok,reason}), so
--     the new guard matches that contract exactly and carries account_deleted in its message.
-- ---------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.advertiser_set_line_item_status(p_id uuid, p_target text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv     uuid;
  v_current public.line_item_status;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;
  IF p_target NOT IN ('active', 'paused') THEN
    RAISE EXCEPTION 'line item status target must be active or paused' USING errcode = '22023';
  END IF;

  PERFORM app.assert_owns_line_item(p_id);   -- ownership FIRST

  -- *** A9: a dispute-held advertiser cannot resume serving; only admin clears the hold. ***
  IF p_target = 'active'
     AND EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND dispute_hold_at IS NOT NULL) THEN
    RAISE EXCEPTION 'advertiser is on dispute hold; contact support' USING errcode = '55000';
  END IF;

  -- *** GDPR P2: erasure is TERMINAL — an erased advertiser can never resume serving. ***
  -- Same shape/precedence as the A9 hold above (resume-only; pausing an already-stopped org is
  -- harmless and must stay reachable). window_open enforces the same rule structurally.
  IF p_target = 'active'
     AND EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; serving cannot be resumed'
      USING errcode = '55000';
  END IF;

  SELECT status INTO v_current FROM public.line_items WHERE id = p_id;
  IF v_current NOT IN ('active', 'paused') THEN
    RAISE EXCEPTION 'line item must be active or paused to toggle (is %)', v_current
      USING errcode = '55000';
  END IF;

  UPDATE public.line_items SET status = p_target::public.line_item_status WHERE id = p_id;
  RETURN jsonb_build_object('line_item_id', p_id, 'status', p_target);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_set_line_item_status(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_set_line_item_status(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_set_line_item_status IS
  'Self-serve pause/resume of the caller''s own line_item (assert_owns_line_item FIRST); active<->paused only. Pausing stops serving instantly (window_open needs active). A9: refuses resume while the advertiser is dispute-held. GDPR P2: refuses resume once the advertiser is erased (deleted_at set) — erasure is terminal. SECDEF; authenticated.';

CREATE OR REPLACE FUNCTION public.advertiser_set_campaign_status(p_id uuid, p_target text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv     uuid;
  v_current public.campaign_status;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;
  IF p_target NOT IN ('active', 'paused') THEN
    RAISE EXCEPTION 'campaign status target must be active or paused' USING errcode = '22023';
  END IF;

  PERFORM app.assert_owns_campaign(p_id);   -- ownership FIRST

  -- *** A9: a dispute-held advertiser cannot resume serving; only admin clears the hold. ***
  IF p_target = 'active'
     AND EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND dispute_hold_at IS NOT NULL) THEN
    RAISE EXCEPTION 'advertiser is on dispute hold; contact support' USING errcode = '55000';
  END IF;

  -- *** GDPR P2: erasure is TERMINAL — an erased advertiser can never resume serving. ***
  -- Same shape/precedence as the A9 hold above (resume-only; pausing an already-stopped org is
  -- harmless and must stay reachable). window_open enforces the same rule structurally.
  IF p_target = 'active'
     AND EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; serving cannot be resumed'
      USING errcode = '55000';
  END IF;

  SELECT status INTO v_current FROM public.campaigns WHERE id = p_id;
  IF v_current NOT IN ('active', 'paused') THEN
    RAISE EXCEPTION 'campaign must be active or paused to toggle (is %)', v_current
      USING errcode = '55000';
  END IF;

  UPDATE public.campaigns SET status = p_target::public.campaign_status WHERE id = p_id;
  RETURN jsonb_build_object('campaign_id', p_id, 'status', p_target);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_set_campaign_status(uuid, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_set_campaign_status(uuid, text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_set_campaign_status IS
  'Self-serve pause/resume of the caller''s own campaign (assert_owns_campaign FIRST); active<->paused only (draft→active is admin-approval-driven). A9: refuses resume while the advertiser is dispute-held. GDPR P2: refuses resume once the advertiser is erased (deleted_at set) — erasure is terminal. SECDEF; authenticated.';

-- ---------------------------------------------------------------------------------------------
-- Migration-tail privilege assertion: CREATE OR REPLACE preserves the ACL, so anon must still be
-- absent from every one of these. Asserting is free; the anon-EXECUTE footgun reached prod once.
-- ---------------------------------------------------------------------------------------------
do $$
declare v_fn text; v_fns text[] := array[
  'public.admin_ledger_health()',
  'public.window_open(text, text, text)',
  'public.advertiser_set_line_item_status(uuid, text)',
  'public.advertiser_set_campaign_status(uuid, text)'
];
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — CREATE OR REPLACE did not preserve the revoke', v_fn;
    end if;
  end loop;
end $$;
