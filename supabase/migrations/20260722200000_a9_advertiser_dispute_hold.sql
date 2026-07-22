-- lumaline security-audit pass-2 (Cluster P3 / A9) — advertiser dispute-hold on postpay chargeback.
-- Escalates a chargeback beyond the self-reversible line_item pause to an advertiser-level hold that
-- ONLY service_role/admin can lift, gates window_open's serve path on it, and blocks self-serve resume.
--
-- This is the SINGLE pass-2 window_open recreate (base = pass-1 20260722120000; adds ONE serve-gate
-- predicate, keeps every B2 cap + B4 click-token handling + ip_hash stamping + the M9 reserve hot path
-- verbatim). Money/PII-adjacent migration => ends with the anon-EXECUTE fail DO-block.
-- DEPENDS ON: 20260722080000 (book_postpay_chargeback), 20260722120000 (window_open pass-1 recreate),
-- 20260716190000 (advertiser self-serve status RPCs), 20260716150000 (advertisers_protect_cols),
-- 20260716140000 (app.is_money_admin + the money-admin self-lockout guard pattern).

-- ---- 1. dispute_hold_at column (non-null => held) -------------------------------------------------
alter table public.advertisers add column if not exists dispute_hold_at timestamptz;
create index if not exists advertisers_dispute_hold_idx
  on public.advertisers (dispute_hold_at) where dispute_hold_at is not null;

-- ---- 2. protect dispute_hold_at (recreate advertisers_protect_cols; add the column to the diff set) -
-- VERBATIM from 20260716150000 §8 + dispute_hold_at added to the protected-column IS DISTINCT FROM list.
CREATE OR REPLACE FUNCTION app.advertisers_protect_cols()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  -- service_role (edge fns / admin-booking) may set protected columns.
  IF COALESCE(app.jwt_claim('role'), '') = 'service_role' THEN
    RETURN NEW;
  END IF;

  IF NEW.is_house           IS DISTINCT FROM OLD.is_house
     OR NEW.status          IS DISTINCT FROM OLD.status
     OR NEW.stripe_customer_id IS DISTINCT FROM OLD.stripe_customer_id
     OR NEW.billing_mode    IS DISTINCT FROM OLD.billing_mode THEN
    RAISE EXCEPTION 'advertisers: protected column change requires service_role'
      USING errcode = '42501';
  END IF;

  -- *** A9: dispute_hold_at is protected too, but a money-admin (aal2) clears it via the authenticated
  -- admin_clear_advertiser_dispute_hold RPC (whose JWT role is 'authenticated', not service_role). Allow
  -- ONLY dispute_hold_at to change for a money-admin; every other protected column still needs
  -- service_role. is_money_admin() is only evaluated when dispute_hold_at actually changes (short-circuit).
  IF NEW.dispute_hold_at IS DISTINCT FROM OLD.dispute_hold_at
     AND NOT (SELECT app.is_money_admin()) THEN
    RAISE EXCEPTION 'advertisers: dispute_hold_at change requires service_role or money admin'
      USING errcode = '42501';
  END IF;

  RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION app.advertisers_protect_cols() FROM PUBLIC;

-- CREATE OR REPLACE FUNCTION rebinds the same trigger; re-emit it belt-and-suspenders (idempotent).
DROP TRIGGER IF EXISTS advertisers_protect_cols ON public.advertisers;
CREATE TRIGGER advertisers_protect_cols
  BEFORE UPDATE ON public.advertisers
  FOR EACH ROW EXECUTE FUNCTION app.advertisers_protect_cols();

COMMENT ON FUNCTION app.advertisers_protect_cols IS
  'BEFORE UPDATE guard: blocks a change to is_house/status/stripe_customer_id/billing_mode unless the request JWT role is service_role; dispute_hold_at may additionally be changed by a money-admin (aal2) via admin_clear_advertiser_dispute_hold. Column-diff based (a name-only update passes), so the advertiser profile RPC never trips it; the structural backstop for the protected columns (incl. the A9 dispute hold).';

-- ---- 3. book_postpay_chargeback — VERBATIM from 20260722080000 + set the advertiser hold ----------
create or replace function app.book_postpay_chargeback(
  p_payment_intent_id text, p_dispute_id text, p_amount_micros bigint, p_reason text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_group     uuid := gen_random_uuid();
  v_hit       text;
  v_adv       uuid;
  v_collected bigint;
  v_amt       bigint;
begin
  if p_payment_intent_id is null or p_payment_intent_id = ''
     or p_dispute_id is null or p_dispute_id = '' then
    raise exception 'book_postpay_chargeback: payment_intent_id + dispute_id required' using errcode = '22004';
  end if;
  if p_amount_micros is null or p_amount_micros <= 0 then
    raise exception 'book_postpay_chargeback: amount must be positive (got %)', p_amount_micros using errcode = '22003';
  end if;

  -- Resolve the paying advertiser + total collected on this PI (a postpay batch settles many
  -- entry-groups onto ONE PaymentIntent, all the same advertiser).
  select ac.advertiser_id, coalesce(sum(ac.amount_micros), 0)
    into v_adv, v_collected
    from public.advertiser_charges ac
   where ac.stripe_charge_id = p_payment_intent_id
     and ac.settled_via = 'stripe'
     and ac.status = 'succeeded'
   group by ac.advertiser_id
   order by ac.advertiser_id
   limit 1;

  -- Not a postpay charge (likely a deposit dispute that fanned out here) -> clean no-op.
  if v_adv is null then
    return jsonb_build_object('booked', false, 'reason', 'no_matching_postpay_charge',
                              'payment_intent_id', p_payment_intent_id);
  end if;

  -- Cap the write-off at what we actually collected on this PI (defense vs an over-stated amount).
  v_amt := least(p_amount_micros, v_collected);
  if v_amt <= 0 then
    return jsonb_build_object('booked', false, 'reason', 'nothing_collected',
                              'payment_intent_id', p_payment_intent_id);
  end if;

  -- Idempotency arbiter: insert the chargeback row FIRST. A re-delivered dispute event -> no row -> no book.
  insert into public.advertiser_postpay_chargebacks
    (dispute_id, advertiser_id, payment_intent_id, amount_micros, entry_group_id)
  values (p_dispute_id, v_adv, p_payment_intent_id, v_amt, v_group)
  on conflict (dispute_id) do nothing
  returning dispute_id into v_hit;
  if v_hit is null then
    return jsonb_build_object('booked', false, 'reason', 'duplicate', 'dispute_id', p_dispute_id);
  end if;

  -- Zero-sum bad-debt group: platform_cash -R (bank reclaimed the collected cash) / advertiser_bad_debt
  -- +R (platform write-off). advertiser_billing is UNTOUCHED (see header) -> billing_recon unaffected.
  insert into public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
  values
    (v_group, 'postpay_chargeback', 'platform_cash',      -v_amt, 'cleared', 'advertiser_dispute', v_adv, v_adv),
    (v_group, 'postpay_chargeback', 'advertiser_bad_debt',  v_amt, 'cleared', 'advertiser_dispute', v_adv, v_adv);

  -- Defense: stop further postpay accrual against a disputing/bad payer (mirrors the billing decline
  -- pause + the deposit-reversal pause). line_item status only -> does NOT trip advertisers_protect_cols.
  update public.line_items li set status = 'paused'
   where li.status = 'active'
     and li.campaign_id in (select c.id from public.campaigns c where c.advertiser_id = v_adv);

  -- A9: advertiser-level dispute hold — window_open stops serving this advertiser and the self-serve
  -- status RPCs refuse to resume, until an admin clears it. service_role caller => protect_cols passes.
  update public.advertisers set dispute_hold_at = now()
   where id = v_adv and dispute_hold_at is null;

  return jsonb_build_object('booked', true, 'advertiser_id', v_adv, 'dispute_id', p_dispute_id,
                            'bad_debt_micros', v_amt, 'entry_group_id', v_group);
end;
$$;
revoke all on function app.book_postpay_chargeback(text, text, bigint, text) from public, anon, authenticated;
grant  execute on function app.book_postpay_chargeback(text, text, bigint, text) to service_role;

comment on function app.book_postpay_chargeback is
  'Postpay CPVA chargeback bad-debt write-off (idempotent on Stripe dispute_id). Resolves the advertiser '
  'from advertiser_charges by disputed PaymentIntent id; books zero-sum platform_cash -R / '
  'advertiser_bad_debt +R (loss is platform-borne, never clawed from paid publishers), caps R at '
  'collected, pauses the advertiser''s active line_items, and (A9) sets an advertiser-level dispute_hold_at '
  'that window_open + the self-serve status RPCs honor until an admin clears it. A non-postpay PI -> clean '
  'no-op. service_role only.';

-- ---- 4. window_open — THE single pass-2 recreate. VERBATIM from 20260722120000 + ONE serve-gate ----
-- Base = pass-1 20260722120000 body (B2 caps + B4 click-token-hash + ip_hash stamp + M9 reserve). The
-- ONLY change: the real-publisher candidates CTE excludes a dispute-held advertiser
-- (a.dispute_hold_at is null). The sentinel/anon path serves is_house advertisers only (which never take
-- a postpay chargeback), so it needs no gate. Signature unchanged (3-arg) => CREATE OR REPLACE, no DROP.
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
  'A9: the real-publisher serve path excludes any advertiser with dispute_hold_at set (postpay chargeback). '
  'A12: budget_total_micros is a SOFT lifetime cap — it sums only CLOSED (provisional/cleared) '
  'impressions, so concurrent opens can overshoot by up to (in-flight-1) impressions; bounded per device '
  'by the concurrency cap; PREPAY advertisers are HARD-protected by the backed serve-time '
  'app.advertiser_reserve() balance hold; POSTPAY budget_total is soft by design (final charge reflects '
  'actual cleared delivery).';

-- ---- 5. self-serve status RPCs — refuse resume while the advertiser is dispute-held -----------------
-- VERBATIM from 20260716190000 + a dispute-hold check after the ownership assert.
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
  'Self-serve pause/resume of the caller''s own line_item (assert_owns_line_item FIRST); active<->paused only. Pausing stops serving instantly (window_open needs active). A9: refuses resume while the advertiser is dispute-held. SECDEF; authenticated.';

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
  'Self-serve pause/resume of the caller''s own campaign (assert_owns_campaign FIRST); active<->paused only (draft→active is admin-approval-driven). A9: refuses resume while the advertiser is dispute-held. SECDEF; authenticated.';

-- ---- 6. admin clear (money-admin / aal2; self-serve can NEVER call this) ---------------------------
create or replace function public.admin_clear_advertiser_dispute_hold(p_advertiser_id uuid)
returns jsonb
language plpgsql security definer set search_path = ''
as $$
declare v_had timestamptz;
begin
  -- Money gate: aal2 + app.money_admins membership (re-enabling a bad payer is a money action;
  -- same gate as admin_open_clawback, 20260716140000).
  if not (select app.is_money_admin()) then
    raise exception 'money admin (aal2) required' using errcode = '42501';
  end if;
  -- OLD alias unsupported in UPDATE ... RETURNING: read the prior value under lock, then clear.
  select dispute_hold_at into v_had
    from public.advertisers where id = p_advertiser_id for update;
  update public.advertisers set dispute_hold_at = null
   where id = p_advertiser_id and v_had is not null;
  return jsonb_build_object('advertiser_id', p_advertiser_id, 'cleared', v_had is not null);
end;
$$;
revoke all on function public.admin_clear_advertiser_dispute_hold(uuid) from public, anon;
grant  execute on function public.admin_clear_advertiser_dispute_hold(uuid) to authenticated, service_role;
comment on function public.admin_clear_advertiser_dispute_hold is
  'Money-admin (aal2 + app.money_admins) clear of an advertiser dispute hold (set by book_postpay_chargeback). '
  'Lifts the window_open serve-gate + the self-serve resume-block. Line_items stay paused (advertiser '
  'resumes them deliberately once cleared). SECDEF; anon revoked; in-body is_money_admin re-check. '
  'M8 self-lockout hazard: an all-aal1 admin base cannot clear a hold — the owner must be in '
  'app.money_admins with a verified aal2 session.';

-- ---- 7. Migration-tail assertion (money/PII migration MUST fail if anon retains EXECUTE) -----------
do $$
declare v_fn text; v_fns text[] := array[
  'public.window_open(text, text, text)',
  'public.advertiser_set_line_item_status(uuid, text)',
  'public.advertiser_set_campaign_status(uuid, text)',
  'public.admin_clear_advertiser_dispute_hold(uuid)',
  'app.book_postpay_chargeback(text, text, bigint, text)'
];
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — REVOKE ... FROM public, anon missing', v_fn;
    end if;
  end loop;
end $$;
