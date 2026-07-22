-- lumaline security-audit hardening pass-2 (Cluster P1: trusted client-IP). Persist the window's
-- edge-derived salted ip_hash onto the DURABLE impressions row.
--
-- ad_windows.ip_hash is stamped at window_open (20260722120000) and read live by scan_ivt
-- (20260722130000) while the UNLOGGED row exists. impressions.ip_hash (column since 20260627022224)
-- was never written. Copy it at close so self-click / IVT / self-deal forensics survive ad_windows
-- crash-loss + the stale sweep, and can run on the permanent, RLS-protected impressions table.
--
-- This is the ONE authoritative pass-2 close_window recreate: VERBATIM copy of the current M9 body
-- (20260716180000_advertiser_serving_guardrails.sql:381-524) with ip_hash added to the two impressions
-- INSERTs ONLY. No change to reserve accounting, dwell tolerance, idempotency, or the house gross=0
-- guard. Wire-compatible (no signature change; direct authenticated EXECUTE preserved).
-- DEPENDS ON: 20260716180000 (M9 close_window body), 20260722120000 (ad_windows.ip_hash writer).

create index if not exists impressions_ip_hash_state_idx
  on public.impressions (ip_hash, state) where ip_hash is not null;

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
  -- P1: persist the window's salted ip_hash onto the durable impressions row.
  IF w.creative_id IS NULL THEN
    PERFORM app.advertiser_release(v_adv, w.reserve_micros);
    UPDATE public.ad_windows SET state = 'void', reserve_micros = 0 WHERE window_id = p_window_id;
    INSERT INTO public.impressions(window_id, publisher_id, line_item_id, creative_id,
        attention_seconds, gross_micros, state, ip_hash)
      VALUES (w.window_id, w.publisher_id, NULL, NULL, v_att, 0, 'void', w.ip_hash)
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

  -- P1: persist the window's salted ip_hash onto the durable impressions row.
  INSERT INTO public.impressions(window_id, publisher_id, line_item_id, creative_id,
      attention_seconds, gross_micros, state, ip_hash)
    VALUES (w.window_id, w.publisher_id, w.line_item_id, w.creative_id, v_att, v_gross, 'provisional', w.ip_hash)
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
GRANT  EXECUTE ON FUNCTION public.close_window(uuid) TO authenticated, service_role;

COMMENT ON FUNCTION public.close_window(uuid) IS
  'Per-tick settle + prepay reserve true-up. VERBATIM 20260716180000 body; P1 addition: persists the '
  'window''s edge-derived salted ip_hash (ad_windows.ip_hash) onto the durable impressions row for '
  'self-click/IVT/self-deal forensics that survive the UNLOGGED ad_windows. No reserve/dwell/idempotency/'
  'house-gross-zero change. ip_hash is best-effort/advisory (direct-RPC callers may pass a forged one); '
  'the hard bound is window_open per-device/per-publisher caps.';

-- Migration-tail assertion — anon holds NO EXECUTE on the recreated money RPC.
do $$
begin
  if has_function_privilege('anon', 'public.close_window(uuid)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.close_window — REVOKE ... FROM public, anon missing';
  end if;
end $$;
