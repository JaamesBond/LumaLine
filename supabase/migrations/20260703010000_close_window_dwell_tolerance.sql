-- lumaline — close_window: tolerate edge round-trip latency in the dwell gate.
--
-- WHY: the client stamps its dwell start (state.startedAt) at status-line tick time, BEFORE the
-- /window/open round-trip. The server stamps ad_windows.started_at from now() = the open
-- TRANSACTION start, which happens AFTER that round-trip + sentinel-JWT mint + ad signing
-- (~1s on the live edge). So for a client that genuinely dwelled the full dwell_ms, close_window
-- measured `now() - started_at` ~network-latency SHORT of dwell_ms and rejected the honest dwell
-- as 'dwell too short' (never credited, window 'abandoned'). Only visible at real edge latency —
-- local/in-process tests run at ~ms latency and always cleared.
--
-- FIX (server half of a two-part fix; the client re-samples startedAt post-open in >=0.1.2):
-- subtract a small tolerance from the dwell threshold. This does NOT relax the attention proof —
-- the >=3 heartbeats spaced >=500ms (>=1s of chained, HMAC-keyed beating) and the activity_progress
-- gate still bind. attention_seconds stays `round(least(v_elapsed, dwell_ms)/1000)`, i.e. capped at
-- the REAL measured elapsed, so a latency-shortened window credits its true (lower) attention, never
-- an inflated dwell_ms. Only change: a window the server measured a hair under dwell_ms (because the
-- clock started a round-trip late) is no longer thrown away.
--
-- VERBATIM copy of the CURRENT close_window (20260629030000_sentinel_never_bills.sql — which
-- carries the belt-and-suspenders is_house gross=0 guard) with exactly two additions: the
-- v_tolerance declaration and the `- v_tolerance` in the dwell check. The is_house guard, the
-- house/no-fill void path, idempotency, and grants are all preserved. Grants re-asserted (SECDEF).
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
  -- Slack for edge round-trip latency between the client's dwell-start and the server's
  -- started_at stamp (see header). 1000ms comfortably covers the observed shortfall; the
  -- beat + activity gates remain the real attention proof.
  v_tolerance integer := 1000;
BEGIN
  SELECT * INTO w FROM public.ad_windows WHERE window_id = p_window_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'unknown window');
  END IF;
  IF v_pub IS NULL OR w.publisher_id <> v_pub THEN
    RAISE EXCEPTION 'not your window' USING ERRCODE = '28000';
  END IF;
  IF w.state <> 'open' THEN   -- idempotent: already closed/credited/abandoned
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already closed');
  END IF;

  -- Instant revocation: a device revoked after open cannot collect an impression.
  PERFORM 1 FROM public.devices d WHERE d.id = w.device_id AND d.revoked_at IS NULL;
  IF NOT FOUND THEN
    UPDATE public.ad_windows SET state = 'abandoned' WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'device revoked');
  END IF;

  -- Dwell quality gates.
  IF w.beats_count < 3 THEN
    UPDATE public.ad_windows SET state = 'abandoned' WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', format('too few beats (%s)', w.beats_count));
  END IF;
  IF NOT w.activity_progress THEN
    UPDATE public.ad_windows SET state = 'abandoned' WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'no activity progress');
  END IF;
  v_elapsed := EXTRACT(EPOCH FROM (NOW() - w.started_at)) * 1000;
  IF v_elapsed < w.dwell_ms - v_tolerance THEN
    UPDATE public.ad_windows SET state = 'abandoned' WHERE window_id = p_window_id;
    UPDATE public.clicks SET state = 'void', gross_micros = 0
      WHERE window_id = p_window_id AND state <> 'void';
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'dwell too short');
  END IF;

  v_att := round(least(v_elapsed, w.dwell_ms) / 1000.0);

  -- House / no-fill: a valid dwell with no booked creative is recorded void, never billed.
  IF w.creative_id IS NULL THEN
    UPDATE public.ad_windows SET state = 'void' WHERE window_id = p_window_id;
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
    -- Row already existed (concurrent/replayed close): do not re-credit.
    UPDATE public.ad_windows SET state = 'credited' WHERE window_id = p_window_id;
    RETURN jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already credited');
  END IF;

  UPDATE public.ad_windows SET state = 'credited' WHERE window_id = p_window_id;

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
REVOKE EXECUTE ON FUNCTION public.close_window(uuid) FROM public;
GRANT EXECUTE ON FUNCTION public.close_window(uuid) TO authenticated, service_role;
