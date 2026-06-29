-- lumaline M2-T2 — structural sentinel-never-bills guard.
--
-- Prevents any house/sentinel advertiser from having non-zero bids at the DB level.
-- Trust Invariant #4: "Honest billing — the sentinel-never-bills guarantee is enforced
-- by a DB constraint, not by convention."
--
-- Three layers (defence in depth):
--   1. is_house boolean column on advertisers — marks the house/sentinel advertiser(s).
--   2. check_house_bids() SECURITY DEFINER function + CHECK on line_items — any
--      INSERT or UPDATE that sets cpva>0 or cpc>0 on a line_item whose campaign's
--      advertiser is_house=true is rejected with a constraint violation.
--   3. Belt-and-suspenders guard in close_window — even if a non-zero row somehow
--      existed (e.g. a direct service_role INSERT before this migration, or a future
--      migration error), billing always zeros v_gross when the advertiser is_house.
--
-- The sentinel advertiser UUID is known from seed.prod.sql:
--   '5e470000-0000-4000-8000-00000000a001'
--
-- Deployment note: on `supabase db reset` (dev/CI), migrations run before seed.sql so
-- the UPDATE below finds no rows (UPDATE 0); seed.sql then inserts the sentinel
-- advertiser with is_house=true directly. On an already-deployed prod instance, the row
-- exists before this migration and the UPDATE marks it correctly.

-- ---------------------------------------------------------------------------
-- 1. is_house column on advertisers
-- ---------------------------------------------------------------------------
ALTER TABLE public.advertisers
  ADD COLUMN IF NOT EXISTS is_house boolean NOT NULL DEFAULT false;

-- Mark the house/sentinel advertiser — covers already-deployed prod.
-- Fresh-stack (supabase db reset): seed.sql INSERT sets is_house=true directly.
UPDATE public.advertisers
  SET is_house = true
  WHERE id = '5e470000-0000-4000-8000-00000000a001';

-- ---------------------------------------------------------------------------
-- 2. check_house_bids() — helper for the CHECK constraint.
--
-- A CHECK constraint cannot reference other tables directly (no subqueries), so we
-- wrap the cross-table join in a SECURITY DEFINER function. The constraint calls this
-- function for every INSERT/UPDATE on line_items.
--
-- Returns false (rejects the row) when:
--   - The parent campaign's advertiser has is_house=true AND (p_cpva>0 OR p_cpc>0).
-- Returns true (allows the row) for all other cases:
--   - Non-house advertiser: any bid value is permitted.
--   - House advertiser with both bids=0: the zero-cost self-promo case.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.check_house_bids(
  p_campaign_id uuid, p_cpva bigint, p_cpc bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
AS $$
  SELECT CASE
    WHEN EXISTS (
      SELECT 1 FROM public.campaigns cm
      JOIN public.advertisers a ON a.id = cm.advertiser_id
      WHERE cm.id = p_campaign_id AND a.is_house = true
    ) THEN (p_cpva = 0 AND p_cpc = 0)
    ELSE true
  END;
$$;

-- Only the roles that legitimately INSERT/UPDATE line_items need EXECUTE.
-- authenticated: admins manage line_items via the authenticated+is_admin() RLS policy.
-- service_role: edge functions / RPCs that insert on behalf of the system.
REVOKE EXECUTE ON FUNCTION public.check_house_bids(uuid, bigint, bigint) FROM public;
GRANT EXECUTE ON FUNCTION public.check_house_bids(uuid, bigint, bigint)
  TO authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 3. CHECK constraint on line_items
--
-- Fires on every INSERT and UPDATE. The function call is the constraint predicate;
-- returning false raises a check_violation (SQLSTATE 23514).
-- ---------------------------------------------------------------------------
ALTER TABLE public.line_items
  ADD CONSTRAINT line_items_house_bids_zero
  CHECK (public.check_house_bids(campaign_id, cpva_bid_micros, cpc_bid_micros));

-- ---------------------------------------------------------------------------
-- 4. close_window — belt-and-suspenders house guard in billing.
--
-- Verbatim copy of close_window from 20260629020000_serving_algorithm.sql with ONE
-- addition: after computing v_gross, look up whether the window's line_item belongs
-- to a house advertiser, and if so, force v_gross=0.
--
-- Why belt-and-suspenders? The CHECK above prevents a house line_item from having a
-- non-zero bid — so clearing_price_micros is always 0 for house windows and v_gross
-- computes to 0 without this guard.  But if someone bypassed the constraint (e.g. a
-- direct psql INSERT on an earlier schema version), billing must still be correct.
-- Trust Invariant #4 is too important to rely on a single layer.
--
-- IMPORTANT: do NOT edit the original migration file. This CREATE OR REPLACE replaces
-- the function in place; the previous definition is discarded.
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
  IF v_elapsed < w.dwell_ms THEN
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
