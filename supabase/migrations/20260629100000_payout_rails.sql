-- lumaline M3-T1/T2/T3 — publisher payout rails (Stripe Connect, money-safe SQL layer).
--
-- The Stripe API calls (account creation, account links, transfers) live in the
-- `stripe-connect` edge function. THIS migration is the database half: the
-- reservation, ledger booking, reconciliation, and eligibility primitives that
-- protect money regardless of what the edge function does. Everything here is
-- testable WITHOUT live Stripe (test/payout-rails.integration.mjs).
--
-- TWO-PHASE PAYOUT (ledger booked at CONFIRM, never at reserve):
--
--   1. payout_batch_reserve()  -> INSERT a 'pending' payout per eligible publisher.
--      The unique partial index payouts_one_active_per_publisher is the
--      reservation LOCK: at most one non-terminal payout per publisher, so a
--      re-run (or a concurrent batch) cannot create a second transfer. NO ledger
--      is booked here, so the publisher's visible balance only drops once money
--      has actually moved.
--
--   2. edge fn calls Stripe transfers.create with idempotencyKey = payout_id, then
--      payout_confirm(payout_id, transfer_id) -> books the balanced ledger group
--      and flips status to 'paid'. Crash-after-transfer/​before-confirm is safe:
--      the batch re-selects the still-'pending' row, re-calls Stripe with the same
--      idempotency key (Stripe returns the SAME transfer), and confirm books once.
--
--   On a Stripe error the edge fn calls payout_fail(payout_id, reason) -> 'failed',
--   no ledger (nothing was booked). A later transfer.reversed webhook calls
--   payout_reverse(payout_id, reason) -> books the inverse ledger group so the pair
--   nets to zero and the balance becomes payable again.
--
-- LEDGER CONVENTION (matches app.accrue's signs):
--   accrual : publisher_earnings is NEGATIVE (owed to the publisher).
--   payout  : publisher_earnings is POSITIVE (+amount, reduces what is owed),
--             balanced by platform_cash NEGATIVE (-amount, cash leaves the platform).
--   So "already paid" = SUM(positive payout publisher_earnings legs), and a reversal
--   adds the mirror (-amount / +amount) to net the payout to zero.
--
-- All money RPCs are SECURITY DEFINER and granted to service_role ONLY (the edge
-- function's role). anon/authenticated cannot call them.

-- ---------------------------------------------------------------------------
-- Schema: payout lifecycle columns + the reservation lock + webhook dedup table.
-- ---------------------------------------------------------------------------
ALTER TABLE public.payouts ADD COLUMN IF NOT EXISTS paid_at        timestamptz;
ALTER TABLE public.payouts ADD COLUMN IF NOT EXISTS failure_reason text;

COMMENT ON COLUMN public.payouts.paid_at        IS 'Set by payout_confirm() when the Stripe transfer succeeded and the ledger was booked.';
COMMENT ON COLUMN public.payouts.failure_reason IS 'Set by payout_fail()/payout_reverse() — why the payout did not (or no longer) holds.';

-- The reservation lock: at most ONE active (pending|in_transit) payout per
-- publisher. This is what makes reserve idempotent and blocks double-transfer.
CREATE UNIQUE INDEX IF NOT EXISTS payouts_one_active_per_publisher
  ON public.payouts (publisher_id)
  WHERE status IN ('pending', 'in_transit');

-- Webhook replay/dedup guard. Every Stripe event id is recorded once; a second
-- delivery of the same id is a no-op (the edge fn checks this table first).
CREATE TABLE IF NOT EXISTS public.stripe_webhook_events (
  event_id    text primary key,
  type        text not null,
  received_at timestamptz not null default now()
);
ALTER TABLE public.stripe_webhook_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stripe_webhook_events_service ON public.stripe_webhook_events;
CREATE POLICY stripe_webhook_events_service ON public.stripe_webhook_events
  FOR ALL TO service_role USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON public.stripe_webhook_events TO service_role;

-- ---------------------------------------------------------------------------
-- app.publisher_payable_micros — matured earnings minus already-paid.
--   earned_past_hold = -SUM(cleared cpva publisher_earnings legs whose backing
--                      impression is older than p_hold)
--   already_paid     =  SUM(cleared payout publisher_earnings legs, +amount)
--   payable          = earned_past_hold - already_paid
--
-- LOUD CPC GUARD (money-safety): payouts cover CPVA only until CPC billing lands
-- (M4). If any cleared cpc_accrual publisher_earnings leg exists, this RAISES
-- rather than silently underpaying the publisher.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.publisher_payable_micros(p_publisher_id uuid, p_hold interval)
RETURNS bigint
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_earned bigint;
  v_paid   bigint;
  v_cpc    bigint;
BEGIN
  SELECT count(*) INTO v_cpc
    FROM public.ledger_entries
   WHERE account = 'publisher_earnings' AND event_type = 'cpc_accrual'
     AND state = 'cleared' AND publisher_id = p_publisher_id;
  IF v_cpc > 0 THEN
    RAISE EXCEPTION
      'cpc_accrual publisher_earnings present for % but payouts cover cpva only (CPC billing is M4) — refusing to underpay',
      p_publisher_id USING errcode = '22023';
  END IF;

  SELECT COALESCE(-sum(le.amount_micros), 0) INTO v_earned
    FROM public.ledger_entries le
    JOIN public.impressions imp ON imp.id = le.source_id
   WHERE le.account = 'publisher_earnings' AND le.event_type = 'cpva_accrual'
     AND le.state = 'cleared' AND le.source_type = 'impression'
     AND le.publisher_id = p_publisher_id
     AND imp.created_at <= now() - p_hold;

  SELECT COALESCE(sum(le.amount_micros), 0) INTO v_paid
    FROM public.ledger_entries le
   WHERE le.account = 'publisher_earnings' AND le.event_type = 'payout'
     AND le.state = 'cleared' AND le.publisher_id = p_publisher_id;

  RETURN v_earned - v_paid;
END;
$$;
REVOKE ALL ON FUNCTION app.publisher_payable_micros(uuid, interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.publisher_payable_micros(uuid, interval) TO service_role;

-- ---------------------------------------------------------------------------
-- payout_batch_reserve — phase 1. INSERT a pending payout per eligible publisher.
-- Books NO ledger. Eligible = verified Connect account + active + not deleted +
-- no active payout + payable in [min, velocity_max]. Returns {reserved[], skipped[]}.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.payout_batch_reserve(
  p_hold                interval default '7 days',
  p_min_micros          bigint   default 25000000,        -- $25.00
  p_velocity_max_micros bigint   default 10000000000,     -- $10,000 anomaly ceiling
  p_limit               int      default 100)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  rec       record;
  v_payable bigint;
  v_id      uuid;
  reserved  jsonb := '[]'::jsonb;
  skipped   jsonb := '[]'::jsonb;
BEGIN
  FOR rec IN
    SELECT p.id
      FROM public.publishers p
     WHERE p.payout_status = 'verified'
       AND p.stripe_account_id IS NOT NULL
       AND p.status = 'active'
       AND p.deleted_at IS NULL
       AND NOT EXISTS (
         SELECT 1 FROM public.payouts po
          WHERE po.publisher_id = p.id AND po.status IN ('pending', 'in_transit'))
     ORDER BY p.created_at
     LIMIT p_limit
  LOOP
    v_payable := app.publisher_payable_micros(rec.id, p_hold);

    IF v_payable < p_min_micros THEN
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'below_min', 'payable_micros', v_payable);
      CONTINUE;
    END IF;
    IF v_payable > p_velocity_max_micros THEN
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'velocity_cap', 'payable_micros', v_payable);
      CONTINUE;
    END IF;

    -- The unique partial index makes a concurrent double-reserve fail loudly;
    -- treat that as "already reserved" and skip rather than abort the batch.
    BEGIN
      INSERT INTO public.payouts (publisher_id, amount_micros, status, hold_until, min_payout_micros)
      VALUES (rec.id, v_payable, 'pending', now(), p_min_micros)
      RETURNING id INTO v_id;
    EXCEPTION WHEN unique_violation THEN
      skipped := skipped || jsonb_build_object('publisher_id', rec.id, 'reason', 'already_reserved');
      CONTINUE;
    END;

    reserved := reserved || jsonb_build_object('publisher_id', rec.id, 'payout_id', v_id, 'amount_micros', v_payable);
  END LOOP;

  RETURN jsonb_build_object('reserved', reserved, 'skipped', skipped);
END;
$$;
REVOKE ALL ON FUNCTION public.payout_batch_reserve(interval, bigint, bigint, int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.payout_batch_reserve(interval, bigint, bigint, int) TO service_role;

-- ---------------------------------------------------------------------------
-- payout_confirm — phase 2. Book the balanced ledger group and flip to 'paid'.
-- Idempotent: a second call (status already terminal) is a no-op, never a 2nd group.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.payout_confirm(p_payout_id uuid, p_transfer_id text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_po public.payouts%ROWTYPE;
  g    uuid := gen_random_uuid();
BEGIN
  SELECT * INTO v_po FROM public.payouts WHERE id = p_payout_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'payout not found' USING errcode = 'P0002';
  END IF;
  IF v_po.status <> 'pending' AND v_po.status <> 'in_transit' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_pending', 'status', v_po.status);
  END IF;

  INSERT INTO public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) VALUES
    (g, 'payout', 'publisher_earnings',  v_po.amount_micros, 'cleared', 'payout', p_payout_id, v_po.publisher_id),
    (g, 'payout', 'platform_cash',      -v_po.amount_micros, 'cleared', 'payout', p_payout_id, null);

  UPDATE public.payouts
     SET status = 'paid', stripe_transfer_id = p_transfer_id, paid_at = now()
   WHERE id = p_payout_id;

  RETURN jsonb_build_object('ok', true, 'payout_id', p_payout_id, 'entry_group_id', g);
END;
$$;
REVOKE ALL ON FUNCTION public.payout_confirm(uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.payout_confirm(uuid, text) TO service_role;

-- ---------------------------------------------------------------------------
-- payout_fail — phase 2 failure (transfer never succeeded). No ledger to reverse.
-- Idempotent.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.payout_fail(p_payout_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_po public.payouts%ROWTYPE;
BEGIN
  SELECT * INTO v_po FROM public.payouts WHERE id = p_payout_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'payout not found' USING errcode = 'P0002';
  END IF;
  IF v_po.status = 'paid' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_paid');  -- use payout_reverse instead
  END IF;
  IF v_po.status = 'failed' OR v_po.status = 'canceled' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_failed');
  END IF;

  UPDATE public.payouts SET status = 'failed', failure_reason = p_reason WHERE id = p_payout_id;
  RETURN jsonb_build_object('ok', true, 'payout_id', p_payout_id);
END;
$$;
REVOKE ALL ON FUNCTION public.payout_fail(uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.payout_fail(uuid, text) TO service_role;

-- ---------------------------------------------------------------------------
-- payout_reverse — a previously-PAID transfer was reversed at Stripe. Book the
-- mirror ledger group so the payout nets to zero and the balance is payable again.
-- Idempotent (a payout already 'failed' is a no-op).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.payout_reverse(p_payout_id uuid, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_po public.payouts%ROWTYPE;
  g    uuid := gen_random_uuid();
BEGIN
  SELECT * INTO v_po FROM public.payouts WHERE id = p_payout_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'payout not found' USING errcode = 'P0002';
  END IF;
  IF v_po.status <> 'paid' THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'not_paid', 'status', v_po.status);
  END IF;

  -- Mirror of payout_confirm's group: cancels it out to net zero on the payout legs.
  INSERT INTO public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) VALUES
    (g, 'payout', 'publisher_earnings', -v_po.amount_micros, 'cleared', 'payout', p_payout_id, v_po.publisher_id),
    (g, 'payout', 'platform_cash',       v_po.amount_micros, 'cleared', 'payout', p_payout_id, null);

  UPDATE public.payouts SET status = 'failed', failure_reason = p_reason WHERE id = p_payout_id;
  RETURN jsonb_build_object('ok', true, 'payout_id', p_payout_id, 'entry_group_id', g);
END;
$$;
REVOKE ALL ON FUNCTION public.payout_reverse(uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.payout_reverse(uuid, text) TO service_role;

-- ---------------------------------------------------------------------------
-- set_publisher_payout_eligibility — webhook account.updated handler target.
-- Flips a publisher's payout_status by Stripe account id. service_role only.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.set_publisher_payout_eligibility(p_stripe_account_id text, p_status text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_status NOT IN ('none', 'pending', 'verified', 'ineligible_country') THEN
    RAISE EXCEPTION 'invalid payout_status: %', p_status USING errcode = '22023';
  END IF;
  UPDATE public.publishers
     SET payout_status = p_status::public.payout_status
   WHERE stripe_account_id = p_stripe_account_id;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN jsonb_build_object('ok', true, 'updated', v_n);
END;
$$;
REVOKE ALL ON FUNCTION public.set_publisher_payout_eligibility(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.set_publisher_payout_eligibility(text, text) TO service_role;

-- ---------------------------------------------------------------------------
-- payout_recon_totals — sum the ledger debits of PAID payouts in a window, for
-- comparison against Stripe's transfer total (mirrors billing_recon_totals).
-- Excludes pending (no transfer yet) and reversed/failed (net-zero) payouts.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.payout_recon_totals(p_from timestamptz, p_to timestamptz)
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT jsonb_build_object(
    'payout_debits_micros',
      COALESCE(sum(le.amount_micros) FILTER (WHERE le.account = 'publisher_earnings'), 0)::bigint,
    'payout_count',
      count(DISTINCT p.id)::bigint)
  FROM public.payouts p
  JOIN public.ledger_entries le
    ON le.source_id = p.id AND le.source_type = 'payout'
   AND le.event_type = 'payout' AND le.state = 'cleared'
  WHERE p.status = 'paid'
    AND p.created_at >= p_from
    AND p.created_at <= p_to;
$$;
REVOKE ALL ON FUNCTION public.payout_recon_totals(timestamptz, timestamptz) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.payout_recon_totals(timestamptz, timestamptz) TO service_role;

COMMENT ON FUNCTION public.payout_batch_reserve IS
  'Phase 1: reserve a pending payout per eligible publisher (no ledger). One-active-per-publisher index is the reservation lock.';
COMMENT ON FUNCTION public.payout_confirm IS
  'Phase 2: book the balanced payout ledger group + mark paid. Idempotent.';
COMMENT ON FUNCTION public.payout_reverse IS
  'transfer.reversed: book the inverse ledger group so a paid payout nets to zero and becomes payable again. Idempotent.';
COMMENT ON FUNCTION public.payout_recon_totals IS
  'Sum cleared payout publisher_earnings debits for PAID payouts in [from,to] — compare to Stripe transfers.';
