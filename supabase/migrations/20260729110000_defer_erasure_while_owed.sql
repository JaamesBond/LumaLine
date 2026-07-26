-- lumaline GDPR Phase 4b — an unpaid balance DEFERS erasure instead of destroying it.
--
-- THE DEFECT, proven live on a clean stack before this migration existed:
--
--     PRECONDITION  payable=50000000 (€50)  in_flight=0  matured_impressions=1
--     app.gdpr_erase_publisher(...)  ->  {"ok": true, ...}
--     AFTER         still_owed=50000000  payout_status=none  stripe=NULL  status=suspended  erased=t
--     still_a_candidate = 0
--
-- app.gdpr_erase_publisher refused on exactly ONE condition — a payouts row in pending/in_transit —
-- and never read the publisher's balance at all. Payouts run WEEKLY; the Phase 3 completion cron
-- runs HOURLY. So the normal state of a publisher who is owed money is "owed, with nothing in
-- flight", and that publisher was erased on the spot. The erasure itself then sets
-- payout_status='none', stripe_account_id=NULL, status='suspended' and deleted_at — which trips
-- FOUR separate guards in payout_batch_reserve's candidate select. There is no path back: the money
-- is unrecoverable, permanently.
--
-- That made two PUBLISHED statements false as written:
--   * docs/legal/publisher-tos.md §7.3 — "A balance you have carried forward is never forfeited by
--     leaving"
--   * README.md — "whatever you've earned is paid out in full … We never keep your earnings"
--
-- THE FIX. An unpaid payable balance becomes a DEFERRABLE refusal, so erasure WAITS for the money
-- instead of erasing over it. Phase 3 (20260727100000) already built exactly this machinery:
-- app.gdpr_deferrable_reason() is the allow-list that decides whether a refusal freezes the account
-- and schedules a retry ({ok:true, state:'pending'}) or dead-ends ({ok:false}); the hourly
-- app.gdpr_complete_pending() re-runs the same gate and completes it once it passes. This migration
-- adds one refusal to the erasure body and one string to that allow-list. Nothing else.
--
-- WHY €0.01 IS THE RIGHT FLOOR, and why it CANNOT deadlock. Phase 4 (20260729100000) waives the
-- payout minimum for a closing publisher down to Stripe's own floor: it computes
-- `(payable / 10000) * 10000` and skips below 10000. That integer floor means floor(P) >= 10000 iff
-- P >= 10000, so the guard below refuses EXACTLY the set of balances Phase 4 will actually pay, and
-- releases exactly the set it cannot. Dust under one cent is genuinely unpayable — Stripe cannot
-- transfer it, the ledger floors it to zero, and the ToS already discloses that bound — so holding
-- an erasure hostage to it would be a freeze that could never lift. The two thresholds are the same
-- number ON PURPOSE and must move together; a mismatch in either direction is a deadlock (guard
-- above the payout floor) or a strand (guard below it).
--
-- THE FULL LOOP, which is the point of the change: publisher closes owing €0.40 -> earnings_unpaid
-- -> deferred + frozen (devices revoked, status left 'active' by Phase 3 precisely so the payout
-- can still run) -> the weekly batch runs and Phase 4 waives the €1 minimum, paying the €0.40 ->
-- payable drops to 0 -> the hourly cron re-runs the gate, it passes, the publisher is erased. Both
-- published statements become true as written.
--
-- ORDERING. The new refusal sits AFTER the payout_in_flight check, so a publisher whose money is
-- already moving still reports that more specific reason (both are deferrable, so the outcome is
-- the same freeze — but the reason a human reads should name the actual blocker).
--
-- RESIDUAL, stated plainly. A publisher who is owed >= €0.01 but is NOT payout-eligible — never
-- onboarded to Stripe, unverified, or sitting on an unreleased publisher_payout_holds row — now
-- stays PENDING rather than being erased, because no payout batch will ever clear their balance on
-- its own. That is deliberate: the alternative is the defect above. Phase 3's Art. 12(3) watchdog is
-- the escape hatch — app.gdpr_complete_pending() raises the `gdpr_pending_overdue` alert at 25 days,
-- five days inside the one-month deadline, so a human resolves it (finish onboarding, release the
-- hold, or pay by hand) rather than the system silently keeping the money. An alert is a worse
-- outcome than an automatic erasure; it is a far better one than a permanent, invisible forfeiture.
--
-- WHAT IS NOT TOUCHED: payout_confirm / payout_fail / payout_reverse, the reservation lock, and
-- payout_batch_reserve (Phase 4 owns that one) — the stated trust invariant.
--
-- Depends on: 20260705120000 (the app.gdpr_erase_publisher body copied below),
--             20260727100000 (app.gdpr_deferrable_reason + the pending state machine),
--             20260729100000 (Phase 4's waived minimum — the half that actually pays the balance).

-- ===========================================================================
-- 1. app.gdpr_erase_publisher — body copied VERBATIM from its live definer
--    (20260705120000_gdpr_self_delete.sql:28-100, confirmed against pg_get_functiondef on a
--    migrated stack — it is the ONLY definition of this function anywhere in supabase/migrations),
--    with exactly ONE addition: the earnings_unpaid guard below.
-- ===========================================================================
CREATE OR REPLACE FUNCTION app.gdpr_erase_publisher(p_publisher_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_pub      public.publishers%ROWTYPE;
  v_devices  integer := 0;
  v_disputes integer := 0;
BEGIN
  -- Lock the publisher.
  SELECT * INTO v_pub FROM public.publishers WHERE id = p_publisher_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'publisher not found' USING errcode = 'P0002';
  END IF;

  -- Idempotent.
  IF v_pub.deleted_at IS NOT NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_deleted');
  END IF;

  -- Money-safety: never erase a publisher with money in flight. The clawback/payout
  -- trail must settle (or fail) first so funds and PII are reconciled before erasure.
  IF EXISTS (
    SELECT 1 FROM public.payouts
    WHERE publisher_id = p_publisher_id AND status IN ('pending', 'in_transit')
  ) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'payout_in_flight');
  END IF;

  -- *** P4b: never erase a publisher who is still OWED money. ***
  -- Erasure nulls stripe_account_id, zeroes payout_status, suspends status and sets deleted_at —
  -- four independent reasons payout_batch_reserve would never look at this publisher again. Erasing
  -- while a balance stands does not merely delay the payment, it destroys it. Deferrable (see
  -- app.gdpr_deferrable_reason below), so the request is ACCEPTED and scheduled rather than
  -- refused: Phase 4 pays the balance down on the next weekly batch (minimum waived for a closing
  -- account), and the hourly app.gdpr_complete_pending() completes the erasure once it clears.
  -- 10000 micros = €0.01 = the same floor payout_batch_reserve applies, so this refuses exactly the
  -- balances that CAN be paid and releases the sub-cent dust that never can.
  IF (SELECT app.publisher_payable_micros(p_publisher_id, app.payout_hold_interval())) >= 10000 THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'earnings_unpaid');
  END IF;

  -- Remove device PII (no financial value).
  DELETE FROM public.devices WHERE publisher_id = p_publisher_id;
  GET DIAGNOSTICS v_devices = ROW_COUNT;
  DELETE FROM public.device_auth_codes WHERE publisher_id = p_publisher_id;

  -- Scrub free-text PII in disputes but keep the rows for audit.
  UPDATE public.disputes
     SET description = '[redacted: account deleted]'
   WHERE publisher_id = p_publisher_id;
  GET DIAGNOSTICS v_disputes = ROW_COUNT;

  -- Anonymize the publisher row IN PLACE (preserves ledger linkage).
  UPDATE public.publishers SET
    handle            = 'deleted-' || left(id::text, 8),
    country           = NULL,
    stripe_account_id = NULL,
    payout_status     = 'none',
    status            = 'suspended',
    deleted_at        = now()
  WHERE id = p_publisher_id;

  -- Tombstone the auth identity (the strongest PII: email). Done in place so the
  -- on-delete-cascade FK from publishers.auth_user_id does NOT fire.
  UPDATE auth.users SET
    email              = 'deleted-' || left(p_publisher_id::text, 8) || '@deleted.invalid',
    phone              = NULL,
    raw_user_meta_data = '{}'::jsonb,
    raw_app_meta_data  = '{}'::jsonb
  WHERE id = v_pub.auth_user_id;

  -- Best-effort revoke of sessions/identities (auth internals vary by version).
  BEGIN DELETE FROM auth.sessions   WHERE user_id = v_pub.auth_user_id; EXCEPTION WHEN others THEN NULL; END;
  BEGIN DELETE FROM auth.identities WHERE user_id = v_pub.auth_user_id; EXCEPTION WHEN others THEN NULL; END;

  RETURN jsonb_build_object(
    'ok',                true,
    'publisher_id',      p_publisher_id,
    'devices_deleted',   v_devices,
    'disputes_scrubbed', v_disputes
  );
END;
$$;
REVOKE ALL ON FUNCTION app.gdpr_erase_publisher(uuid) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.gdpr_erase_publisher IS
  'Private shared body for GDPR erasure (anonymize-in-place, ledger preserved, idempotent, refuses while a payout is in flight). Reached only via the SECURITY DEFINER wrappers gdpr_delete_publisher()/gdpr_self_delete(); never callable by client roles. P4b: ALSO refuses (reason earnings_unpaid) while the publisher is owed at least one whole cent — erasure nulls the Stripe account and suspends the row, so erasing over a balance destroys it rather than delaying it. Both refusals are deferrable: the request enters pending, Phase 4 pays the balance on the next batch with the minimum waived, and app.gdpr_complete_pending() completes the erasure.';

-- ===========================================================================
-- 2. app.gdpr_deferrable_reason — earnings_unpaid joins the allow-list.
--
-- Re-declared VERBATIM from its live definer (20260727100000:104-119), with 'earnings_unpaid'
-- added to the IN list and the comment extended. The allow-list shape is deliberately preserved:
-- an unrecognized reason must keep defaulting to TERMINAL. Without this half, the guard above
-- would be strictly WORSE than the defect — a hard {ok:false} dead-end on every publisher who is
-- owed anything, with no schedule and no way through.
--
-- It qualifies on the same test every other member does: money in flight that self-resolves. A
-- weekly payout batch is a longer wait than a Stripe transfer settling, but it is still a TIMING
-- problem with a mechanism that clears it, not a permanent condition — and Phase 4 is that
-- mechanism. Where it genuinely cannot clear (a publisher who never onboarded), the 25-day
-- Art. 12(3) alert escalates to a human; see the RESIDUAL note at the head of this file.
-- ===========================================================================
create or replace function app.gdpr_deferrable_reason(p_reason text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select p_reason in ('payout_in_flight', 'earnings_unpaid', 'topup_pending', 'charge_pending', 'uncharged_postpay_billings');
$$;

revoke all on function app.gdpr_deferrable_reason(text) from public, anon, authenticated;
grant execute on function app.gdpr_deferrable_reason(text) to service_role;

comment on function app.gdpr_deferrable_reason is
  'Classifies an erasure refusal reason as a DEFERRAL (money in flight or money still owed; clears '
  'via the payout batch or Stripe settlement, so the request enters pending and a cron completes '
  'it) or TERMINAL (already_deleted, house_advertiser; passed straight back). Allow-list, so any '
  'future reason defaults to terminal. P4b added earnings_unpaid — a publisher owed at least one '
  'whole cent waits for the payout that Phase 4 guarantees them instead of being erased over it.';

-- ===========================================================================
-- 3. Migration-tail assertions. Both are cheap, and both have bitten this repo before: the
--    anon-EXECUTE default-privilege footgun reached production once (20260629120000), and a
--    deferrable-reason allow-list that silently lost a member would turn every deferral into a
--    dead-end refusal with no visible error anywhere.
-- ===========================================================================
do $$
declare
  v_fn  text;
  v_fns text[] := array['app.gdpr_erase_publisher(uuid)', 'app.gdpr_deferrable_reason(text)'];
  v_r   text;
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    end if;
    if has_function_privilege('authenticated', v_fn, 'EXECUTE') then
      raise exception 'authenticated retains EXECUTE on % — REVOKE missing', v_fn;
    end if;
  end loop;

  -- Every pre-existing deferrable reason still defers, and the new one does too. A CREATE OR
  -- REPLACE that dropped a member would otherwise fail silently and dead-end live erasure requests.
  foreach v_r in array array['payout_in_flight', 'earnings_unpaid', 'topup_pending',
                             'charge_pending', 'uncharged_postpay_billings'] loop
    if not app.gdpr_deferrable_reason(v_r) then
      raise exception 'app.gdpr_deferrable_reason(%) must be TRUE — the allow-list lost a member', v_r;
    end if;
  end loop;
  -- ...and the terminal ones are still terminal (the allow-list did not become a pass-through).
  foreach v_r in array array['already_deleted', 'house_advertiser'] loop
    if app.gdpr_deferrable_reason(v_r) then
      raise exception 'app.gdpr_deferrable_reason(%) must be FALSE — a terminal reason became deferrable', v_r;
    end if;
  end loop;
end $$;
