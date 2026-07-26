-- lumaline GDPR Phase 3 — the pending-deletion state machine.
--
-- A deletion request that cannot complete immediately must SCHEDULE ITSELF, not dead-end.
-- Today public.gdpr_self_delete() and public.advertiser_gdpr_self_delete() return
-- {ok:false, reason} when money is in flight and arrange NOTHING: the data subject has to come
-- back and retry by hand while the Art. 12(3) one-month response clock runs against us. A refusal
-- is not an answer to an erasure request; it is a deferral we never recorded.
--
-- WHAT THIS ADDS
--   1. A `deletion_requested_at` watermark on BOTH roles, mirroring the existing `deleted_at`
--      idiom. Set when a request could not complete; NULL once erased or cancelled.
--   2. The request path becomes ERASE-OR-ENTER-PENDING. The GATE ITSELF IS UNCHANGED — what
--      changes is what happens when it refuses.
--   3. A FREEZE, so a pending account does nothing new while it waits.
--   4. app.gdpr_complete_pending() — an hourly cron that re-runs the same gate and completes the
--      ones that now pass, delegating to the UNCHANGED erasure bodies. No fork, ever: two copies
--      of an erasure body is how the ledger/refusal invariants drift apart.
--   5. A 25-day alert, so the Art. 12(3) one-month deadline surfaces BEFORE it is missed.
--   6. Cancel, available right up until erasure fires.
--
-- WHY A FREEZE AT ALL. Between "I asked to be erased" and "the blocker cleared" the account is in
-- a state the user has already repudiated. Letting it keep serving, spending or minting sessions
-- in that window would mean honouring the request in name only.
--
-- HOW THIS SITS AGAINST WHAT ALREADY SHIPPED (Phases 1-2 + the erased-surface audit):
--   * Phase 2 (20260726100000) REMOVED the advertiser idle-balance gate, so an advertiser now
--     enters pending only for in-flight TRANSACTIONS (topup_pending / charge_pending /
--     uncharged_postpay_billings), which self-resolve in days. `spend_down` is therefore the
--     PRINCIPAL DELIBERATE use of the pending state, not an edge case.
--   * Erasure is now TERMINAL (20260726110000 + 20260726120000): window_open carries
--     `a.deleted_at is null` and nine self-serve RPCs refuse an erased org. The freeze never
--     fights those gates — it operates strictly BEFORE deleted_at is set, so the two never
--     overlap.
--   * `deletion_disposition` already exists with CHECK (dormant|writeoff). Phase 2 deliberately
--     WITHHELD 'spend_down' until the cron that honours it existed. That cron is this migration.

-- ===========================================================================
-- 1. The watermark columns + the spend_down disposition.
-- ===========================================================================

alter table public.publishers  add column if not exists deletion_requested_at timestamptz;
alter table public.advertisers add column if not exists deletion_requested_at timestamptz;

comment on column public.publishers.deletion_requested_at is
  'Set when a self-serve erasure could not complete immediately (money in flight). An hourly cron '
  're-runs the gate and completes it. NULL once erased or cancelled. Not a protected column.';
comment on column public.advertisers.deletion_requested_at is
  'Set when a self-serve erasure could not complete immediately, or when the advertiser elected '
  'spend_down. An hourly cron completes it. NULL once erased or cancelled.';

-- Neither column is guarded by app.advertisers_protect_cols: its EFFECTIVE definition
-- (20260722200000 §2, which superseded 20260716150000 §8) guards only is_house / status /
-- stripe_customer_id / billing_mode / dispute_hold_at. publishers carries no protect trigger at
-- all. Verified against the live catalog, not from memory — the request/cancel RPCs run as
-- `authenticated` and would raise 42501 here if either column were protected.

-- spend_down joins the disposition set now that app.gdpr_complete_pending() (below) exists to
-- honour it. Phase 2 deliberately withheld it: accepting a value nothing acted on would have been
-- a silent broken promise about a user's money. Extending a CHECK requires drop + recreate —
-- there is no ALTER CONSTRAINT for a CHECK expression. The name below is the one Postgres actually
-- assigned to 20260726100000's inline constraint (confirmed from pg_constraint, not guessed).
alter table public.advertisers drop constraint if exists advertisers_deletion_disposition_check;
alter table public.advertisers add constraint advertisers_deletion_disposition_check
  check (deletion_disposition in ('dormant', 'writeoff', 'spend_down'));

comment on column public.advertisers.deletion_disposition is
  'What is to become of a residual prepaid balance at GDPR erasure: dormant (left on the books as '
  'an unspent, unrecognized liability — the default), writeoff (deliberately zeroed by the '
  'advertiser via advertiser_writeoff_credit()), or spend_down (Phase 3: erasure is DEFERRED until '
  'the credit is exhausted, completed by app.gdpr_complete_pending()). NULL when no erasure has '
  'been requested.';

-- The cron scans exactly this predicate on both tables. Partial, so the index holds only the rows
-- actually pending — normally a handful — and costs nothing once they drain. Both tables are small
-- enough that a plain (non-CONCURRENT) build is a sub-second exclusive lock at deploy time.
create index if not exists publishers_pending_deletion_idx
  on public.publishers (deletion_requested_at)
  where deletion_requested_at is not null and deleted_at is null;

create index if not exists advertisers_pending_deletion_idx
  on public.advertisers (deletion_requested_at)
  where deletion_requested_at is not null and deleted_at is null;

-- ===========================================================================
-- 2. Which refusals are DEFERRALS, and which are terminal.
--
-- This is the single most load-bearing classification in the phase, so it is one function rather
-- than a condition repeated in four places. It is an ALLOW-LIST on purpose: a refusal reason added
-- later defaults to TERMINAL (passed straight back to the caller) rather than to "silently freeze
-- the account and schedule a deletion". The failure mode of guessing wrong in the deferrable
-- direction is an account frozen forever for a deletion that can never complete; in the terminal
-- direction it is the pre-Phase-3 status quo. Only one of those is acceptable to get wrong.
--
-- DEFERRABLE — money in flight. Every one of these self-resolves within days:
--   payout_in_flight            (publisher: a pending/in_transit payout must settle or fail first)
--   topup_pending               (advertiser: a Stripe Checkout deposit is mid-flight)
--   charge_pending              (advertiser: a charge is awaiting confirmation)
--   uncharged_postpay_billings  (advertiser: delivered spend not yet invoiced)
-- TERMINAL — not a timing problem, so scheduling would be a promise that can never be kept:
--   already_deleted   — there is nothing left to erase.
--   house_advertiser  — the house/sentinel org is structurally un-erasable. Scheduling it would
--                       freeze the identity that serves the beta self-promo line, permanently.
-- ===========================================================================
create or replace function app.gdpr_deferrable_reason(p_reason text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select p_reason in ('payout_in_flight', 'topup_pending', 'charge_pending', 'uncharged_postpay_billings');
$$;

revoke all on function app.gdpr_deferrable_reason(text) from public, anon, authenticated;
grant execute on function app.gdpr_deferrable_reason(text) to service_role;

comment on function app.gdpr_deferrable_reason is
  'Classifies an erasure refusal reason as a DEFERRAL (money in flight; self-resolves in days, so '
  'the request enters pending and a cron completes it) or TERMINAL (already_deleted, '
  'house_advertiser; passed straight back). Allow-list, so any future reason defaults to terminal.';

-- ===========================================================================
-- 3. public.gdpr_self_delete() — erase, or enter pending and freeze.
--
-- Signature, grants and the money gate are all UNCHANGED. app.gdpr_erase_publisher is called, never
-- copied: it remains the single authority on whether erasure may proceed, and this wrapper only
-- decides what to do with its answer.
--
-- THE FREEZE IS DEVICE REVOCATION, NOT `status`. window_open already requires
-- `d.revoked_at is null` (20260726110000:36), so revoking the publisher's devices stops serving
-- through an EXISTING check with no change to the money hot path at all. Freezing via
-- publishers.status would be actively harmful: Phase 4's payout_batch_reserve selects on
-- (payout_status='verified' AND status='active' AND deleted_at IS NULL), so a status freeze would
-- block the final payout that phase exists to deliver — to a publisher who is owed it and has
-- asked to leave. status therefore stays 'active' throughout the pending state.
-- ===========================================================================
create or replace function public.gdpr_self_delete()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pid     uuid;
  v_res     jsonb;
  v_reason  text;
  v_at      timestamptz;
  v_devices integer := 0;
begin
  v_pid := (select app.current_publisher_id());
  if v_pid is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;

  v_res := app.gdpr_erase_publisher(v_pid);

  if coalesce((v_res->>'ok')::boolean, false) then
    -- Completed now. Clear the watermark so the column means exactly one thing to every reader —
    -- "an erasure is pending" — and can never be misread as "an erasure happened". The erasure
    -- itself is already recorded by publishers.deleted_at, which is the durable evidence.
    update public.publishers set deletion_requested_at = null where id = v_pid;
    return v_res || jsonb_build_object('state', 'erased');
  end if;

  v_reason := v_res->>'reason';
  if not app.gdpr_deferrable_reason(v_reason) then
    return v_res;   -- terminal (already_deleted) — the pre-Phase-3 contract, byte for byte
  end if;

  -- Enter (or stay in) pending. coalesce is what stops a repeat request from restarting the Art.
  -- 12(3) one-month clock: a user who clicks twice must not silently grant us another month, and
  -- the 25-day overdue alert must keep measuring from the FIRST request.
  update public.publishers
     set deletion_requested_at = coalesce(deletion_requested_at, now())
   where id = v_pid
  returning deletion_requested_at into v_at;

  update public.devices set revoked_at = now()
   where publisher_id = v_pid and revoked_at is null;
  get diagnostics v_devices = row_count;

  return jsonb_build_object(
    'ok',              true,
    'state',           'pending',
    'reason',          v_reason,
    'publisher_id',    v_pid,
    'requested_at',    v_at,
    'devices_revoked', v_devices);
end;
$$;
revoke all on function public.gdpr_self_delete() from public, anon;
grant  execute on function public.gdpr_self_delete() to authenticated;

comment on function public.gdpr_self_delete is
  'Self-serve GDPR erasure for the publisher web portal. Target derived from '
  'app.current_publisher_id() — no argument, so it cannot reach another publisher. Delegates to the '
  'UNCHANGED app.gdpr_erase_publisher. Phase 3: when that refuses for money in flight the request '
  'no longer dead-ends — it records deletion_requested_at, revokes every device (freezing serving '
  'through window_open''s existing revoked_at gate, while publishers.status stays ''active'' for '
  'the Phase 4 final payout) and returns {ok:true, state:''pending''}. app.gdpr_complete_pending() '
  'finishes it. already_deleted stays a terminal {ok:false}.';

-- ===========================================================================
-- 4. public.advertiser_gdpr_self_delete(p_disposition) — erase, or enter pending and freeze.
--
-- CREATE OR REPLACE cannot change an argument list, so the no-argument form must be DROPPED: left
-- in place it would remain as an overload and make the zero-argument call ambiguous — which is
-- exactly how the portal calls it. The new parameter is DEFAULTED, so `select
-- advertiser_gdpr_self_delete()` and a PostgREST POST with a `{}` body both keep working unchanged
-- (verified against PostgREST's overload resolution, which matches a request with no keys to a
-- function whose every parameter has a default).
-- ===========================================================================
drop function if exists public.advertiser_gdpr_self_delete();

create or replace function public.advertiser_gdpr_self_delete(p_disposition text default 'dormant')
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_adv       uuid;
  v_is_house  boolean;
  v_deleted   timestamptz;
  v_bal       bigint := 0;
  v_res       jsonb;
  v_reason    text;
  v_at        timestamptz;
  v_paused_li integer := 0;
  v_paused_cp integer := 0;
  v_li_ids    uuid[]  := '{}';
  v_cp_ids    uuid[]  := '{}';
begin
  v_adv := (select app.current_advertiser_id());
  if v_adv is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;

  -- 'writeoff' is deliberately NOT accepted here. Recording it would claim the residual credit was
  -- zeroed when this function moves no money at all — precisely the silent broken promise Phase 2
  -- refused to make when it withheld spend_down. Zeroing credit stays the separate, explicit
  -- advertiser_writeoff_credit() opt-in, which the advertiser may call before or after erasure.
  if p_disposition is null or p_disposition not in ('dormant', 'spend_down') then
    raise exception
      'disposition must be dormant or spend_down (to forfeit credit, call advertiser_writeoff_credit() explicitly)'
      using errcode = '22023';
  end if;

  -- Classify the two TERMINAL conditions before considering a deferral. app.advertiser_gdpr_erase
  -- re-checks both under FOR UPDATE and remains the authority; this read only decides whether a
  -- schedule is even meaningful. Without it, a spend_down election by the house advertiser (or by
  -- an already-erased org) would be recorded as a pending deletion that can never complete.
  select a.is_house, a.deleted_at into v_is_house, v_deleted
    from public.advertisers a where a.id = v_adv;
  if not found then
    raise exception 'advertiser not found' using errcode = 'P0002';
  end if;
  if v_is_house then
    return jsonb_build_object('ok', false, 'reason', 'house_advertiser');
  end if;
  if v_deleted is not null then
    return jsonb_build_object('ok', false, 'reason', 'already_deleted');
  end if;

  select coalesce(b.balance_micros, 0) + coalesce(b.reserved_micros, 0) into v_bal
    from public.advertiser_balances b where b.advertiser_id = v_adv;
  v_bal := coalesce(v_bal, 0);

  -- spend_down: a DELIBERATE deferral, checked BEFORE the erase attempt. Phase 2 removed the
  -- idle-balance gate, so an advertiser holding credit and nothing in flight erases immediately —
  -- attempting first would destroy the very deferral the user asked for. This is the one path
  -- where the freeze is skipped by design: credit that cannot be spent cannot be spent down.
  if p_disposition = 'spend_down' and v_bal > 0 then
    update public.advertisers
       set deletion_requested_at = coalesce(deletion_requested_at, now()),
           deletion_disposition  = 'spend_down'
     where id = v_adv
    returning deletion_requested_at into v_at;

    -- Logged with EMPTY freeze arrays: spend_down froze nothing, and cancel reads this record to
    -- decide what to restore. Omitting the entry entirely would leave cancel unable to tell
    -- "nothing was paused" from "the record is missing".
    perform app.log_advertiser_action(v_adv, 'gdpr_pending', 'advertiser', v_adv,
      jsonb_build_object('reason', 'spend_down', 'disposition', 'spend_down',
                         'outstanding_micros', v_bal,
                         'campaigns_paused', '[]'::jsonb, 'line_items_paused', '[]'::jsonb));

    return jsonb_build_object(
      'ok', true, 'state', 'pending', 'reason', 'spend_down',
      'advertiser_id', v_adv, 'requested_at', v_at,
      'outstanding_micros', v_bal, 'serving_frozen', false);
  end if;

  v_res := app.advertiser_gdpr_erase(v_adv);

  if coalesce((v_res->>'ok')::boolean, false) then
    update public.advertisers
       set deletion_requested_at = null,
           deletion_disposition  = p_disposition
     where id = v_adv;
    return v_res || jsonb_build_object('state', 'erased');
  end if;

  v_reason := v_res->>'reason';
  if not app.gdpr_deferrable_reason(v_reason) then
    return v_res;   -- terminal — the pre-Phase-3 contract, byte for byte
  end if;

  -- Pending + freeze. coalesce preserves the ORIGINAL request time (the Art. 12(3) clock).
  update public.advertisers
     set deletion_requested_at = coalesce(deletion_requested_at, now()),
         deletion_disposition  = p_disposition
   where id = v_adv
  returning deletion_requested_at into v_at;

  -- Same shape as the erasure body's own pause, so a pending org stops serving exactly the way an
  -- erased one does. The self-serve resume RPCs are gated below, so this cannot be clicked away.
  --
  -- The affected IDS are captured, not just counted. Cancel has to put back exactly what the
  -- freeze took down: a blanket "unpause everything paused" would resurrect campaigns the
  -- advertiser had deliberately stopped long before they ever asked to be deleted, and start
  -- spending their money again. RETURNING into an array is the cheapest precise record available,
  -- and advertiser_action_log is already the audit trail for this org.
  with paused as (
    update public.line_items set status = 'paused'
     where status = 'active'
       and campaign_id in (select id from public.campaigns where advertiser_id = v_adv)
    returning id)
  select coalesce(array_agg(id), '{}'::uuid[]) from paused into v_li_ids;
  v_paused_li := coalesce(array_length(v_li_ids, 1), 0);

  with paused as (
    update public.campaigns set status = 'paused'
     where advertiser_id = v_adv and status = 'active'
    returning id)
  select coalesce(array_agg(id), '{}'::uuid[]) from paused into v_cp_ids;
  v_paused_cp := coalesce(array_length(v_cp_ids, 1), 0);

  perform app.log_advertiser_action(v_adv, 'gdpr_pending', 'advertiser', v_adv,
    jsonb_build_object('reason', v_reason, 'disposition', p_disposition,
                       'campaigns_paused',  to_jsonb(v_cp_ids),
                       'line_items_paused', to_jsonb(v_li_ids)));

  return jsonb_build_object(
    'ok', true, 'state', 'pending', 'reason', v_reason,
    'advertiser_id', v_adv, 'requested_at', v_at,
    'campaigns_paused', v_paused_cp, 'line_items_paused', v_paused_li,
    'serving_frozen', true);
end;
$$;
revoke all on function public.advertiser_gdpr_self_delete(text) from public, anon;
grant  execute on function public.advertiser_gdpr_self_delete(text) to authenticated;

comment on function public.advertiser_gdpr_self_delete is
  'Self-serve GDPR erasure for the advertiser portal. Target derived from '
  'app.current_advertiser_id() — the disposition is the only argument, so it still cannot reach '
  'another org. Delegates to the UNCHANGED app.advertiser_gdpr_erase. Phase 3: p_disposition '
  'dormant (default, preserving the live no-argument call) or spend_down; writeoff is refused here '
  'because this function moves no money — use advertiser_writeoff_credit(). A refusal for money in '
  'flight now enters pending and pauses campaigns/line_items instead of dead-ending; spend_down '
  'enters pending and deliberately KEEPS serving so the credit can actually be spent. '
  'house_advertiser and already_deleted stay terminal and are never scheduled.';

-- ===========================================================================
-- 5. Making the freeze HOLD.
--
-- Revoking devices and pausing campaigns is only a freeze if the account cannot immediately undo
-- it. Left unguarded, a publisher runs `lumaline login` and mints a fresh device; an advertiser
-- clicks Resume. Both would silently un-freeze an account whose owner has asked to be erased —
-- the same defect class the erased-surface audit (20260726110000 / 20260726120000) closed one
-- state later, repeated one state earlier.
--
-- Three functions, each re-declared VERBATIM from its live definer with ONE guard added in the
-- same shape and at the same precedence as the account_deleted guard already beside it. The
-- serving hot path (window_open) is deliberately NOT touched: the freeze needs no change there,
-- because it works through gates window_open already evaluates (devices.revoked_at for the
-- publisher, line_items/campaigns.status for the advertiser).
--
-- RESIDUAL, stated plainly: these close the SELF-SERVE routes. A pending advertiser whose rows are
-- forced back to 'active' behind the RPCs would serve again, because window_open keys serving on
-- deleted_at, not on deletion_requested_at. That is the pre-existing terminal-erasure boundary and
-- is unchanged here; pending is a reversible state by design, and the cron closes it within the
-- hour by setting deleted_at, after which the structural gate applies.
-- ===========================================================================

-- --- 5a. public.device_code_redeem — VERBATIM from 20260629010000:184-230, plus the pending gate.
--         This is the SOLE point at which a public.devices row is ever created, so it is the only
--         place the publisher freeze can be undone.
create or replace function public.device_code_redeem(
  p_device_code_hash   text,
  p_label              text default null,
  p_client_version     text default null,
  p_refresh_token_hash text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r       public.device_auth_codes;
  v_dev   uuid;
  v_user  uuid;
  v_handle text;
begin
  select * into r from public.device_auth_codes where device_code_hash = p_device_code_hash for update;
  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;
  -- Expire lazily so a never-polled-after-approval grant cannot linger.
  if r.expires_at <= now() and r.status in ('pending', 'approved') then
    update public.device_auth_codes set status = 'expired' where id = r.id;
    return jsonb_build_object('status', 'expired');
  end if;
  if r.status = 'pending' then return jsonb_build_object('status', 'authorization_pending'); end if;
  if r.status = 'denied'  then return jsonb_build_object('status', 'denied'); end if;
  if r.status = 'expired' then return jsonb_build_object('status', 'expired'); end if;
  if r.status = 'consumed' then return jsonb_build_object('status', 'consumed'); end if;

  -- *** GDPR P3: a publisher with a deletion pending must not mint a new session. ***
  -- Placed immediately before the mint so every pre-existing status reply is byte-identical. The
  -- grant is deliberately NOT consumed: it is still one-shot, and cancelling the deletion must
  -- leave the user able to finish the login they already approved. auth-device maps an unknown
  -- status to invalid_grant, which the CLI treats as non-retryable, so an undeployed edge function
  -- degrades to a clean refusal rather than an infinite poll.
  if exists (select 1 from public.publishers p
              where p.id = r.publisher_id and p.deletion_requested_at is not null) then
    return jsonb_build_object('status', 'deletion_pending');
  end if;

  -- status = 'approved' -> mint exactly once.
  insert into public.devices (publisher_id, label, client_version, attested, refresh_token_hash)
    values (r.publisher_id, p_label, p_client_version, false, p_refresh_token_hash)
    returning id into v_dev;
  update public.device_auth_codes
     set status = 'consumed', device_id = v_dev, consumed_at = now()
   where id = r.id;
  select auth_user_id, handle into v_user, v_handle from public.publishers where id = r.publisher_id;
  return jsonb_build_object(
    'status', 'approved',
    'publisher_id', r.publisher_id,
    'device_id', v_dev,
    'auth_user_id', v_user,
    'handle', v_handle);
end;
$$;
revoke execute on function public.device_code_redeem(text, text, text, text) from anon, authenticated, public;
grant  execute on function public.device_code_redeem(text, text, text, text) to service_role;

comment on function public.device_code_redeem is
  'service_role ONLY (the auth-device /device/token poll). Maps an RFC 8628 grant to a status; on '
  '''approved'' it CREATES the device row and returns the identity the edge fn needs to mint the '
  'device JWT. One-shot: approved -> consumed. GDPR P3: returns ''deletion_pending'' (without '
  'consuming the grant) when the publisher has a deletion pending — this is the only device-mint '
  'point, so it is where the pending freeze has to hold.';

-- --- 5b/5c. The advertiser resume RPCs — VERBATIM from 20260726110000:356-398 / 405-447 (the live
--            definitions), plus the pending gate. Resume-only, exactly like the A9 dispute hold and
--            the P2 erasure guard beside it: pausing an already-stopped org stays harmless and must
--            remain reachable. spend_down is EXEMPT — its whole purpose is to keep serving.
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

  -- *** GDPR P3: a deletion is pending — the freeze must not be clickable away. Reversible, unlike
  -- the erasure above: advertiser_gdpr_cancel_deletion() lifts it. spend_down is EXEMPT because
  -- deferring erasure until the credit is exhausted requires that the credit stay spendable. ***
  IF p_target = 'active'
     AND EXISTS (SELECT 1 FROM public.advertisers
                  WHERE id = v_adv AND deletion_requested_at IS NOT NULL
                    AND deletion_disposition IS DISTINCT FROM 'spend_down') THEN
    RAISE EXCEPTION 'deletion_pending: an account deletion is pending; cancel it to resume serving'
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
  'Self-serve pause/resume of the caller''s own line_item (assert_owns_line_item FIRST); active<->paused only. Pausing stops serving instantly (window_open needs active). A9: refuses resume while the advertiser is dispute-held. GDPR P2: refuses resume once the advertiser is erased (deleted_at set) — erasure is terminal. GDPR P3: refuses resume while a deletion is pending, unless the disposition is spend_down (which must keep serving). SECDEF; authenticated.';

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

  -- *** GDPR P3: a deletion is pending — the freeze must not be clickable away. Reversible, unlike
  -- the erasure above: advertiser_gdpr_cancel_deletion() lifts it. spend_down is EXEMPT because
  -- deferring erasure until the credit is exhausted requires that the credit stay spendable. ***
  IF p_target = 'active'
     AND EXISTS (SELECT 1 FROM public.advertisers
                  WHERE id = v_adv AND deletion_requested_at IS NOT NULL
                    AND deletion_disposition IS DISTINCT FROM 'spend_down') THEN
    RAISE EXCEPTION 'deletion_pending: an account deletion is pending; cancel it to resume serving'
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
  'Self-serve pause/resume of the caller''s own campaign (assert_owns_campaign FIRST); active<->paused only (draft→active is admin-approval-driven). A9: refuses resume while the advertiser is dispute-held. GDPR P2: refuses resume once the advertiser is erased (deleted_at set) — erasure is terminal. GDPR P3: refuses resume while a deletion is pending, unless the disposition is spend_down (which must keep serving). SECDEF; authenticated.';

-- ===========================================================================
-- 6. app.gdpr_complete_pending() — the hourly completion pass.
--
-- For every row that is pending and not yet erased, re-run the SAME gate by calling the SAME
-- erasure body the request path calls. There is no second implementation of erasure anywhere in
-- this phase, deliberately: two copies of that body is precisely how the ledger, refusal and
-- anonymization invariants would drift apart, and they are the invariants that matter most.
--
-- PER-ROW ISOLATION. Each row's erasure runs inside its own BEGIN/EXCEPTION block, so one stuck
-- account cannot abort the pass and strand every other data subject's deletion behind it. plpgsql
-- implements that with a subtransaction, so a failed row rolls back cleanly on its own. Failures
-- are REPORTED in the `skipped` array, never swallowed — a silently-dropped row would be a missed
-- Art. 17 obligation that no one ever hears about. p_limit bounds the work per call; anything left
-- over is picked up by the next hourly pass, and the overdue alert catches a row that never drains.
--
-- SPEND_DOWN needs one extra condition beyond the shared gate: the credit must actually be gone.
-- Both balance_micros AND reserved_micros must be zero. reserved_micros is money already committed
-- to open serve windows (window_open tests balance - reserved, so a reserve is a hold WITHIN the
-- balance); erasing while a reserve is outstanding would strand a hold that
-- app.advertiser_reconcile_reserved could later "self-heal" by releasing money that was never
-- drawn. Reserves drain on their own via lumaline-sweep-windows, so this cannot deadlock — and if
-- one ever did stick, the 25-day alert surfaces it to a human instead of erasing over it.
--
-- ART. 12(3): the controller must respond within ONE MONTH. A row still pending at 25 days raises
-- app.alert_events, giving five days of margin. The insert/resolve pair mirrors
-- public.monitor_sync_alerts (20260702010000:142-161) exactly, including the ON CONFLICT against
-- the partial unique index on open (check_name, dedup_key) — so an hourly cron cannot spam a new
-- row every hour, and an alert clears itself once the deletion completes. An alert nobody can
-- clear is an alert everybody learns to ignore.
-- ===========================================================================
create or replace function app.gdpr_complete_pending(
  p_overdue interval default interval '25 days',
  p_limit   integer  default 500)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r             record;
  v_res         jsonb;
  v_pub_erased  integer := 0;
  v_adv_erased  integer := 0;
  v_skipped     jsonb   := '[]'::jsonb;
  v_pending_pub bigint  := 0;
  v_pending_adv bigint  := 0;
  v_raised      bigint  := 0;
  v_resolved    bigint  := 0;
begin
  -- --- publishers ---------------------------------------------------------------------------
  for r in
    select p.id
      from public.publishers p
     where p.deletion_requested_at is not null
       and p.deleted_at is null
     order by p.deletion_requested_at
     limit p_limit
  loop
    begin
      v_res := app.gdpr_erase_publisher(r.id);
      if coalesce((v_res->>'ok')::boolean, false) then
        update public.publishers set deletion_requested_at = null where id = r.id;
        v_pub_erased := v_pub_erased + 1;
      end if;
      -- Not ok: still blocked (or a refusal that is not a timing problem). Either way the row
      -- stays pending and the overdue alert below is what escalates it to a human.
    exception when others then
      v_skipped := v_skipped || jsonb_build_object(
        'role', 'publisher', 'id', r.id, 'sqlstate', sqlstate, 'error', sqlerrm);
    end;
  end loop;

  -- --- advertisers --------------------------------------------------------------------------
  for r in
    select a.id, a.deletion_disposition
      from public.advertisers a
     where a.deletion_requested_at is not null
       and a.deleted_at is null
     order by a.deletion_requested_at
     limit p_limit
  loop
    begin
      if r.deletion_disposition = 'spend_down'
         and exists (select 1 from public.advertiser_balances b
                      where b.advertiser_id = r.id
                        and (coalesce(b.balance_micros, 0) > 0 or coalesce(b.reserved_micros, 0) > 0)) then
        null;   -- credit outstanding: still spending down, by the advertiser's own election
      else
        v_res := app.advertiser_gdpr_erase(r.id);
        if coalesce((v_res->>'ok')::boolean, false) then
          -- deletion_disposition is deliberately PRESERVED: it is the record of what became of
          -- the residual credit, and is the only place that answer survives.
          update public.advertisers set deletion_requested_at = null where id = r.id;
          v_adv_erased := v_adv_erased + 1;
        end if;
      end if;
    exception when others then
      v_skipped := v_skipped || jsonb_build_object(
        'role', 'advertiser', 'id', r.id, 'sqlstate', sqlstate, 'error', sqlerrm);
    end;
  end loop;

  -- --- Art. 12(3) overdue alerts, computed AFTER the passes above ----------------------------
  -- so a row completed in this very pass is neither alerted nor left holding a stale open alert.
  with overdue as (
    select 'publisher' as role, p.id::text as subject_id, p.deletion_requested_at as requested_at
      from public.publishers p
     where p.deletion_requested_at is not null
       and p.deleted_at is null
       and p.deletion_requested_at < now() - p_overdue
    union all
    select 'advertiser', a.id::text, a.deletion_requested_at
      from public.advertisers a
     where a.deletion_requested_at is not null
       and a.deleted_at is null
       and a.deletion_requested_at < now() - p_overdue
  ), incoming as (
    select o.role || ':' || o.subject_id as dedup_key,
           jsonb_build_object(
             'role', o.role, 'subject_id', o.subject_id,
             'requested_at', o.requested_at,
             'age_days', floor(extract(epoch from (now() - o.requested_at)) / 86400)) as payload
      from overdue o
  ), ins as (
    insert into app.alert_events (check_name, severity, dedup_key, payload)
    select 'gdpr_pending_overdue', 'high', i.dedup_key, i.payload from incoming i
    on conflict (check_name, dedup_key) where status = 'open' do nothing
    returning 1
  ), res as (
    update app.alert_events e
       set status = 'resolved', resolved_at = now()
     where e.check_name = 'gdpr_pending_overdue'
       and e.status = 'open'
       and not exists (select 1 from incoming i where i.dedup_key = e.dedup_key)
    returning 1
  )
  select (select count(*) from ins), (select count(*) from res) into v_raised, v_resolved;

  select count(*) into v_pending_pub from public.publishers
   where deletion_requested_at is not null and deleted_at is null;
  select count(*) into v_pending_adv from public.advertisers
   where deletion_requested_at is not null and deleted_at is null;

  return jsonb_build_object(
    'publishers_erased',   v_pub_erased,
    'advertisers_erased',  v_adv_erased,
    'still_pending',       v_pending_pub + v_pending_adv,
    'pending_publishers',  v_pending_pub,
    'pending_advertisers', v_pending_adv,
    'alerts_raised',       v_raised,
    'alerts_resolved',     v_resolved,
    'skipped',             v_skipped);
end;
$$;

revoke all on function app.gdpr_complete_pending(interval, integer) from public, anon, authenticated;
grant execute on function app.gdpr_complete_pending(interval, integer) to service_role;

comment on function app.gdpr_complete_pending is
  'Hourly completion pass for GDPR Phase 3 pending deletions. Re-runs the SAME gate by calling the '
  'UNCHANGED app.gdpr_erase_publisher / app.advertiser_gdpr_erase — there is no second erasure '
  'implementation. spend_down additionally requires balance_micros AND reserved_micros to be zero '
  '(a reserve is a hold within the balance; erasing over one would strand it). Each row is '
  'isolated in its own subtransaction so a single stuck account cannot block every other data '
  'subject, and failures are REPORTED in `skipped`, never swallowed. Raises/resolves the '
  'app.alert_events check gdpr_pending_overdue at 25 days, five days inside the Art. 12(3) '
  'one-month deadline. service_role only; NOT scheduled by this migration — see '
  'scripts/ops/pending-deletion-enable.sql.';

-- Migration-tail privilege assertion — the anon-EXECUTE footgun reached production here once.
do $$
declare
  v_fn  text;
  v_fns text[] := array[
    'app.gdpr_complete_pending(interval,integer)',
    'app.gdpr_deferrable_reason(text)',
    'public.gdpr_self_delete()',
    'public.advertiser_gdpr_self_delete(text)',
    'public.device_code_redeem(text,text,text,text)',
    'public.advertiser_set_line_item_status(uuid,text)',
    'public.advertiser_set_campaign_status(uuid,text)'];
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    end if;
  end loop;
  -- The two app.* helpers and the device-mint RPC must not be reachable by a logged-in user either.
  foreach v_fn in array array['app.gdpr_complete_pending(interval,integer)',
                              'app.gdpr_deferrable_reason(text)',
                              'public.device_code_redeem(text,text,text,text)'] loop
    if has_function_privilege('authenticated', v_fn, 'EXECUTE') then
      raise exception 'authenticated retains EXECUTE on % — REVOKE missing', v_fn;
    end if;
  end loop;
end $$;

-- ===========================================================================
-- 7. Cancel — available right up until erasure fires, and not one moment after.
--
-- A pending deletion is the only reversible state in this whole area, and it must be reversible by
-- the data subject alone: the freeze is real, so a user who changes their mind (or whose blocker
-- turns out to take weeks) would otherwise be locked out of their own account with no self-serve
-- way back. Both functions take NO argument — the target comes from the caller's own session, so
-- neither can reach another account.
--
-- Once deleted_at is set there is nothing to cancel. Erasure is terminal (20260726110000): the
-- personal data is already anonymized and the auth email already tombstoned, so "un-erasing" would
-- be a resurrection these functions have no material to perform. Both return already_deleted.
-- ===========================================================================

create or replace function public.gdpr_cancel_deletion()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pid     uuid;
  v_pub     public.publishers%rowtype;
  v_revoked integer := 0;
begin
  v_pid := (select app.current_publisher_id());
  if v_pid is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;

  select * into v_pub from public.publishers where id = v_pid for update;
  if not found then
    raise exception 'publisher not found' using errcode = 'P0002';
  end if;
  if v_pub.deleted_at is not null then
    return jsonb_build_object('ok', false, 'reason', 'already_deleted');
  end if;
  if v_pub.deletion_requested_at is null then
    return jsonb_build_object('ok', false, 'reason', 'not_pending');
  end if;

  update public.publishers set deletion_requested_at = null where id = v_pid;

  -- Devices are deliberately NOT un-revoked. A revoked credential is revoked; silently reviving a
  -- token the user had cause to consider destroyed is the wrong default, and the refresh-token
  -- hashes stored against those rows are exactly the material an attacker would want restored.
  -- The user re-authenticates with `lumaline login` and mints a fresh one — which the mint gate
  -- above now permits again, because the watermark is clear. The payload says so explicitly so the
  -- client can tell the user what to do next instead of leaving them staring at a dead CLI.
  select count(*) into v_revoked
    from public.devices where publisher_id = v_pid and revoked_at is not null;

  return jsonb_build_object(
    'ok',                    true,
    'state',                 'cancelled',
    'publisher_id',          v_pid,
    'devices_still_revoked', v_revoked,
    'next_step',             'run `lumaline login` to authorize a new device');
end;
$$;
revoke all on function public.gdpr_cancel_deletion() from public, anon;
grant  execute on function public.gdpr_cancel_deletion() to authenticated;

comment on function public.gdpr_cancel_deletion is
  'Cancels the caller''s OWN pending GDPR deletion (no argument — target derived from '
  'app.current_publisher_id()). Clears deletion_requested_at, so the completion cron will not pick '
  'the row up and the device-mint gate re-opens. Devices stay REVOKED by design; the returned '
  'payload reports how many and tells the client to re-run login. Refuses with already_deleted '
  'once erasure has fired (it is terminal) and not_pending when nothing is scheduled.';

create or replace function public.advertiser_gdpr_cancel_deletion()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_adv        uuid;
  v_adv_row    public.advertisers%rowtype;
  v_freeze     jsonb;
  v_cp_ids     uuid[] := '{}';
  v_li_ids     uuid[] := '{}';
  v_resumed_cp integer := 0;
  v_resumed_li integer := 0;
begin
  v_adv := (select app.current_advertiser_id());
  if v_adv is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;

  select * into v_adv_row from public.advertisers where id = v_adv for update;
  if not found then
    raise exception 'advertiser not found' using errcode = 'P0002';
  end if;
  if v_adv_row.deleted_at is not null then
    return jsonb_build_object('ok', false, 'reason', 'already_deleted');
  end if;
  if v_adv_row.deletion_requested_at is null then
    return jsonb_build_object('ok', false, 'reason', 'not_pending');
  end if;

  -- Restore EXACTLY what the freeze paused, read back from the record it wrote. Anything the
  -- advertiser had already paused before the request is absent from these arrays and stays paused:
  -- cancel restores, it does not resurrect. A missing record (a row put into pending by hand)
  -- restores nothing rather than guessing — under-restoring is recoverable with one click, while
  -- over-restoring silently puts an ad back on air and starts spending the advertiser's money.
  select l.payload into v_freeze
    from public.advertiser_action_log l
   where l.advertiser_id = v_adv and l.action = 'gdpr_pending'
   order by l.at desc
   limit 1;

  if v_freeze is not null then
    select coalesce(array_agg((e)::uuid), '{}'::uuid[]) into v_cp_ids
      from jsonb_array_elements_text(coalesce(v_freeze->'campaigns_paused',  '[]'::jsonb)) e;
    select coalesce(array_agg((e)::uuid), '{}'::uuid[]) into v_li_ids
      from jsonb_array_elements_text(coalesce(v_freeze->'line_items_paused', '[]'::jsonb)) e;
  end if;

  update public.campaigns set status = 'active'
   where advertiser_id = v_adv and status = 'paused' and id = any (v_cp_ids);
  get diagnostics v_resumed_cp = row_count;

  update public.line_items set status = 'active'
   where status = 'paused' and id = any (v_li_ids)
     and campaign_id in (select id from public.campaigns where advertiser_id = v_adv);
  get diagnostics v_resumed_li = row_count;

  -- The elected disposition goes with the request: it describes what is to become of a residual
  -- balance AT erasure, and there is no longer an erasure for it to describe.
  update public.advertisers
     set deletion_requested_at = null, deletion_disposition = null
   where id = v_adv;

  perform app.log_advertiser_action(v_adv, 'gdpr_cancel', 'advertiser', v_adv,
    jsonb_build_object('campaigns_resumed', v_resumed_cp, 'line_items_resumed', v_resumed_li));

  return jsonb_build_object(
    'ok', true, 'state', 'cancelled', 'advertiser_id', v_adv,
    'campaigns_resumed', v_resumed_cp, 'line_items_resumed', v_resumed_li);
end;
$$;
revoke all on function public.advertiser_gdpr_cancel_deletion() from public, anon;
grant  execute on function public.advertiser_gdpr_cancel_deletion() to authenticated;

comment on function public.advertiser_gdpr_cancel_deletion is
  'Cancels the caller''s OWN pending GDPR deletion (no argument — target derived from '
  'app.current_advertiser_id()). Clears deletion_requested_at + deletion_disposition and resumes '
  'EXACTLY the campaigns/line_items the freeze paused, read back from the gdpr_pending '
  'advertiser_action_log record — never a blanket unpause, which would resurrect campaigns the '
  'advertiser had deliberately stopped and start spending their money again. Refuses with '
  'already_deleted once erasure has fired (it is terminal) and not_pending when nothing is scheduled.';

-- Migration-tail privilege assertion for the cancel pair.
do $$
declare
  v_fn  text;
  v_fns text[] := array['public.gdpr_cancel_deletion()', 'public.advertiser_gdpr_cancel_deletion()'];
begin
  foreach v_fn in array v_fns loop
    if has_function_privilege('anon', v_fn, 'EXECUTE') then
      raise exception 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    end if;
    if not has_function_privilege('authenticated', v_fn, 'EXECUTE') then
      raise exception 'authenticated lost EXECUTE on % — the self-serve cancel is unreachable', v_fn;
    end if;
  end loop;
end $$;
