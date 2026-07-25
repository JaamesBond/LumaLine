-- lumaline GDPR Phase 2 — split personal-data erasure from commercial closure.
--
-- app.advertiser_gdpr_erase refused while advertiser_balances.balance_micros > 0. Combined with
-- non-refundable deposits and the deliberate absence of any withdrawal RPC (20260716200000: the
-- only exits are delivered spend, a card dispute, an admin clawback, or an admin correction), an
-- advertiser holding unspent credit could NEVER complete an Art. 17 erasure. Not "later" — never.
--
-- The root cause is a category error: one check gated both the erasure of a NATURAL PERSON'S
-- personal data (member auth emails) and the settlement of a LEGAL ENTITY'S money. GDPR protects
-- the former; the balance belongs to the latter. Art. 12(2) requires the controller to FACILITATE
-- the exercise of data-subject rights, so conditioning erasure on money the user cannot reach is
-- the wrong shape regardless of what the ToS says about refundability.
--
-- WHAT IS REMOVED: the idle-balance gate only.
-- WHAT STAYS: house_advertiser, already_deleted, topup_pending, charge_pending and
-- uncharged_postpay_billings. Those are in-flight TRANSACTIONS, not idle credit — they resolve on
-- their own within days and erasing mid-transaction would strand money in an unreconcilable state.
--
-- The residual balance is left ON THE BOOKS as an unspent liability. It is NOT swept to the
-- platform: recognizing forfeited prepaid credit as revenue is "breakage", which needs a stated
-- accounting policy and EU VAT analysis that do not exist. Task 2 adds an explicit, opt-in
-- writeoff for an advertiser who wants to zero it deliberately.

create or replace function app.advertiser_gdpr_erase(p_advertiser_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
DECLARE
  v_adv        public.advertisers%ROWTYPE;
  v_claims     text;
  v_paused_li  integer := 0;
  v_paused_cp  integer := 0;
  v_emails     integer := 0;
BEGIN
  SELECT * INTO v_adv FROM public.advertisers WHERE id = p_advertiser_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'advertiser not found' USING errcode = 'P0002';
  END IF;

  -- Never erase the house/sentinel advertiser.
  IF v_adv.is_house THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'house_advertiser');
  END IF;

  -- Idempotent.
  IF v_adv.deleted_at IS NOT NULL THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'already_deleted');
  END IF;

  -- Money-safety: refuse while ANY money is in flight (funds + reserve must settle first).
  IF EXISTS (SELECT 1 FROM public.advertiser_topup_intents t
              WHERE t.advertiser_id = p_advertiser_id AND t.status = 'pending') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'topup_pending');
  END IF;
  IF EXISTS (SELECT 1 FROM public.advertiser_charges ac
              WHERE ac.advertiser_id = p_advertiser_id AND ac.status = 'pending') THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'charge_pending');
  END IF;
  IF EXISTS (SELECT 1 FROM public.uncharged_advertiser_billings u
              WHERE u.advertiser_id = p_advertiser_id) THEN
    RETURN jsonb_build_object('ok', false, 'reason', 'uncharged_postpay_billings');
  END IF;

  -- Stop serving: pause the org's active campaigns + line_items (NOT the protected advertiser status).
  UPDATE public.line_items SET status = 'paused'
   WHERE status = 'active'
     AND campaign_id IN (SELECT id FROM public.campaigns WHERE advertiser_id = p_advertiser_id);
  GET DIAGNOSTICS v_paused_li = ROW_COUNT;
  UPDATE public.campaigns SET status = 'paused'
   WHERE advertiser_id = p_advertiser_id AND status = 'active';
  GET DIAGNOSTICS v_paused_cp = ROW_COUNT;

  -- Anonymize the advertiser row IN PLACE (name + stripe_customer_id + deleted_at). stripe_customer_id
  -- is a protected column → briefly present a service_role role claim to the protect trigger.
  v_claims := current_setting('request.jwt.claims', true);
  PERFORM set_config('request.jwt.claims',
    (coalesce(nullif(v_claims, ''), '{}')::jsonb || jsonb_build_object('role', 'service_role'))::text, true);

  UPDATE public.advertisers
     SET name               = 'deleted-' || left(id::text, 8),
         stripe_customer_id = NULL,
         deleted_at         = now()
   WHERE id = p_advertiser_id;

  PERFORM set_config('request.jwt.claims', coalesce(v_claims, ''), true);   -- restore

  -- Tombstone the auth identity of every mapped member (the strongest PII: email). Done in place so
  -- the advertiser_users→auth.users FK is preserved (mappings kept so current_advertiser_id() still
  -- resolves for an idempotent repeat call, mirroring gdpr_self_delete's keep-in-place semantics).
  UPDATE auth.users u SET
    email              = 'deleted-' || left(u.id::text, 8) || '@deleted.invalid',
    phone              = NULL,
    raw_user_meta_data = '{}'::jsonb,
    raw_app_meta_data  = '{}'::jsonb
  WHERE u.id IN (SELECT auth_user_id FROM public.advertiser_users WHERE advertiser_id = p_advertiser_id);
  GET DIAGNOSTICS v_emails = ROW_COUNT;

  -- advertiser_balance_ledger + advertiser_action_log are PRESERVED (financial/audit records; they
  -- carry no user-authored free-text — creative copy lives in creatives, which no longer serves).
  PERFORM app.log_advertiser_action(p_advertiser_id, 'gdpr_erase', 'advertiser', p_advertiser_id,
    jsonb_build_object('emails_tombstoned', v_emails, 'campaigns_paused', v_paused_cp,
                       'line_items_paused', v_paused_li));

  RETURN jsonb_build_object('ok', true, 'advertiser_id', p_advertiser_id,
                            'emails_tombstoned', v_emails,
                            'campaigns_paused', v_paused_cp, 'line_items_paused', v_paused_li);
END;
$$;

comment on function app.advertiser_gdpr_erase is
  'Private shared body for advertiser GDPR erasure. Phase 2 removed the idle-balance gate: an '
  'unspent, non-refundable balance can never block Art. 17 erasure. In-flight transactions '
  '(topup_pending / charge_pending / uncharged_postpay_billings), the house advertiser and a '
  'repeat call still refuse. Residual credit is left on the books as an unrecognized liability.';
