-- lumaline GDPR Phase 2 (follow-up) — close the ERASED-ADVERTISER SELF-SERVE SURFACE.
--
-- app.advertiser_gdpr_erase (20260726100000) deliberately KEEPS the public.advertiser_users
-- mappings: that is what makes a repeat erasure idempotent (already_deleted) and what keeps
-- public.advertiser_data_export reachable for an erased org. The consequence is that a member of an
-- erased org still resolves app.current_advertiser_id(), so every self-serve advertiser RPC stays
-- callable after erasure.
--
-- 20260726110000 closed only the SPENDING path: window_open excludes deleted_at orgs structurally,
-- and advertiser_set_campaign_status / advertiser_set_line_item_status refuse to RESUME one. That
-- left the whole creation/edit surface open, and — worst of all — the DEPOSIT path: an erased org
-- could still fund an account that can never serve, which is strictly worse than a no-op because it
-- takes real money for a product that structurally cannot be delivered.
--
-- WHAT THIS MIGRATION GATES (refuse once public.advertisers.deleted_at IS NOT NULL):
--   1. public.advertiser_create_campaign
--   2. public.advertiser_create_line_item
--   3. public.advertiser_edit_line_item
--   4. public.advertiser_submit_creative
--   5. public.advertiser_edit_creative
--   6. public.advertiser_update_profile
--   7. public.advertiser_deposit_self_id  (NEW) — the deposit/checkout gate; see §2.
--
-- WHAT THIS MIGRATION DELIBERATELY LEAVES REACHABLE (over-gating here would recreate exactly the
-- class of defect Phase 2 exists to remove — see the Art. 12(2) reasoning in 20260726100000):
--   * public.advertiser_data_export      — the GDPR Art. 15/20 right. An erased data subject must
--                                          still be able to obtain their data. Gating it would make
--                                          erasure destroy the very right it is meant to serve.
--   * public.advertiser_writeoff_credit  — an erased org electing to abandon residual credit is
--                                          legitimate and is the documented opt-in counterpart to
--                                          the dormant-balance default.
--   * The read-only surfaces (advertiser_balance_summary, advertiser_campaigns_summary,
--     advertiser_spend_summary, advertiser_check, advertiser_self_id) — reading your own records
--     after erasure is not a spend and not a write.
--   * advertiser_set_campaign_status / advertiser_set_line_item_status — already gated RESUME-ONLY
--     by 20260726110000. PAUSING must stay permitted: refusing it would strand an erased org in an
--     active state, which is worse than the gap being closed.
--
-- SOURCE OF THE BODIES: all six functions below are defined ONLY in
-- 20260716190000_advertiser_selfserve_rpcs.sql (verified: no later migration redefines them, unlike
-- the status RPCs which 20260722200000 and 20260726110000 both superseded). Each body below is
-- VERBATIM from that file — lines 264-294, 299-368, 375-462, 468-498, 503-540, 623-649 — with the
-- erasure guard as the ONLY addition, and the REVOKE/GRANT/COMMENT lines re-declared byte-identically
-- (CREATE OR REPLACE preserves the ACL, but test/migration-secdef-lint.test.mjs requires a same-file
-- REVOKE per public SECDEF function).
--
-- REFUSAL CONTRACT: none of these six returns {ok:false, reason:…} — every existing refusal in them
-- is a RAISE EXCEPTION with an errcode. So the guard matches the shape already used for erasure by
-- the two status RPCs (20260726110000:383-387): RAISE … USING errcode = '55000', carrying
-- account_deleted in the message so a caller can branch on it.
--
-- GUARD PLACEMENT: immediately after the caller's identity is established — after the v_adv NULL
-- check, and after the assert_owns_* call where the function takes a child id. Same precedence as
-- the A9 dispute hold and the 20260726110000 erasure guard: ownership is asserted FIRST, so an
-- erased org probing another org's ids still gets the ownership error, never a different one.
--
-- UNCONDITIONAL, NOT RESUME-ONLY: unlike the status RPCs, none of these six has a resume/activate
-- semantic — create_* only ever writes 'draft', submit/edit_creative only ever write
-- 'pending_review' (approval is reviewer-only), and edit_line_item cannot write status at all. So
-- gating them unconditionally cannot strand an erased org in an active state, and there is no
-- pause-equivalent that must stay open.

-- ===========================================================================
-- 1. The six self-serve creation/edit RPCs.
-- ===========================================================================

-- --- create_campaign -------------------------------------------------------
CREATE OR REPLACE FUNCTION public.advertiser_create_campaign(p_name text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv uuid;
  v_id  uuid;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  -- *** GDPR P2: erasure is TERMINAL — an erased org cannot create new commercial objects. ***
  IF EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; it can no longer be modified'
      USING errcode = '55000';
  END IF;

  IF p_name IS NULL OR length(btrim(p_name)) = 0 THEN
    RAISE EXCEPTION 'campaign name must not be empty' USING errcode = '23514';
  END IF;
  IF length(p_name) > 200 THEN
    RAISE EXCEPTION 'campaign name exceeds 200 characters' USING errcode = '23514';
  END IF;

  INSERT INTO public.campaigns (advertiser_id, name, status)
    VALUES (v_adv, btrim(p_name), 'draft')
    RETURNING id INTO v_id;

  RETURN jsonb_build_object('campaign_id', v_id, 'status', 'draft');
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_create_campaign(text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_create_campaign(text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_create_campaign IS
  'Self-serve: create a draft campaign under the caller''s own advertiser (advertiser_id from current_advertiser_id(), never a client arg). GDPR P2: refuses once the advertiser is erased (deleted_at set). SECDEF; granted to authenticated.';

-- --- create_line_item ------------------------------------------------------
-- FORCE cpc=0 (CPVA-only self-serve) + cpva>=floor + targeting '{}' (v1 global) + status 'draft'.
-- assert_owns_campaign FIRST closes the child-FK IDOR (create under another org's campaign).
CREATE OR REPLACE FUNCTION public.advertiser_create_line_item(
  p_campaign_id           uuid,
  p_cpva_bid_micros       bigint,
  p_weight                integer     DEFAULT 1,
  p_budget_total_micros   bigint      DEFAULT NULL,
  p_budget_daily_micros   bigint      DEFAULT NULL,
  p_pacing_mode           text        DEFAULT 'even',
  p_frequency_cap_per_day integer     DEFAULT NULL,
  p_start_at              timestamptz DEFAULT NULL,
  p_end_at                timestamptz DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv    uuid;
  v_id     uuid;
  v_weight integer := COALESCE(p_weight, 1);
  v_pacing text    := COALESCE(p_pacing_mode, 'even');
  v_floor  bigint  := app.advertiser_min_bid_micros();
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  -- Ownership FIRST — derive nothing from the client beyond the asserted campaign id.
  PERFORM app.assert_owns_campaign(p_campaign_id);

  -- *** GDPR P2: erasure is TERMINAL — an erased org cannot create new commercial objects. ***
  IF EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; it can no longer be modified'
      USING errcode = '55000';
  END IF;

  -- Structural self-serve invariants (matched by the line_items_selfserve_bids CHECK).
  IF p_cpva_bid_micros IS NULL OR p_cpva_bid_micros < v_floor THEN
    RAISE EXCEPTION 'cpva bid % is below the minimum bid floor %', p_cpva_bid_micros, v_floor
      USING errcode = '23514';
  END IF;
  IF v_weight <= 0 THEN
    RAISE EXCEPTION 'weight must be positive' USING errcode = '23514';
  END IF;
  IF v_pacing NOT IN ('even', 'asap') THEN
    RAISE EXCEPTION 'pacing_mode must be even or asap' USING errcode = '23514';
  END IF;
  IF p_budget_total_micros IS NOT NULL AND p_budget_total_micros < 0 THEN
    RAISE EXCEPTION 'budget_total_micros must be >= 0' USING errcode = '23514';
  END IF;
  IF p_budget_daily_micros IS NOT NULL AND p_budget_daily_micros < 0 THEN
    RAISE EXCEPTION 'budget_daily_micros must be >= 0' USING errcode = '23514';
  END IF;
  IF p_frequency_cap_per_day IS NOT NULL AND p_frequency_cap_per_day < 0 THEN
    RAISE EXCEPTION 'frequency_cap_per_day must be >= 0' USING errcode = '23514';
  END IF;
  IF p_start_at IS NOT NULL AND p_end_at IS NOT NULL AND p_end_at <= p_start_at THEN
    RAISE EXCEPTION 'end_at must be after start_at' USING errcode = '23514';
  END IF;

  INSERT INTO public.line_items (
      campaign_id, cpva_bid_micros, cpc_bid_micros, weight,
      budget_total_micros, budget_daily_micros, pacing_mode, frequency_cap_per_day,
      start_at, end_at, targeting, status)
    VALUES (
      p_campaign_id, p_cpva_bid_micros, 0, v_weight,               -- cpc FORCED 0
      p_budget_total_micros, p_budget_daily_micros, v_pacing::public.pacing_mode, p_frequency_cap_per_day,
      p_start_at, p_end_at, '{}'::jsonb, 'draft')                  -- targeting FORCED global v1
    RETURNING id INTO v_id;

  RETURN jsonb_build_object('line_item_id', v_id, 'status', 'draft', 'cpc_bid_micros', 0);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_create_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_create_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz) TO authenticated;

COMMENT ON FUNCTION public.advertiser_create_line_item IS
  'Self-serve: create a draft CPVA-only line_item under the caller''s own campaign (assert_owns_campaign FIRST). Forces cpc_bid_micros=0, cpva>=advertiser_min_bid_micros(), targeting global, status draft. GDPR P2: refuses once the advertiser is erased (deleted_at set). SECDEF; granted to authenticated.';

-- --- edit_line_item --------------------------------------------------------
-- Only a draft/paused line_item is editable. FORCE cpc=0 + min-bid. On a cpva-bid CHANGE, reset the
-- owning ACTIVE creatives to pending_review (a signed creative may not be silently re-priced below
-- floor or given a click bid after approval); delivery-only edits (budget/pacing/dates/weight/cap) do
-- NOT reset moderation.
CREATE OR REPLACE FUNCTION public.advertiser_edit_line_item(
  p_id                    uuid,
  p_cpva_bid_micros       bigint,
  p_weight                integer     DEFAULT 1,
  p_budget_total_micros   bigint      DEFAULT NULL,
  p_budget_daily_micros   bigint      DEFAULT NULL,
  p_pacing_mode           text        DEFAULT 'even',
  p_frequency_cap_per_day integer     DEFAULT NULL,
  p_start_at              timestamptz DEFAULT NULL,
  p_end_at                timestamptz DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv       uuid;
  v_status    public.line_item_status;
  v_old_cpva  bigint;
  v_weight    integer := COALESCE(p_weight, 1);
  v_pacing    text    := COALESCE(p_pacing_mode, 'even');
  v_floor     bigint  := app.advertiser_min_bid_micros();
  v_reset     integer := 0;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  PERFORM app.assert_owns_line_item(p_id);   -- ownership FIRST

  -- *** GDPR P2: erasure is TERMINAL — an erased org cannot edit its commercial objects. ***
  IF EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; it can no longer be modified'
      USING errcode = '55000';
  END IF;

  SELECT status, cpva_bid_micros INTO v_status, v_old_cpva
    FROM public.line_items WHERE id = p_id;
  IF v_status NOT IN ('draft', 'paused') THEN
    RAISE EXCEPTION 'line item must be draft or paused to edit (is %)', v_status
      USING errcode = '55000';
  END IF;

  IF p_cpva_bid_micros IS NULL OR p_cpva_bid_micros < v_floor THEN
    RAISE EXCEPTION 'cpva bid % is below the minimum bid floor %', p_cpva_bid_micros, v_floor
      USING errcode = '23514';
  END IF;
  IF v_weight <= 0 THEN
    RAISE EXCEPTION 'weight must be positive' USING errcode = '23514';
  END IF;
  IF v_pacing NOT IN ('even', 'asap') THEN
    RAISE EXCEPTION 'pacing_mode must be even or asap' USING errcode = '23514';
  END IF;
  IF p_budget_total_micros IS NOT NULL AND p_budget_total_micros < 0 THEN
    RAISE EXCEPTION 'budget_total_micros must be >= 0' USING errcode = '23514';
  END IF;
  IF p_budget_daily_micros IS NOT NULL AND p_budget_daily_micros < 0 THEN
    RAISE EXCEPTION 'budget_daily_micros must be >= 0' USING errcode = '23514';
  END IF;
  IF p_frequency_cap_per_day IS NOT NULL AND p_frequency_cap_per_day < 0 THEN
    RAISE EXCEPTION 'frequency_cap_per_day must be >= 0' USING errcode = '23514';
  END IF;
  IF p_start_at IS NOT NULL AND p_end_at IS NOT NULL AND p_end_at <= p_start_at THEN
    RAISE EXCEPTION 'end_at must be after start_at' USING errcode = '23514';
  END IF;

  UPDATE public.line_items SET
      cpva_bid_micros       = p_cpva_bid_micros,
      cpc_bid_micros        = 0,                                   -- FORCED 0
      weight                = v_weight,
      budget_total_micros   = p_budget_total_micros,
      budget_daily_micros   = p_budget_daily_micros,
      pacing_mode           = v_pacing::public.pacing_mode,
      frequency_cap_per_day = p_frequency_cap_per_day,
      start_at              = p_start_at,
      end_at                = p_end_at
    WHERE id = p_id;

  -- A material (bid) change forces re-moderation of already-approved creatives.
  IF p_cpva_bid_micros IS DISTINCT FROM v_old_cpva THEN
    UPDATE public.creatives
       SET status = 'pending_review'
     WHERE line_item_id = p_id AND status = 'active';
    GET DIAGNOSTICS v_reset = ROW_COUNT;
  END IF;

  RETURN jsonb_build_object('line_item_id', p_id, 'status', v_status,
                            'cpc_bid_micros', 0, 'creatives_reset', v_reset);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_edit_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_edit_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz) TO authenticated;

COMMENT ON FUNCTION public.advertiser_edit_line_item IS
  'Self-serve edit of a draft/paused line_item (assert_owns_line_item FIRST): forces cpc=0 + cpva>=floor; a cpva-bid change resets owning ACTIVE creatives to pending_review (no silent re-pricing below floor / cpc after approval); delivery-only edits do not reset. GDPR P2: refuses once the advertiser is erased (deleted_at set). SECDEF; authenticated.';

-- --- submit_creative -------------------------------------------------------
-- Always lands 'pending_review' — a creative can NEVER reach 'active' via a self-serve path (approval
-- is reviewer-only, 20260716200000). Validator runs for a clean UX error; the content TRIGGER is the
-- structural gate.
CREATE OR REPLACE FUNCTION public.advertiser_submit_creative(
  p_line_item_id uuid, p_line text, p_dest_url text DEFAULT NULL, p_label text DEFAULT 'sponsored')
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv   uuid;
  v_id    uuid;
  v_label text := COALESCE(NULLIF(btrim(p_label), ''), 'sponsored');
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  PERFORM app.assert_owns_line_item(p_line_item_id);   -- ownership FIRST

  -- *** GDPR P2: erasure is TERMINAL — an erased org cannot submit new creative content. ***
  IF EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; it can no longer be modified'
      USING errcode = '55000';
  END IF;

  PERFORM app.validate_disclosure_label(v_label);      -- structural disclosure-label allow-list
  PERFORM app.validate_creative_content(p_line, v_label, p_dest_url);   -- UX error (trigger re-checks)

  INSERT INTO public.creatives (line_item_id, line, dest_url, label, status)
    VALUES (p_line_item_id, p_line, p_dest_url, v_label, 'pending_review')
    RETURNING id INTO v_id;

  RETURN jsonb_build_object('creative_id', v_id, 'status', 'pending_review');
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_submit_creative(uuid, text, text, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_submit_creative(uuid, text, text, text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_submit_creative IS
  'Self-serve: submit a creative under the caller''s own line_item (assert_owns_line_item FIRST) at status pending_review — never active (approval is reviewer-only). Content validated (RPC UX + the load-bearing table TRIGGER). GDPR P2: refuses once the advertiser is erased (deleted_at set). SECDEF; authenticated.';

-- --- edit_creative ---------------------------------------------------------
-- Editable only while pending_review/rejected/paused (never a live 'active' row — pause it first).
-- Re-validates and resets to pending_review for re-moderation.
CREATE OR REPLACE FUNCTION public.advertiser_edit_creative(
  p_id uuid, p_line text, p_dest_url text DEFAULT NULL, p_label text DEFAULT 'sponsored')
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv    uuid;
  v_status public.creative_status;
  v_label  text := COALESCE(NULLIF(btrim(p_label), ''), 'sponsored');
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  PERFORM app.assert_owns_creative(p_id);   -- ownership FIRST

  -- *** GDPR P2: erasure is TERMINAL — an erased org cannot edit its creative content. ***
  IF EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; it can no longer be modified'
      USING errcode = '55000';
  END IF;

  SELECT status INTO v_status FROM public.creatives WHERE id = p_id;
  IF v_status NOT IN ('pending_review', 'rejected', 'paused') THEN
    RAISE EXCEPTION 'creative must be pending_review, rejected or paused to edit (is %)', v_status
      USING errcode = '55000';
  END IF;

  PERFORM app.validate_disclosure_label(v_label);      -- structural disclosure-label allow-list
  PERFORM app.validate_creative_content(p_line, v_label, p_dest_url);

  UPDATE public.creatives
     SET line = p_line, dest_url = p_dest_url, label = v_label, status = 'pending_review'
   WHERE id = p_id;

  RETURN jsonb_build_object('creative_id', p_id, 'status', 'pending_review');
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_edit_creative(uuid, text, text, text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_edit_creative(uuid, text, text, text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_edit_creative IS
  'Self-serve edit of a pending_review/rejected/paused creative (assert_owns_creative FIRST): re-validate + reset to pending_review. Cannot touch a live active creative (pause it first). GDPR P2: refuses once the advertiser is erased (deleted_at set). SECDEF; authenticated.';

-- --- update_profile (display name only) ------------------------------------
-- Column-scoped to name; is_house/status/stripe_customer_id/billing_mode are structurally unwritable
-- (the advertisers_protect_cols column-diff trigger, 20260716150000, blocks a protected-column change
-- for a non-service_role request even under this SECDEF path). The advertiser org name never appears
-- in a served creative (only line+label, both content-guarded), so it is an internal/admin-facing
-- field; reviewer scrutiny of names (impersonation) is a soft ops concern handled by the reviewer
-- tier (20260716200000), not a signing/trust gate.
--
-- The erasure guard matters MOST here: app.advertiser_gdpr_erase anonymizes the org name in place to
-- 'deleted-<8hex>'. Without this guard a still-mapped member could simply rename the org back and
-- UNDO the anonymization — the erasure would be cosmetically reversible by the very party it ran for.
CREATE OR REPLACE FUNCTION public.advertiser_update_profile(p_name text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv uuid;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  -- *** GDPR P2: erasure is TERMINAL — renaming an erased org would UNDO its anonymization. ***
  IF EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased; it can no longer be modified'
      USING errcode = '55000';
  END IF;

  IF p_name IS NULL OR length(btrim(p_name)) = 0 THEN
    RAISE EXCEPTION 'name must not be empty' USING errcode = '23514';
  END IF;
  IF length(p_name) > 120 THEN
    RAISE EXCEPTION 'name exceeds 120 characters' USING errcode = '23514';
  END IF;

  UPDATE public.advertisers SET name = btrim(p_name) WHERE id = v_adv;   -- only `name`; protected cols untouched
  RETURN jsonb_build_object('advertiser_id', v_adv, 'name', btrim(p_name));
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_update_profile(text) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_update_profile(text) TO authenticated;

COMMENT ON FUNCTION public.advertiser_update_profile IS
  'Self-serve update of the caller''s own advertiser display name ONLY (column-scoped; the advertisers_protect_cols trigger blocks is_house/status/stripe_customer_id/billing_mode). GDPR P2: refuses once the advertiser is erased (deleted_at set) — otherwise a rename would undo the erasure''s in-place anonymization. SECDEF; authenticated.';

-- ===========================================================================
-- 2. The DEPOSIT gate — public.advertiser_deposit_self_id().
--
-- WHY A NEW FUNCTION RATHER THAN A GUARD INSIDE AN EXISTING ONE:
--
-- The deposit path is supabase/functions/advertiser-portal POST /funding/checkout. It resolves the
-- depositing org server-side via public.advertiser_self_id (JWT-derived; a body advertiser_id is
-- ignored), then creates a Stripe Checkout session and stamps public.advertiser_topup_intents — the
-- server-stored authority the webhook credits from (never event metadata).
--
-- advertiser_self_id itself MUST NOT be gated: it is the shared identity primitive behind the
-- read-only surfaces, which stay reachable after erasure. So the deposit path gets its OWN
-- identity resolver carrying the gate, and the edge function calls THIS one on the checkout path.
-- The rule therefore lives in SQL, in one place, next to every other erasure guard — the edge
-- function only surfaces the database's refusal, it does not define it.
--
-- WHY THE GATE IS HERE AND NOT AT THE CREDIT SEAM (app.advertiser_credit_deposit) OR ON A
-- topup_intents INSERT TRIGGER — this is a money-safety ordering decision, not a convenience one:
--
--   The only correct place to refuse a deposit is BEFORE the Stripe Checkout session exists, i.e.
--   before the customer can be charged. Both alternatives sit AFTER it:
--     * A refusal inside app.advertiser_credit_deposit fires when the card has ALREADY been
--       captured — the customer is charged and the credit is refused. That strands real money.
--     * A BEFORE INSERT trigger on advertiser_topup_intents fires after the session is created too
--       (the row is keyed by checkout_session_id, which does not exist until Stripe mints it). A
--       failed insert leaves a live, payable session with no credit-authority row, so a customer who
--       completes it is charged and the webhook then finds no intent and credits nothing.
--   Both convert a recoverable failure ("an erased org was credited" — visible on the books,
--   reversible by admin adjustment or write-off) into an unrecoverable one ("charged, no record").
--   For a live real-money system that is the wrong trade, so neither is added.
--
-- ON BYPASSABILITY: the usual objection to an edge-function check — that a direct PostgREST call
-- routes around it — does not apply to this path. `authenticated` holds SELECT-only on
-- public.advertiser_topup_intents (no INSERT/UPDATE grant, 20260716170000:204) and
-- app.advertiser_credit_deposit is service_role-only (20260716170000:466-467). There is no
-- authenticated-reachable deposit write in the database at all, so the edge function is the sole
-- self-serve entry to the deposit path and gating its identity resolver closes it completely.
-- ===========================================================================
CREATE OR REPLACE FUNCTION public.advertiser_deposit_self_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_adv uuid;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());

  -- Same contract as advertiser_self_id for a session mapped to no org: NULL, not a raise. The
  -- caller (advertiser-portal) already turns that into its own 403.
  IF v_adv IS NULL THEN
    RETURN NULL;
  END IF;

  -- *** GDPR P2: an erased org may never be funded. Refusing HERE is pre-money — the caller has not
  -- yet created a Stripe Checkout session, so nothing can be charged and nothing is stranded. ***
  IF EXISTS (SELECT 1 FROM public.advertisers WHERE id = v_adv AND deleted_at IS NOT NULL) THEN
    RAISE EXCEPTION 'account_deleted: this advertiser account has been erased and can no longer be funded'
      USING errcode = '55000';
  END IF;

  RETURN v_adv;
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_deposit_self_id() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_deposit_self_id() TO authenticated, service_role;

COMMENT ON FUNCTION public.advertiser_deposit_self_id IS
  'Deposit-path identity resolver: the caller''s own advertiser id (from app.current_advertiser_id(), never a client arg), or NULL if the session maps to no org — but RAISES account_deleted (55000) once that advertiser is erased. advertiser-portal POST /funding/checkout calls THIS instead of advertiser_self_id so an erased org can never open a Checkout session and fund an account that structurally cannot serve. Deliberately a separate function: advertiser_self_id stays ungated for the read-only surfaces, which remain reachable after erasure. SECDEF; authenticated + service_role.';

-- ===========================================================================
-- 3. Migration-tail privilege assertion — anon must hold NO EXECUTE on any function touched here.
-- CREATE OR REPLACE preserves the ACL, but the REVOKEs above are re-declared anyway (the
-- secdef_grant_hardening footgun reached prod once, and the static lint requires them); this block
-- fails the migration loudly if any of them is ever dropped.
-- ===========================================================================
DO $$
DECLARE
  v_fn  text;
  v_fns text[] := ARRAY[
    'public.advertiser_create_campaign(text)',
    'public.advertiser_create_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz)',
    'public.advertiser_edit_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz)',
    'public.advertiser_submit_creative(uuid, text, text, text)',
    'public.advertiser_edit_creative(uuid, text, text, text)',
    'public.advertiser_update_profile(text)',
    'public.advertiser_deposit_self_id()'
  ];
BEGIN
  FOREACH v_fn IN ARRAY v_fns LOOP
    IF has_function_privilege('anon', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    END IF;
  END LOOP;
END;
$$;

-- ===========================================================================
-- 4. Assertion: the DO-NOT-GATE surfaces are still callable — this migration must not have
-- over-gated. A guard accidentally added to the Art. 15/20 export or to the opt-in write-off would
-- be a REGRESSION of Phase 2's whole premise, so assert their bodies stay free of a deleted_at
-- refusal rather than trusting that nobody edited them.
-- ===========================================================================
DO $$
DECLARE
  v_fn  text;
  v_src text;
  v_fns text[] := ARRAY['advertiser_data_export', 'advertiser_writeoff_credit', 'advertiser_self_id'];
BEGIN
  FOREACH v_fn IN ARRAY v_fns LOOP
    SELECT p.prosrc INTO v_src
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.proname = v_fn;
    IF v_src IS NULL THEN
      RAISE EXCEPTION 'public.% is missing — the ungated GDPR surface must exist', v_fn;
    END IF;
    IF v_src ILIKE '%account_deleted%' THEN
      RAISE EXCEPTION 'public.% carries an account_deleted refusal — it MUST stay reachable after erasure (Art. 15/20)', v_fn;
    END IF;
  END LOOP;
END;
$$;
