-- lumaline M9-T4 — advertiser self-serve write boundary: ownership asserts, the creative content
-- TRIGGER, and the guard-railed CRUD RPCs that replace admin-booking's POST routes for advertisers.
--
-- 20260716150000 REVOKEd INSERT/UPDATE/DELETE on advertisers/campaigns/line_items/creatives FROM
-- authenticated, so a crafted PostgREST write from an advertiser session now matches NO grant. This
-- migration ships the ONLY write path advertisers get: self-scoped SECURITY DEFINER RPCs. Because a
-- SECDEF RPC runs as the function owner and BYPASSES the now-locked table RLS (exactly like
-- window_open, true_total_budget_cap.sql:8-9), the RPC body is the entire isolation boundary — so:
--
--   1. app.assert_owns_campaign/line_item/creative(uuid) — mandatory SECDEF assertion helpers, each
--      RAISEing 28000 unless the FK chain terminates at (SELECT app.current_advertiser_id()). EVERY
--      write RPC that takes a client-passed child id calls the matching assert as its FIRST statement
--      and derives ids from the resolved row, never the argument — closing the child-FK IDOR (an
--      advertiser cannot create a line_item under another org's campaign, submit a creative under
--      another org's line_item, or flip another org's campaign/line_item/creative). One audited
--      primitive, not eight prose repetitions.
--
--   2. app.validate_creative_content + the BEFORE INSERT OR UPDATE TRIGGER app.creative_content_guard
--      on public.creatives — the LOAD-BEARING content gate. lumaline-feed signs the DB creative
--      VERBATIM (lumaline-feed/index.ts:111-117) and admin-booking's POST /creatives + PATCH activate
--      validate NOTHING (admin-booking/index.ts:106-167,259-280). A table trigger makes the byte-
--      sanitizer structural on EVERY write path — self-serve RPC, admin-booking, direct service_role,
--      future writers — so no un-sanitized creative can ever exist at status='active' where it would
--      be signed. The RPCs also call the validator directly for a fast, specific UX error; the
--      trigger delegates to the SAME validator so the two can never drift (validator/trigger parity).
--      Human §4-prohibited-category review stays the separate reviewer-only pending_review→active step
--      (20260716200000); NOTHING here sets a creative to 'active'.
--
--   3. The self-scoped CRUD RPCs (create/edit/pause campaigns/line_items/creatives, update profile)
--      + the CPVA-only/min-bid forcing in-body. cpc_bid_micros is forced 0 and cpva>=the single-source
--      floor app.advertiser_min_bid_micros() on every create/edit, matched by the structural
--      line_items CHECK (shipped 20260716180000, re-asserted idempotently below). A cpva-bid change
--      resets the owning ACTIVE creatives to pending_review so a signed creative can never be silently
--      re-priced below floor or given a click bid after approval.
--
--   4. advertiser_campaigns_summary() / advertiser_spend_summary() — self-scoped aggregate reads.
--      spend is CPVA-only (impressions attention billing; clicks/CPC never read) and AGGREGATE — NO
--      per-publisher rows, NO ledger_entries exposure (data-minimization; advertisers never see a
--      publisher identity or a ledger leg).
--
-- CONVENTIONS (secdef_grant_hardening.sql lesson, 20260716150000/170000 style):
--   * app.* helpers (asserts / validator / trigger fn): definer-internal — `REVOKE ALL ... FROM
--     PUBLIC, anon, authenticated` (the owner calls them via ownership from the SECDEF RPCs + the
--     SECDEF trigger; no role grant needed). off the Data API (app schema, config.toml:13).
--   * public self-serve RPCs: SECDEF search_path='', re-derive current_advertiser_id() every call,
--     `REVOKE ALL ... FROM PUBLIC, anon` (not just anon — anon inherits the auto-granted PUBLIC
--     EXECUTE, the footgun that reached prod) then `GRANT EXECUTE ... TO authenticated`.
--   * migration tail RAISEs if anon retains EXECUTE on ANY function added here.
--
-- DEPENDS ON: 20260716150000 (advertiser_users, app.current_advertiser_id, the DML lockdown,
-- advertisers_protect_cols) + 20260716170000 (app.advertiser_min_bid_micros) + 20260716180000
-- (public.check_selfserve_line_item + the line_items_selfserve_bids CHECK, re-asserted below).
--
-- T4b (content trigger vs currently-serving rows): every existing creative is safe — the house
-- self-promo ('LumaLine — honest, signed ads for Claude Code' / https://lumaline.dev / 'sponsored',
-- seed.prod.sql:71 + fix_house_creative_url.sql) and the dev seed both pass (no control bytes, line
-- <=120, label <=30, https dest). The em-dash is a normal UTF-8 char, NOT a control byte, and
-- length() counts characters (ad-policy §5). So the BEFORE UPDATE trigger never rejects a live row.

-- ===========================================================================
-- 1. Ownership assertion helpers — the ONE audited write-isolation primitive.
--
-- SECDEF STABLE so they bypass the locked table RLS and resolve the caller's org once per statement.
-- Each RAISEs 28000 unless the FK chain from the passed id terminates at the CALLER's advertiser
-- (auth.uid()→advertiser_users, resolved by app.current_advertiser_id() — which reads the request
-- JWT and is unaffected by the SECDEF context). A NULL id or an unmapped caller (current_advertiser_id
-- NULL) fails the EXISTS and RAISEs, so unauthenticated/foreign callers are refused identically.
-- Definer-internal: only the owner (running the self-serve RPCs) may call them.
-- ===========================================================================
CREATE OR REPLACE FUNCTION app.assert_owns_campaign(p_campaign_id uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  IF p_campaign_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.campaigns c
    WHERE c.id = p_campaign_id
      AND c.advertiser_id = (SELECT app.current_advertiser_id())
  ) THEN
    RAISE EXCEPTION 'not your campaign' USING errcode = '28000';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION app.assert_owns_campaign(uuid) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.assert_owns_campaign IS
  'RAISE 28000 unless p_campaign_id belongs to the caller''s advertiser (auth.uid()→current_advertiser_id()). Mandatory FIRST statement of every campaign write RPC; the write-isolation primitive after DML was revoked. Definer-internal.';

CREATE OR REPLACE FUNCTION app.assert_owns_line_item(p_line_item_id uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  IF p_line_item_id IS NULL OR NOT EXISTS (
    SELECT 1
    FROM public.line_items li
    JOIN public.campaigns  c ON c.id = li.campaign_id
    WHERE li.id = p_line_item_id
      AND c.advertiser_id = (SELECT app.current_advertiser_id())
  ) THEN
    RAISE EXCEPTION 'not your line item' USING errcode = '28000';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION app.assert_owns_line_item(uuid) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.assert_owns_line_item IS
  'RAISE 28000 unless p_line_item_id''s campaign belongs to the caller''s advertiser (line_item→campaign→advertiser terminates at current_advertiser_id()). Mandatory FIRST statement of every line_item / creative-submit write RPC. Definer-internal.';

CREATE OR REPLACE FUNCTION app.assert_owns_creative(p_creative_id uuid)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  IF p_creative_id IS NULL OR NOT EXISTS (
    SELECT 1
    FROM public.creatives cr
    JOIN public.line_items li ON li.id = cr.line_item_id
    JOIN public.campaigns  c  ON c.id  = li.campaign_id
    WHERE cr.id = p_creative_id
      AND c.advertiser_id = (SELECT app.current_advertiser_id())
  ) THEN
    RAISE EXCEPTION 'not your creative' USING errcode = '28000';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION app.assert_owns_creative(uuid) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.assert_owns_creative IS
  'RAISE 28000 unless p_creative_id''s creative→line_item→campaign chain terminates at the caller''s advertiser. Mandatory FIRST statement of every creative write RPC. Definer-internal.';

-- ===========================================================================
-- 2. Creative content validator + the load-bearing BEFORE INSERT/UPDATE TRIGGER.
--
-- The validator is the SINGLE source of content-safety truth (ad-policy §5:110-116):
--   * line + label reject ANY control byte via [[:cntrl:]] — the POSIX control class is exactly the
--     C0 range 0x00-0x1F plus DEL 0x7F, so ESC(0x1b), CR, LF, NUL and every OSC-8 hyperlink intro
--     (ESC ] 8 ; ; … BEL) are rejected. A raw ANSI/OSC-8 sequence could otherwise spoof the
--     'sponsored' label or inject a terminal hyperlink that bypasses the tokenized c.lumaline.dev
--     click redirect the system depends on.
--   * line <= 120 chars, label <= 30 chars (length() counts characters, matching ad-policy §5).
--   * dest_url, when present, must be an https:// URL (no http/data/javascript schemes).
--   * line + label must be non-empty (an empty served line is never legitimate).
-- STABLE (regex/length are pure of DB state but locale-sensitive), errcode 23514 (check_violation) so
-- the RPCs surface a clean, specific UX error before the trigger fires. Definer-internal (app schema,
-- off the Data API); the owner calls it from the SECDEF RPCs + the SECDEF trigger.
-- ===========================================================================
CREATE OR REPLACE FUNCTION app.validate_creative_content(p_line text, p_label text, p_dest_url text)
RETURNS void
LANGUAGE plpgsql STABLE SET search_path = ''
AS $$
BEGIN
  IF p_line IS NULL OR length(p_line) = 0 THEN
    RAISE EXCEPTION 'creative line must not be empty' USING errcode = '23514';
  END IF;
  IF length(p_line) > 120 THEN
    RAISE EXCEPTION 'creative line exceeds 120 characters (got %)', length(p_line) USING errcode = '23514';
  END IF;
  IF p_line ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'creative line contains control/escape bytes' USING errcode = '23514';
  END IF;

  IF p_label IS NULL OR length(p_label) = 0 THEN
    RAISE EXCEPTION 'creative label must not be empty' USING errcode = '23514';
  END IF;
  IF length(p_label) > 30 THEN
    RAISE EXCEPTION 'creative label exceeds 30 characters (got %)', length(p_label) USING errcode = '23514';
  END IF;
  IF p_label ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'creative label contains control/escape bytes' USING errcode = '23514';
  END IF;

  IF p_dest_url IS NOT NULL THEN
    IF p_dest_url !~ '^https://' THEN
      RAISE EXCEPTION 'creative dest_url must be an https:// URL' USING errcode = '23514';
    END IF;
    -- Byte-sanitize the dest_url too, not just line/label: click_resolve writes the stored dest
    -- straight into the click function's Location header (click/index.ts) and the no-token feed
    -- fallback embeds it as the OSC-8 hyperlink target, so a raw CR/LF/ESC/OSC-8 byte AFTER
    -- 'https://' would be a header-injection / terminal-injection vector. Reject control bytes AND
    -- any whitespace (a well-formed URL has none) so the trigger's "no unsafe bytes ever reach a
    -- signed/served field" guarantee is TOTAL across every served + redirect field on every path.
    IF p_dest_url ~ '[[:cntrl:][:space:]]' THEN
      RAISE EXCEPTION 'creative dest_url contains control/whitespace bytes' USING errcode = '23514';
    END IF;
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION app.validate_creative_content(text, text, text) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.validate_creative_content IS
  'Single source of creative content-safety truth (ad-policy §5): reject control/ESC/OSC-8/CR/LF bytes in line+label AND in dest_url (control + whitespace), line>120, label>30, empty line/label, non-https dest_url. Called by the RPCs (fast UX error) AND the creatives content TRIGGER (load-bearing). errcode 23514. Definer-internal.';

-- app.validate_disclosure_label — the disclosure label is a STRUCTURAL trust token, not free text.
--
-- The "clearly-labeled sponsored line" trust invariant must not rest on a human reviewer catching a
-- deceptive/homoglyph label ('tip', 'free', 'official', or a Cyrillic 'ѕponsored') at approval time.
-- The advertiser-controlled label is constrained to a small server-side ALLOW-LIST (exact ASCII, so a
-- homoglyph never matches). Enforced by the self-serve submit/edit RPCs (an advertiser literally
-- cannot submit a non-allow-list label) AND re-asserted by advertiser_approve_creative (20260716200000)
-- so a self-serve creative can never reach status='active' with a deceptive disclosure — structural,
-- not review-dependent. Scoped to the advertiser-controlled paths (NOT validate_creative_content /
-- the trigger) so the trusted admin-booking path keeps its existing label freedom.
CREATE OR REPLACE FUNCTION app.validate_disclosure_label(p_label text)
RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = ''
AS $$
BEGIN
  IF COALESCE(p_label, '') NOT IN ('sponsored', 'ad', 'promoted') THEN
    RAISE EXCEPTION 'disclosure label must be one of sponsored / ad / promoted (got %)', p_label
      USING errcode = '23514';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION app.validate_disclosure_label(text) FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.validate_disclosure_label IS
  'Constrains the advertiser-controlled disclosure label to the exact-ASCII allow-list {sponsored, ad, promoted} (homoglyphs never match). Enforced by advertiser_submit_creative/advertiser_edit_creative + re-asserted by advertiser_approve_creative so the "clearly-labeled sponsored line" invariant is structural, not reviewer-dependent. Definer-internal.';

-- The trigger fn is SECURITY DEFINER so it always runs as the owner regardless of which role issues
-- the write (service_role admin-booking, the owner-run SECDEF RPCs, a direct service_role INSERT) and
-- can therefore always call the definer-internal validator. It only reads NEW (no table access / RLS).
CREATE OR REPLACE FUNCTION app.creative_content_guard()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $$
BEGIN
  PERFORM app.validate_creative_content(NEW.line, NEW.label, NEW.dest_url);
  RETURN NEW;
END;
$$;
REVOKE EXECUTE ON FUNCTION app.creative_content_guard() FROM PUBLIC;

COMMENT ON FUNCTION app.creative_content_guard IS
  'BEFORE INSERT OR UPDATE trigger on public.creatives: delegates to app.validate_creative_content so EVERY write path (self-serve RPC, admin-booking POST/activate, direct service_role, future writers) is byte-sanitized before a creative can exist — no unsafe bytes ever reach status=active where lumaline-feed signs verbatim. SECDEF so it runs as owner on any write path.';

DROP TRIGGER IF EXISTS creatives_content_guard ON public.creatives;
CREATE TRIGGER creatives_content_guard
  BEFORE INSERT OR UPDATE ON public.creatives
  FOR EACH ROW EXECUTE FUNCTION app.creative_content_guard();

-- ===========================================================================
-- 3. CPVA-only + positive min-bid CHECK on line_items — OWNED BY 20260716180000.
--
-- The structural CHECK (public.check_selfserve_line_item + constraint line_items_selfserve_bids)
-- ships in the hard-ordered predecessor 20260716180000 (timestamp 18 < 19, so it ALWAYS runs first
-- under ordered migrations — a partial apply that ran 19 without 18 is impossible). The prior
-- re-assert here was strictly redundant and has been removed; the RPCs below still force cpc=0 +
-- cpva>=floor in-body (belt), and the 180000 CHECK is the structural backstop regardless of path.
-- ===========================================================================

-- ===========================================================================
-- 4. Self-serve write RPCs.
--
-- All: SECDEF search_path='', re-derive v_adv := current_advertiser_id() (RAISE 28000 if the session
-- maps to no org), assert ownership FIRST for any child-id argument, force the trust-critical values
-- (cpc=0 / min-bid / targeting / status), and NEVER accept an advertiser_id argument (id is always
-- derived from auth.uid()). is_house/status jumps beyond active<->paused/sub-floor bids/cpc>0 are
-- structurally unreachable. Nothing here sets a creative to 'active' — approval is reviewer-only
-- (20260716200000). `REVOKE ALL FROM PUBLIC, anon; GRANT authenticated`.
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
  'Self-serve: create a draft campaign under the caller''s own advertiser (advertiser_id from current_advertiser_id(), never a client arg). SECDEF; granted to authenticated.';

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
  'Self-serve: create a draft CPVA-only line_item under the caller''s own campaign (assert_owns_campaign FIRST). Forces cpc_bid_micros=0, cpva>=advertiser_min_bid_micros(), targeting global, status draft. SECDEF; granted to authenticated.';

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
  'Self-serve edit of a draft/paused line_item (assert_owns_line_item FIRST): forces cpc=0 + cpva>=floor; a cpva-bid change resets owning ACTIVE creatives to pending_review (no silent re-pricing below floor / cpc after approval); delivery-only edits do not reset. SECDEF; authenticated.';

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
  'Self-serve: submit a creative under the caller''s own line_item (assert_owns_line_item FIRST) at status pending_review — never active (approval is reviewer-only). Content validated (RPC UX + the load-bearing table TRIGGER). SECDEF; authenticated.';

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
  'Self-serve edit of a pending_review/rejected/paused creative (assert_owns_creative FIRST): re-validate + reset to pending_review. Cannot touch a live active creative (pause it first). SECDEF; authenticated.';

-- --- set_campaign_status (active<->paused only) ----------------------------
-- Draft→active is NOT a self-serve action (activation piggybacks on admin creative approval,
-- 20260716200000); the advertiser may only pause/resume an already-active campaign.
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
  'Self-serve pause/resume of the caller''s own campaign (assert_owns_campaign FIRST); active<->paused only (draft→active is admin-approval-driven). SECDEF; authenticated.';

-- --- set_line_item_status (active<->paused only) ---------------------------
-- Pausing a line_item stops its serving instantly (window_open requires li.status='active') — the
-- advertiser's own kill switch on their inventory. Draft→active stays admin-approval-driven.
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
  'Self-serve pause/resume of the caller''s own line_item (assert_owns_line_item FIRST); active<->paused only. Pausing stops serving instantly (window_open needs active). SECDEF; authenticated.';

-- --- update_profile (display name only) ------------------------------------
-- Column-scoped to name; is_house/status/stripe_customer_id/billing_mode are structurally unwritable
-- (the advertisers_protect_cols column-diff trigger, 20260716150000, blocks a protected-column change
-- for a non-service_role request even under this SECDEF path). The advertiser org name never appears
-- in a served creative (only line+label, both content-guarded), so it is an internal/admin-facing
-- field; reviewer scrutiny of names (impersonation) is a soft ops concern handled by the reviewer
-- tier (20260716200000), not a signing/trust gate.
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
  'Self-serve update of the caller''s own advertiser display name ONLY (column-scoped; the advertisers_protect_cols trigger blocks is_house/status/stripe_customer_id/billing_mode). SECDEF; authenticated.';

-- ===========================================================================
-- 5. Self-serve read RPCs — self-scoped aggregates (no per-publisher rows, no ledger_entries).
-- ===========================================================================

-- --- advertiser_campaigns_summary ------------------------------------------
-- Per-campaign rollup + totals for the Overview/Campaigns pages. Self-scoped; the frontend still
-- reads raw campaigns/line_items/creatives via own-row RLS for the CRUD forms.
CREATE OR REPLACE FUNCTION public.advertiser_campaigns_summary()
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv       uuid;
  v_campaigns jsonb;
  v_totals    jsonb;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  WITH camp AS (
    SELECT c.id, c.name, c.status,
           (SELECT count(*) FROM public.line_items li WHERE li.campaign_id = c.id) AS line_items,
           (SELECT count(*) FROM public.line_items li WHERE li.campaign_id = c.id AND li.status = 'active') AS active_line_items,
           (SELECT count(*) FROM public.creatives cr
              JOIN public.line_items li ON li.id = cr.line_item_id
             WHERE li.campaign_id = c.id AND cr.status = 'active') AS active_creatives,
           (SELECT count(*) FROM public.creatives cr
              JOIN public.line_items li ON li.id = cr.line_item_id
             WHERE li.campaign_id = c.id AND cr.status = 'pending_review') AS pending_creatives,
           (SELECT count(*) FROM public.creatives cr
              JOIN public.line_items li ON li.id = cr.line_item_id
             WHERE li.campaign_id = c.id AND cr.status = 'rejected') AS rejected_creatives
      FROM public.campaigns c
     WHERE c.advertiser_id = v_adv
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'campaign_id',        id,
           'name',               name,
           'status',             status,
           'line_items',         line_items,
           'active_line_items',  active_line_items,
           'active_creatives',   active_creatives,
           'pending_creatives',  pending_creatives,
           'rejected_creatives', rejected_creatives) ORDER BY name), '[]'::jsonb),
         jsonb_build_object(
           'campaigns',          count(*),
           'active_campaigns',   count(*) FILTER (WHERE status = 'active'),
           'line_items',         COALESCE(sum(line_items), 0),
           'active_line_items',  COALESCE(sum(active_line_items), 0),
           'active_creatives',   COALESCE(sum(active_creatives), 0),
           'pending_creatives',  COALESCE(sum(pending_creatives), 0),
           'rejected_creatives', COALESCE(sum(rejected_creatives), 0))
    INTO v_campaigns, v_totals
    FROM camp;

  RETURN jsonb_build_object('campaigns', v_campaigns, 'totals', v_totals);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_campaigns_summary() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_campaigns_summary() TO authenticated;

COMMENT ON FUNCTION public.advertiser_campaigns_summary IS
  'Self-scoped campaign rollup (per-campaign line_item/creative status counts + totals) for the caller''s own advertiser. SECDEF STABLE; authenticated. No cross-advertiser rows.';

-- --- advertiser_spend_summary (CPVA-only, aggregate) -----------------------
-- Per-line_item impression/attention/spend rollup over VALID billable delivery (impressions in
-- provisional+cleared — matching the window_open budget guard). CPVA-only by construction (reads
-- impressions attention billing, NEVER clicks/CPC). AGGREGATE ONLY: no publisher_id, no ledger_entries
-- leg — an advertiser never sees a publisher identity or a ledger row (data-minimization).
CREATE OR REPLACE FUNCTION public.advertiser_spend_summary()
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = ''
AS $$
DECLARE
  v_adv        uuid;
  v_line_items jsonb;
  v_totals     jsonb;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  WITH lis AS (
    SELECT li.id AS line_item_id, li.campaign_id, li.cpva_bid_micros, li.budget_total_micros,
           COALESCE(agg.impressions, 0)       AS impressions,
           COALESCE(agg.attention_seconds, 0) AS attention_seconds,
           COALESCE(agg.spend_micros, 0)      AS spend_micros
      FROM public.line_items li
      JOIN public.campaigns  c ON c.id = li.campaign_id
      LEFT JOIN LATERAL (
        SELECT count(*)                       AS impressions,
               COALESCE(sum(i.attention_seconds), 0) AS attention_seconds,
               COALESCE(sum(i.gross_micros), 0)      AS spend_micros
          FROM public.impressions i
         WHERE i.line_item_id = li.id
           AND i.state IN ('provisional', 'cleared')   -- valid billable (clawed_back/void excluded)
      ) agg ON true
     WHERE c.advertiser_id = v_adv
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'line_item_id',            line_item_id,
           'campaign_id',             campaign_id,
           'cpva_bid_micros',         cpva_bid_micros,
           'impressions',             impressions,
           'attention_seconds',       attention_seconds,
           'spend_micros',            spend_micros,
           'budget_total_micros',     budget_total_micros,
           'remaining_budget_micros',
             CASE WHEN budget_total_micros IS NULL THEN NULL
                  ELSE greatest(budget_total_micros - spend_micros, 0) END) ORDER BY line_item_id), '[]'::jsonb),
         jsonb_build_object(
           'impressions',       COALESCE(sum(impressions), 0),
           'attention_seconds', COALESCE(sum(attention_seconds), 0),
           'spend_micros',      COALESCE(sum(spend_micros), 0))
    INTO v_line_items, v_totals
    FROM lis;

  RETURN jsonb_build_object('line_items', v_line_items, 'totals', v_totals);
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_spend_summary() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_spend_summary() TO authenticated;

COMMENT ON FUNCTION public.advertiser_spend_summary IS
  'Self-scoped CPVA-only spend rollup: per-line_item impressions/attention-seconds/spend (valid billable, provisional+cleared) + remaining budget + totals, for the caller''s own advertiser. Aggregate — NO per-publisher rows, NO ledger_entries. SECDEF STABLE; authenticated.';

-- ===========================================================================
-- 6. Migration-tail assertion — anon must hold NO EXECUTE on any function added here.
--
-- The secdef_grant_hardening.sql footgun: Supabase auto-grants EXECUTE to PUBLIC (anon inherits) on
-- every new function; revoking only anon leaves it callable. Every fn above ships
-- `REVOKE ALL ... FROM PUBLIC, anon[, authenticated]`; this DO-block fails the migration loudly if any
-- slipped (has_function_privilege reads the function-level ACL — false for the app.* helpers even
-- independent of schema USAGE).
-- ===========================================================================
DO $$
DECLARE
  v_fn  text;
  v_fns text[] := ARRAY[
    'app.assert_owns_campaign(uuid)',
    'app.assert_owns_line_item(uuid)',
    'app.assert_owns_creative(uuid)',
    'app.validate_creative_content(text, text, text)',
    'app.validate_disclosure_label(text)',
    'app.creative_content_guard()',
    'public.advertiser_create_campaign(text)',
    'public.advertiser_create_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz)',
    'public.advertiser_edit_line_item(uuid, bigint, integer, bigint, bigint, text, integer, timestamptz, timestamptz)',
    'public.advertiser_submit_creative(uuid, text, text, text)',
    'public.advertiser_edit_creative(uuid, text, text, text)',
    'public.advertiser_set_campaign_status(uuid, text)',
    'public.advertiser_set_line_item_status(uuid, text)',
    'public.advertiser_update_profile(text)',
    'public.advertiser_campaigns_summary()',
    'public.advertiser_spend_summary()'
  ];
BEGIN
  FOREACH v_fn IN ARRAY v_fns LOOP
    IF has_function_privilege('anon', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    END IF;
  END LOOP;
END;
$$;
