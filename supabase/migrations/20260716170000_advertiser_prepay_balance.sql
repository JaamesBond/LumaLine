-- lumaline M9-T2 — advertiser prepay balance store + the atomic never-negative money primitives.
--
-- The self-serve advertiser is PREPAY (advertisers.billing_mode='prepay', 20260716150000):
-- a card deposit becomes spend-only ad credit, delivered spend DRAWS DOWN that credit atomically
-- at billing-settle, and the whole position is reconstructable from — and reconciles against —
-- the existing zero-sum double-entry book (ledger_and_payouts.sql, enums extended 20260716160000).
-- This migration is the money core. It ships:
--
--   1. public.advertiser_balances        — the spendable-credit cache (balance/reserved), TWO
--                                           CHECK(>=0) so never-negative is STRUCTURAL, not code.
--   2. public.advertiser_balance_ledger   — an APPEND-ONLY, trigger-immutable sub-ledger of every
--                                           balance movement (deposit/drawdown/chargeback/…) with
--                                           the three dedup UNIQUEs (pi_id / charge_batch_id /
--                                           dispute_id) that make credit + draw-down + reversal
--                                           idempotent. Cloned from admin_action_log's immutability.
--   3. public.advertiser_topup_intents    — the SERVER-STORED authority for WHICH advertiser a
--                                           deposit credits (never trust Stripe client metadata).
--   4. advertiser_charges.settled_via      — 'stripe' (legacy postpay PI) | 'balance' (prepay draw).
--   5. ad_windows.reserve_micros           — the per-window serve-time hold, so the balance cache's
--                                           reserved_micros is EXACTLY reconstructable as
--                                           SUM(ad_windows.reserve_micros) (a BACKED reserve, not an
--                                           unbacked cache — the reserved-invariant HIGH fix).
--   6. app.advertiser_min_bid_micros()     — the single-source min-bid floor (like payout_hold_interval).
--   7. The primitives (app schema, SECDEF, search_path='', service_role-only):
--        advertiser_credit_deposit       — idempotent-on-pi_id deposit credit (deposit HIGH: only
--                                          a verified payment_intent.succeeded ever reaches here,
--                                          crediting the server-stored intent's advertiser).
--        advertiser_reserve / _release   — the guarded FOR-UPDATE serve-time hold (never over-commit).
--        advertiser_draw_down_batch      — the atomic never-negative draw-down at billing-settle,
--                                          idempotent on charge_batch_id, with LOUD reserved_underflow
--                                          (before any clamp) + insufficient_balance (solvency) alarms.
--        advertiser_apply_deposit_reversal — the chargeback-after-spend BAD-DEBT write-off: zero-sum,
--                                          clamp balance at 0 (never a CHECK(>=0) 5xx-loop), pause the
--                                          advertiser's line_items, idempotent on dispute_id.
--        advertiser_reconcile_reserved   — recompute reserved := SUM(reserve_micros) UNDER the balance
--                                          FOR UPDATE (cannot clobber a concurrently-taken reserve).
--   8. public.advertiser_balance_summary() — the self-serve balance read for the portal.
--
-- NON-REFUNDABLE PREPAID CREDIT (owner decision): deposits are spend-only ad credit. There is NO
-- withdrawal RPC / AML / KYC here — the only exit is delivered spend (draw-down) or a card DISPUTE,
-- which is handled as zero-sum bad-debt (never clawed from already-paid publishers). Any admin
-- clawback/withdrawal surface lives in the aal2-gated 20260716200000, not here.
--
-- MONEY-SAFETY INVARIANTS (structural, not convention):
--   * NEVER-NEGATIVE — two CHECK(>=0) + a guarded UPDATE that books nothing unless balance>=sum +
--     the chargeback clamp max(0,bal-R). balance_micros can never go below 0 on any path.
--   * IDEMPOTENT — UNIQUE(stripe_payment_intent_id) dedups deposit credit; UNIQUE(charge_batch_id)
--     dedups draw-down; UNIQUE(dispute_id) dedups reversal. Retries/replays are no-ops.
--   * ATOMIC — every mutator locks the advertiser_balances row (guarded UPDATE re-checks under the
--     row lock via EvalPlanQual / explicit SELECT..FOR UPDATE), so a burst of concurrent
--     window_opens for one advertiser can never over-reserve past the balance.
--   * ZERO-SUM — every booked group (deposit / draw-down / chargeback) sums to 0 and rides the
--     deferred ledger_group_balances trigger (ledger_and_payouts.sql:36-65) UNCHANGED.
--   * clear_events + app.accrue are UNTOUCHED (loud-fail contract clearing_and_ledger.sql:142-144);
--     draw-down NETS the receivable app.accrue booked, it never re-books the clearing path.
--
-- CONVENTIONS (secdef_grant_hardening.sql lesson): every app primitive ships
-- `REVOKE ALL ... FROM PUBLIC, anon, authenticated` then `GRANT ... TO service_role`; the one PUBLIC
-- fn (advertiser_balance_summary) ships `REVOKE ALL ... FROM PUBLIC, anon` then GRANT authenticated;
-- the migration tail RAISEs if anon retains EXECUTE on anything added here. All SECDEF, search_path=''.
--
-- DEPENDS ON: 20260716150000 (advertisers.billing_mode, advertiser_users, current_advertiser_id,
-- the advertiser_balances seed in ensure_advertiser_user) + 20260716160000 (the ledger_account enum
-- values advertiser_funds / advertiser_bad_debt + ledger_entries.advertiser_id — committed in their
-- OWN prior migration so the literals are usable here, Postgres forbidding same-txn use).

-- ---------------------------------------------------------------------------
-- 1. public.advertiser_balances — the spendable-credit cache.
--
-- One row per advertiser (PK advertiser_id, so ensure_advertiser_user's ON CONFLICT (advertiser_id)
-- seed works). balance_micros = credited-and-not-yet-spent; reserved_micros = held by open/undrawn
-- serve windows. AVAILABLE = balance - reserved is what a new window may reserve. Both CHECK(>=0):
-- never-negative is a table invariant. Writes ONLY via the service_role SECDEF primitives below —
-- no authenticated DML (a crafted PostgREST write matches no grant); own-row SELECT for the portal.
-- ---------------------------------------------------------------------------
CREATE TABLE public.advertiser_balances (
  advertiser_id   uuid PRIMARY KEY REFERENCES public.advertisers (id) ON DELETE CASCADE,
  balance_micros  bigint NOT NULL DEFAULT 0 CHECK (balance_micros  >= 0),
  reserved_micros bigint NOT NULL DEFAULT 0 CHECK (reserved_micros >= 0),
  updated_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.advertiser_balances IS
  'Prepay spendable-credit cache: balance_micros (credited-undrawn) + reserved_micros (held by serve windows). AVAILABLE = balance - reserved. Two CHECK(>=0) = never-negative is structural. Written ONLY by the service_role SECDEF primitives (credit/reserve/release/draw_down/reversal/reconcile); own-row SELECT for the portal. reserved_micros == SUM(ad_windows.reserve_micros) is the BACKED-reserve money invariant (advertiser_ledger_health, 20260716210000).';

ALTER TABLE public.advertiser_balances ENABLE ROW LEVEL SECURITY;

CREATE POLICY advertiser_balances_select_own ON public.advertiser_balances
  FOR SELECT TO authenticated
  USING (advertiser_id = (SELECT app.current_advertiser_id()) OR (SELECT app.is_admin()));
CREATE POLICY advertiser_balances_service ON public.advertiser_balances
  FOR ALL TO service_role USING (true) WITH CHECK (true);

REVOKE ALL ON public.advertiser_balances FROM PUBLIC, anon;   -- belt vs Supabase default anon grant (RLS already denies anon)
GRANT SELECT ON public.advertiser_balances TO authenticated;   -- RLS-scoped to own row; NO write grant
GRANT SELECT, INSERT, UPDATE, DELETE ON public.advertiser_balances TO service_role;

-- ---------------------------------------------------------------------------
-- 2. public.advertiser_balance_ledger — append-only immutable sub-ledger of balance movements.
--
-- One row per balance movement (mirrors admin_action_log's tamper-evidence). The THREE dedup
-- UNIQUEs are the idempotency backbone — NULLs are distinct, so a deposit (pi_id set, batch/dispute
-- NULL), a draw-down (batch set, pi/dispute NULL) and a chargeback (dispute set, pi/batch NULL)
-- coexist while each kind is deduped on its own key:
--   * UNIQUE(stripe_payment_intent_id) — a replayed deposit webhook credits ONCE.
--   * UNIQUE(charge_batch_id)          — a retried/recovered draw-down draws ONCE.
--   * UNIQUE(dispute_id)               — a re-delivered dispute event reverses ONCE.
-- entry_group_id links the row to the zero-sum ledger group it booked (NULL for reserve_reconcile,
-- which is a cache correction that books no money). Append-only: a BEFORE UPDATE/DELETE + BEFORE
-- TRUNCATE trigger (below) blocks mutation even for the owner — this is a financial record.
-- ---------------------------------------------------------------------------
CREATE TABLE public.advertiser_balance_ledger (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  advertiser_id            uuid NOT NULL REFERENCES public.advertisers (id),
  kind                     text NOT NULL
    -- The chargeback path books its platform-loss leg in the ledger_entries advertiser_bad_debt
    -- ACCOUNT, not as a sub-ledger row, so kind='bad_debt' is intentionally absent (every kind here
    -- is actually written by a code path: deposit/drawdown/refund/reserve_reconcile/chargeback).
    CHECK (kind IN ('deposit', 'drawdown', 'refund', 'reserve_reconcile', 'chargeback')),
  amount_micros            bigint NOT NULL,
  stripe_payment_intent_id text UNIQUE,   -- deposit dedup (NULL for non-deposits; NULLs are distinct)
  stripe_event_id          text,          -- the Stripe event that drove this row (audit)
  checkout_session_id      text,          -- the topup_intent this deposit fulfilled (audit)
  charge_batch_id          uuid UNIQUE,    -- draw-down dedup (NULL for non-drawdowns)
  dispute_id               text UNIQUE,    -- chargeback dedup (NULL for non-chargebacks)
  entry_group_id           uuid,          -- the zero-sum ledger group booked (NULL for reserve_reconcile)
  created_at               timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.advertiser_balance_ledger IS
  'Append-only, trigger-immutable sub-ledger of every advertiser_balances movement. UNIQUE(pi_id)/UNIQUE(charge_batch_id)/UNIQUE(dispute_id) make deposit-credit / draw-down / chargeback-reversal idempotent (NULLs distinct, so the kinds coexist). entry_group_id links to the zero-sum ledger group (NULL for reserve_reconcile). A financial record — preserved across GDPR erasure (free-text redacted).';

CREATE INDEX advertiser_balance_ledger_adv_idx  ON public.advertiser_balance_ledger (advertiser_id, created_at DESC);
CREATE INDEX advertiser_balance_ledger_kind_idx ON public.advertiser_balance_ledger (advertiser_id, kind);

ALTER TABLE public.advertiser_balance_ledger ENABLE ROW LEVEL SECURITY;

CREATE POLICY advertiser_balance_ledger_select_own ON public.advertiser_balance_ledger
  FOR SELECT TO authenticated
  USING (advertiser_id = (SELECT app.current_advertiser_id()) OR (SELECT app.is_admin()));
CREATE POLICY advertiser_balance_ledger_service ON public.advertiser_balance_ledger
  FOR ALL TO service_role USING (true) WITH CHECK (true);

REVOKE ALL ON public.advertiser_balance_ledger FROM PUBLIC, anon;   -- belt vs Supabase default anon grant (RLS already denies anon)
GRANT SELECT ON public.advertiser_balance_ledger TO authenticated;   -- RLS own-row; NO write grant
GRANT SELECT, INSERT ON public.advertiser_balance_ledger TO service_role;   -- INSERT only (append-only)

-- Immutability guard (cloned from app.admin_action_log_immutable, admin_dashboard_foundation.sql
-- :178-201): block UPDATE/DELETE at the row level AND TRUNCATE at the statement level, even for the
-- owner / a SECDEF caller. The same RAISE-only fn serves both (never touches NEW/OLD).
CREATE OR REPLACE FUNCTION app.advertiser_balance_ledger_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
  RAISE EXCEPTION 'advertiser_balance_ledger is append-only';
END;
$$;
REVOKE EXECUTE ON FUNCTION app.advertiser_balance_ledger_immutable() FROM PUBLIC;

DROP TRIGGER IF EXISTS advertiser_balance_ledger_no_mutate ON public.advertiser_balance_ledger;
CREATE TRIGGER advertiser_balance_ledger_no_mutate
  BEFORE UPDATE OR DELETE ON public.advertiser_balance_ledger
  FOR EACH ROW EXECUTE FUNCTION app.advertiser_balance_ledger_immutable();

DROP TRIGGER IF EXISTS advertiser_balance_ledger_no_truncate ON public.advertiser_balance_ledger;
CREATE TRIGGER advertiser_balance_ledger_no_truncate
  BEFORE TRUNCATE ON public.advertiser_balance_ledger
  FOR EACH STATEMENT EXECUTE FUNCTION app.advertiser_balance_ledger_immutable();

-- ---------------------------------------------------------------------------
-- 3. public.advertiser_topup_intents — the server-stored deposit authority.
--
-- funding/checkout (the advertiser-portal edge fn) resolves the depositing advertiser from the
-- caller's JWT (advertiser_self_id) and INSERTs a row here BEFORE opening the Stripe Checkout
-- session. The deposit webhook then credits THIS row's advertiser — never Stripe client metadata,
-- which a crafted checkout body could poison (the deposit-credit MEDIUM). PK = checkout_session_id
-- so the session→advertiser binding is 1:1 and lookup-by-session is trivial.
-- ---------------------------------------------------------------------------
CREATE TABLE public.advertiser_topup_intents (
  checkout_session_id text PRIMARY KEY,
  advertiser_id       uuid NOT NULL REFERENCES public.advertisers (id) ON DELETE CASCADE,
  amount_micros       bigint NOT NULL CHECK (amount_micros > 0),
  status              text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'credited', 'expired')),
  created_at          timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.advertiser_topup_intents IS
  'Server-stored authority for WHICH advertiser a deposit credits. funding/checkout stamps the JWT-derived advertiser (advertiser_self_id) here before the Stripe session; the webhook credits THIS row''s advertiser, never client metadata (deposit-credit isolation). status flips pending→credited when advertiser_credit_deposit succeeds.';

CREATE INDEX advertiser_topup_intents_adv_idx ON public.advertiser_topup_intents (advertiser_id, created_at DESC);

ALTER TABLE public.advertiser_topup_intents ENABLE ROW LEVEL SECURITY;

CREATE POLICY advertiser_topup_intents_select_own ON public.advertiser_topup_intents
  FOR SELECT TO authenticated
  USING (advertiser_id = (SELECT app.current_advertiser_id()) OR (SELECT app.is_admin()));
CREATE POLICY advertiser_topup_intents_service ON public.advertiser_topup_intents
  FOR ALL TO service_role USING (true) WITH CHECK (true);

REVOKE ALL ON public.advertiser_topup_intents FROM PUBLIC, anon;   -- belt vs Supabase default anon grant (RLS already denies anon)
GRANT SELECT ON public.advertiser_topup_intents TO authenticated;   -- RLS own-row; NO write grant
GRANT SELECT, INSERT, UPDATE ON public.advertiser_topup_intents TO service_role;

-- ---------------------------------------------------------------------------
-- 4. advertiser_charges.settled_via — how a charge row was collected.
--
-- 'stripe' (default, every legacy postpay row) = collected via a Stripe PaymentIntent. 'balance' =
-- collected by drawing down prepay credit (no PI, stripe_charge_id NULL). /refund branches on this
-- (20260716200000): a card charge refunds via Stripe; a balance charge re-credits the ledger — never
-- both. Default keeps every existing row unambiguously 'stripe'.
-- ---------------------------------------------------------------------------
ALTER TABLE public.advertiser_charges
  ADD COLUMN IF NOT EXISTS settled_via text NOT NULL DEFAULT 'stripe'
    CHECK (settled_via IN ('stripe', 'balance'));

COMMENT ON COLUMN public.advertiser_charges.settled_via IS
  '''stripe'' (legacy postpay PaymentIntent) | ''balance'' (prepay draw-down; stripe_charge_id NULL). /refund branches on it card-vs-balance so a prepay charge is never double-refunded.';

-- ---------------------------------------------------------------------------
-- 4b. uncharged_advertiser_billings gains billing_mode — so billing /charge can ROUTE.
--
-- billing /charge selects this view and, per advertiser, either creates a Stripe PaymentIntent
-- (postpay) or draws down prepay credit (prepay, via app.advertiser_draw_down_batch). It needs to
-- know the advertiser's billing_mode to route. CREATE OR REPLACE VIEW appends billing_mode as the
-- LAST column of BOTH UNION branches (Postgres allows adding trailing columns), leaving every
-- existing column/row byte-identical. Definition otherwise verbatim from cpc_billing.sql.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW public.uncharged_advertiser_billings AS
SELECT
  le.entry_group_id, le.event_type, le.amount_micros,
  le.source_id AS impression_id, i.line_item_id, i.publisher_id,
  li.campaign_id, c.advertiser_id, a.name AS advertiser_name,
  a.is_house, a.stripe_customer_id, le.created_at AS cleared_at,
  a.billing_mode
FROM public.ledger_entries le
JOIN public.impressions i  ON i.id  = le.source_id
JOIN public.line_items  li ON li.id = i.line_item_id
JOIN public.campaigns   c  ON c.id  = li.campaign_id
JOIN public.advertisers a  ON a.id  = c.advertiser_id
LEFT JOIN public.advertiser_charges ac ON ac.entry_group_id = le.entry_group_id
WHERE le.account    = 'advertiser_billing'
  AND le.state      = 'cleared'
  AND le.event_type = 'cpva_accrual'
  AND le.source_type = 'impression'
  AND ac.entry_group_id IS NULL
UNION ALL
SELECT
  le.entry_group_id, le.event_type, le.amount_micros,
  NULL::uuid AS impression_id, cl.line_item_id, cl.publisher_id,
  li.campaign_id, c.advertiser_id, a.name AS advertiser_name,
  a.is_house, a.stripe_customer_id, le.created_at AS cleared_at,
  a.billing_mode
FROM public.ledger_entries le
JOIN public.clicks      cl ON cl.id = le.source_id
JOIN public.line_items  li ON li.id = cl.line_item_id
JOIN public.campaigns   c  ON c.id  = li.campaign_id
JOIN public.advertisers a  ON a.id  = c.advertiser_id
LEFT JOIN public.advertiser_charges ac ON ac.entry_group_id = le.entry_group_id
WHERE le.account    = 'advertiser_billing'
  AND le.state      = 'cleared'
  AND le.event_type = 'cpc_accrual'
  AND le.source_type = 'click'
  AND ac.entry_group_id IS NULL;

-- ---------------------------------------------------------------------------
-- 5. ad_windows.reserve_micros — the per-window serve-time hold (the BACKED reserve).
--
-- window_open (20260716180000) stamps the reserved estimate here when it serves a prepay creative;
-- close_window trues it down to actual gross; draw-down + sweep zero it. This makes the balance
-- cache's reserved_micros EXACTLY reconstructable as SUM(ad_windows.reserve_micros) over the
-- advertiser's open/credited-undrawn windows — a monitored money invariant, not an unbacked cache.
-- ad_windows is UNLOGGED; a NOT NULL DEFAULT 0 add is cheap and every existing/house window reads 0.
-- ---------------------------------------------------------------------------
ALTER TABLE public.ad_windows
  ADD COLUMN IF NOT EXISTS reserve_micros bigint NOT NULL DEFAULT 0;

COMMENT ON COLUMN public.ad_windows.reserve_micros IS
  'Serve-time prepay hold for this window (0 for house/no-fill/postpay). Stamped by window_open, trued to gross by close_window, zeroed by draw-down/sweep. advertiser_balances.reserved_micros == SUM(reserve_micros) over the advertiser''s open+credited-undrawn windows is the BACKED-reserve invariant.';

-- ---------------------------------------------------------------------------
-- 6. app.advertiser_min_bid_micros() — the single-source min-bid floor.
--
-- IMMUTABLE constant (like app.payout_hold_interval, admin_dashboard_foundation.sql:129-142) so the
-- CPVA-only+min-bid CHECK on line_items (20260716180000) and the create/edit RPCs (20260716190000)
-- fold the SAME literal — CPVA-only + a positive floor can never diverge between the table constraint
-- and the RPCs. A NON-house prepay line_item must bid >= this (structural free-distribution defense).
-- OWNER-TUNABLE at deploy (T14): the current value is a conservative positive placeholder in
-- EUR-micros (1000 micros = 0.001 EUR = 0.1 cent). Change it here (single source) before go-live.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_min_bid_micros()
RETURNS bigint
LANGUAGE sql
IMMUTABLE
SET search_path = ''
AS $$
  SELECT 1000::bigint;   -- 0.001 EUR = 0.1 cent. OWNER-TUNABLE before go-live (T14).
$$;
REVOKE EXECUTE ON FUNCTION app.advertiser_min_bid_micros() FROM public;
GRANT  EXECUTE ON FUNCTION app.advertiser_min_bid_micros() TO authenticated, service_role;

COMMENT ON FUNCTION app.advertiser_min_bid_micros IS
  'Single source of truth for the self-serve CPVA min-bid floor (EUR-micros). Folded by the line_items CPVA-only+min-bid CHECK (20260716180000) and the create/edit RPCs (20260716190000) so they can never diverge. IMMUTABLE constant; owner-tunable at deploy (T14).';

-- ---------------------------------------------------------------------------
-- 6b. app.advertiser_expected_reserved / _expected_balance — the SINGLE source of the
--     reserved + balance money-invariant math, so the reconcile primitive (below) and the
--     admin health read + monitor sync (20260716210000) can never drift.
--
-- expected_reserved(adv) = SUM(ad_windows.reserve_micros) over the advertiser's windows, EXCLUDING
--   any window whose impression is clawed_back/void. A credited-but-undrawn window's reserve is
--   trued to gross by close_window and legitimately held; but a subsequent clawback (admin or the
--   self-deal scan) flips its impression to 'clawed_back' WITHOUT entering a charge batch, so
--   draw-down never zeroes that window's reserve. Excluding clawed_back/void windows makes the
--   invariant SELF-HEALING (reconcile recomputes the corrected lower value; the health monitor
--   detects a real drift instead of "confirming" the stale, inflated hold). The clawback call sites
--   (20260716200000) additionally release+zero the reserve immediately, so the two agree on the hot
--   path — this filter is the drift safety net the reviewer's must-fix requires.
-- expected_balance(adv) = −SUM(cleared advertiser_funds legs) (the held-liability that backs the
--   spendable cache exactly). Both are STABLE SECDEF, definer-internal (called by SECDEF fns only).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_expected_reserved(p_advertiser uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(SUM(w.reserve_micros), 0)::bigint
    FROM public.ad_windows w
    JOIN public.line_items li ON li.id = w.line_item_id
    JOIN public.campaigns  c  ON c.id  = li.campaign_id
   WHERE c.advertiser_id = p_advertiser
     AND NOT EXISTS (
       SELECT 1 FROM public.impressions i
        WHERE i.window_id = w.window_id
          AND i.state IN ('clawed_back', 'void'));   -- stale-hold exclusion (self-healing)
$$;
REVOKE ALL ON FUNCTION app.advertiser_expected_reserved(uuid) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_expected_reserved(uuid) TO service_role;

COMMENT ON FUNCTION app.advertiser_expected_reserved IS
  'The BACKED-reserve invariant target: SUM(ad_windows.reserve_micros) over the advertiser''s windows EXCLUDING clawed_back/void impressions (whose reserve draw-down never zeroes). Single source for advertiser_reconcile_reserved + advertiser_ledger_health/health_sync so they can never drift; makes the reserved invariant self-healing after a clawback-before-drawdown. Definer-internal.';

CREATE OR REPLACE FUNCTION app.advertiser_expected_balance(p_advertiser uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT COALESCE(-SUM(le.amount_micros), 0)::bigint
    FROM public.ledger_entries le
   WHERE le.advertiser_id = p_advertiser
     AND le.account = 'advertiser_funds'
     AND le.state   = 'cleared';
$$;
REVOKE ALL ON FUNCTION app.advertiser_expected_balance(uuid) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_expected_balance(uuid) TO service_role;

COMMENT ON FUNCTION app.advertiser_expected_balance IS
  'The BALANCE invariant target: −SUM(cleared advertiser_funds legs) for the advertiser (the held-deposit liability that backs the spendable balance cache exactly). Single source for advertiser_ledger_health/health_sync. Definer-internal.';

-- ---------------------------------------------------------------------------
-- 7a. app.advertiser_alert() — fire-and-forget LOUD money alarm.
--
-- The draw-down solvency alarms (reserved_underflow / insufficient_balance) must be visible to the
-- money monitor WITHOUT the ability to wedge the billing txn. This inserts a single OPEN alert into
-- app.alert_events (the monitor's store, money_monitoring.sql:36-53) using the partial-unique
-- open-dedup so a per-advertiser breach fires ONE sticky alert; a later advertiser_ledger_health()
-- run (20260716210000) resolves it via monitor_sync_alerts when the condition clears. Wrapped in an
-- exception guard so a monitoring hiccup can NEVER abort a real draw-down (mirrors run_monitor's
-- degrade-never-fail ethos, money_monitoring.sql:220-263).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_alert(
  p_check text, p_severity text, p_dedup text, p_payload jsonb)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  INSERT INTO app.alert_events (check_name, severity, dedup_key, payload)
  VALUES (p_check, p_severity, p_dedup, p_payload)
  ON CONFLICT (check_name, dedup_key) WHERE status = 'open' DO NOTHING;
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'advertiser_alert: could not record % (%): %', p_check, p_dedup, SQLERRM;
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_alert(text, text, text, jsonb) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_alert(text, text, text, jsonb) TO service_role;

COMMENT ON FUNCTION app.advertiser_alert IS
  'Fire-and-forget LOUD money alarm: inserts one OPEN app.alert_events row (partial-unique open-dedup) for a prepay breach; a later advertiser_ledger_health run resolves it via monitor_sync_alerts. Exception-guarded so a monitoring failure never aborts the draw-down txn.';

-- ---------------------------------------------------------------------------
-- 7b. app.advertiser_credit_deposit — idempotent deposit credit.
--
-- Called ONLY by the advertiser-portal webhook, ONLY on a signature-verified, deduped
-- payment_intent.succeeded (never a 'processing' PI, never checkout.session alone). Credits the
-- advertiser the caller resolved from the server-stored topup_intent (p_adv), never client metadata.
-- IDEMPOTENT: the balance_ledger row is inserted FIRST with ON CONFLICT (pi_id) DO NOTHING — a
-- replayed webhook (same pi_id) inserts no row and returns credited=false WITHOUT touching balance,
-- so two concurrent deliveries credit exactly once (the UNIQUE is the race arbiter). Books the
-- zero-sum deposit group Dr platform_cash +D / Cr advertiser_funds -D and flips the topup_intent.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_credit_deposit(
  p_advertiser  uuid,
  p_session_id  text,
  p_pi_id       text,
  p_event_id    text,
  p_amount      bigint)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_group uuid := gen_random_uuid();
  v_hit   uuid;
BEGIN
  IF p_advertiser IS NULL OR p_pi_id IS NULL OR p_pi_id = '' THEN
    RAISE EXCEPTION 'advertiser_credit_deposit: advertiser + pi_id are required' USING errcode = '22004';
  END IF;
  IF p_amount IS NULL OR p_amount <= 0 THEN
    RAISE EXCEPTION 'advertiser_credit_deposit: amount must be positive (got %)', p_amount USING errcode = '22003';
  END IF;

  -- Idempotency arbiter: insert the sub-ledger row first. A replay (same pi_id) conflicts -> no row.
  INSERT INTO public.advertiser_balance_ledger
    (advertiser_id, kind, amount_micros, stripe_payment_intent_id, stripe_event_id, checkout_session_id, entry_group_id)
  VALUES
    (p_advertiser, 'deposit', p_amount, p_pi_id, p_event_id, p_session_id, v_group)
  ON CONFLICT (stripe_payment_intent_id) DO NOTHING
  RETURNING id INTO v_hit;

  IF v_hit IS NULL THEN
    RETURN jsonb_build_object('credited', false, 'reason', 'duplicate', 'pi_id', p_pi_id);
  END IF;

  -- Credit the spendable balance (create the row if the advertiser has none yet).
  INSERT INTO public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
  VALUES (p_advertiser, p_amount, 0)
  ON CONFLICT (advertiser_id)
    DO UPDATE SET balance_micros = public.advertiser_balances.balance_micros + EXCLUDED.balance_micros,
                  updated_at = now();

  -- Flip the server-stored intent (best-effort; the balance_ledger row is the source of truth).
  UPDATE public.advertiser_topup_intents
     SET status = 'credited'
   WHERE checkout_session_id = p_session_id AND status <> 'credited';

  -- Zero-sum deposit group: cash in, held liability up (advertiser_funds negative, like publisher_earnings).
  INSERT INTO public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
  VALUES
    (v_group, 'advertiser_deposit', 'platform_cash',     p_amount, 'cleared', 'advertiser_deposit', p_advertiser, p_advertiser),
    (v_group, 'advertiser_deposit', 'advertiser_funds', -p_amount, 'cleared', 'advertiser_deposit', p_advertiser, p_advertiser);

  RETURN jsonb_build_object('credited', true, 'advertiser_id', p_advertiser,
                            'amount_micros', p_amount, 'entry_group_id', v_group);
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_credit_deposit(uuid, text, text, text, bigint) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_credit_deposit(uuid, text, text, text, bigint) TO service_role;

COMMENT ON FUNCTION app.advertiser_credit_deposit IS
  'Idempotent deposit credit (UNIQUE(pi_id) arbiter): credits p_advertiser (the server-stored topup_intent, never client metadata), books zero-sum Dr platform_cash / Cr advertiser_funds, flips the intent. Called only by the webhook on a verified payment_intent.succeeded. service_role only.';

-- ---------------------------------------------------------------------------
-- 7c. app.advertiser_reserve — the guarded serve-time hold.
--
-- window_open calls this after choosing a prepay creative. The guarded UPDATE re-checks
-- AVAILABLE = balance - reserved >= estimate UNDER the advertiser_balances row lock (a concurrent
-- reserve blocks and re-evaluates against the committed value via EvalPlanQual), so a burst of
-- concurrent window_opens can NEVER over-reserve past the balance. Returns covered bool; on false
-- window_open NULLs the creative -> a true no-fill that never bills (the reserve-fall-through fix).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_reserve(p_advertiser uuid, p_estimate bigint)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_estimate IS NULL OR p_estimate <= 0 THEN
    RETURN true;   -- nothing to hold (house / no-fill estimate = 0)
  END IF;

  UPDATE public.advertiser_balances
     SET reserved_micros = reserved_micros + p_estimate,
         updated_at = now()
   WHERE advertiser_id = p_advertiser
     AND balance_micros - reserved_micros >= p_estimate;   -- AVAILABLE guard, re-checked under lock

  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n > 0;
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_reserve(uuid, bigint) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_reserve(uuid, bigint) TO service_role;

COMMENT ON FUNCTION app.advertiser_reserve IS
  'Guarded serve-time hold: reserved += estimate only when AVAILABLE (balance-reserved) covers it, re-checked under the advertiser_balances row lock. Returns covered bool; window_open NULLs the creative on false (no-fill, never bills). service_role only.';

-- ---------------------------------------------------------------------------
-- 7d. app.advertiser_release — release a hold (close_window true-up / sweep / abandon).
--
-- greatest(reserved - delta, 0): a release can never drive reserved negative. Called by close_window
-- (release estimate-gross on credit, or the whole hold on abandon/void/house) and sweep_stale_windows.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_release(p_advertiser uuid, p_delta bigint)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
  IF p_delta IS NULL OR p_delta <= 0 THEN
    RETURN;
  END IF;
  UPDATE public.advertiser_balances
     SET reserved_micros = greatest(reserved_micros - p_delta, 0),
         updated_at = now()
   WHERE advertiser_id = p_advertiser;
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_release(uuid, bigint) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_release(uuid, bigint) TO service_role;

COMMENT ON FUNCTION app.advertiser_release IS
  'Release a serve-time hold: reserved := greatest(reserved - delta, 0) (never negative). Called by close_window (estimate-gross true-up / full release on abandon/void/house) and sweep_stale_windows. service_role only.';

-- ---------------------------------------------------------------------------
-- 7e. app.advertiser_draw_down_batch — the atomic never-negative draw-down at billing-settle.
--
-- Called by billing /charge for a prepay advertiser under the single-flight billing_lock, in place
-- of paymentIntents.create. p_sum = SUM(amount_micros) of the batch's reserved advertiser_charges.
-- Under the advertiser_balances row FOR UPDATE:
--   * IDEMPOTENT on charge_batch_id: a prior drawdown row for this batch -> no-op (retries/recovery
--     never double-spend); UNIQUE(charge_batch_id) is the hard backstop.
--   * LOUD reserved_underflow: if reserved < sum the reserve accounting drifted low (inventory
--     served the hold didn't cover) -> fire a 'high' alarm BEFORE the greatest(,0) clamp so the
--     desync is surfaced, not swallowed.
--   * NEVER-NEGATIVE: draws ONLY when balance >= sum; else fires a 'critical' insufficient_balance
--     SOLVENCY alarm and draws NOTHING (billing then pauses the advertiser + leaves the accrual
--     undrawn until top-up). balance can never go < 0.
--   * On draw: balance -= sum, reserved := greatest(reserved - sum, 0), zero the drawn windows'
--     reserve_micros (so reconcile's SUM excludes them), and book the zero-sum netting group
--     Dr advertiser_funds +sum / Cr advertiser_billing -sum (releases the held liability against the
--     receivable app.accrue booked at clearing). clear_events + app.accrue are NOT touched.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_draw_down_batch(
  p_advertiser uuid, p_batch uuid, p_sum bigint)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_bal   bigint;
  v_res   bigint;
  v_group uuid;
BEGIN
  IF p_batch IS NULL THEN
    RAISE EXCEPTION 'advertiser_draw_down_batch: batch id is required' USING errcode = '22004';
  END IF;
  IF p_sum IS NULL OR p_sum <= 0 THEN
    RETURN jsonb_build_object('drawn', false, 'reason', 'nothing_to_draw', 'amount_micros', 0);
  END IF;

  -- Lock the advertiser's balance row: serializes this draw-down vs concurrent reserves/reconcile.
  SELECT balance_micros, reserved_micros INTO v_bal, v_res
    FROM public.advertiser_balances
   WHERE advertiser_id = p_advertiser
   FOR UPDATE;

  IF NOT FOUND THEN
    -- A prepay advertiser always has a balance row; its absence is a solvency condition.
    PERFORM app.advertiser_alert('advertiser_insufficient_balance', 'critical',
      'advertiser_insufficient_balance:' || p_advertiser::text,
      jsonb_build_object('advertiser_id', p_advertiser, 'batch_id', p_batch,
                         'requested_micros', p_sum, 'reason', 'no_balance_row'));
    RETURN jsonb_build_object('drawn', false, 'reason', 'insufficient_balance',
                              'balance_micros', 0, 'requested_micros', p_sum);
  END IF;

  -- Idempotency: this batch already drawn -> no-op (retry / recovery re-issues the same batch).
  IF EXISTS (SELECT 1 FROM public.advertiser_balance_ledger
              WHERE charge_batch_id = p_batch AND kind = 'drawdown') THEN
    RETURN jsonb_build_object('drawn', false, 'reason', 'duplicate', 'amount_micros', 0, 'batch_id', p_batch);
  END IF;

  -- LOUD reserved_underflow: reserve accounting drifted low (before any clamp hides it).
  IF v_res < p_sum THEN
    PERFORM app.advertiser_alert('advertiser_reserved_underflow', 'high',
      'advertiser_reserved_underflow:' || p_advertiser::text,
      jsonb_build_object('advertiser_id', p_advertiser, 'batch_id', p_batch,
                         'reserved_micros', v_res, 'draw_sum_micros', p_sum));
  END IF;

  -- SOLVENCY guard: never draw below zero. Reaching this means the serve-time reserve already failed.
  IF v_bal < p_sum THEN
    PERFORM app.advertiser_alert('advertiser_insufficient_balance', 'critical',
      'advertiser_insufficient_balance:' || p_advertiser::text,
      jsonb_build_object('advertiser_id', p_advertiser, 'batch_id', p_batch,
                         'balance_micros', v_bal, 'requested_micros', p_sum));
    RETURN jsonb_build_object('drawn', false, 'reason', 'insufficient_balance',
                              'balance_micros', v_bal, 'requested_micros', p_sum);
  END IF;

  -- Draw: decrement balance + release the hold (clamped), then zero the drawn windows' reserve.
  UPDATE public.advertiser_balances
     SET balance_micros  = balance_micros - p_sum,
         reserved_micros = greatest(reserved_micros - p_sum, 0),
         updated_at = now()
   WHERE advertiser_id = p_advertiser;

  UPDATE public.ad_windows w
     SET reserve_micros = 0
   WHERE w.reserve_micros <> 0
     AND w.window_id IN (
       SELECT i.window_id
         FROM public.advertiser_charges ac
         JOIN public.impressions i ON i.id = ac.impression_id
        WHERE ac.charge_batch_id = p_batch);

  -- Zero-sum netting group: release the held liability against the receivable accrue booked at clearing.
  v_group := gen_random_uuid();
  INSERT INTO public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
  VALUES
    (v_group, 'advertiser_drawdown', 'advertiser_funds',    p_sum, 'cleared', 'advertiser_charge_batch', p_batch, p_advertiser),
    (v_group, 'advertiser_drawdown', 'advertiser_billing', -p_sum, 'cleared', 'advertiser_charge_batch', p_batch, p_advertiser);

  -- Append-only sub-ledger row (UNIQUE(charge_batch_id) is the hard idempotency backstop).
  INSERT INTO public.advertiser_balance_ledger
    (advertiser_id, kind, amount_micros, charge_batch_id, entry_group_id)
  VALUES
    (p_advertiser, 'drawdown', p_sum, p_batch, v_group);

  RETURN jsonb_build_object('drawn', true, 'amount_micros', p_sum,
                            'entry_group_id', v_group, 'batch_id', p_batch);
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_draw_down_batch(uuid, uuid, bigint) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_draw_down_batch(uuid, uuid, bigint) TO service_role;

COMMENT ON FUNCTION app.advertiser_draw_down_batch IS
  'Atomic never-negative draw-down at billing-settle (under advertiser_balances FOR UPDATE). Idempotent on charge_batch_id; fires LOUD reserved_underflow (high, before clamp) + insufficient_balance (critical solvency, draws nothing). On draw: balance-=sum, reserved release, zero drawn windows'' reserve, book zero-sum Dr advertiser_funds / Cr advertiser_billing. clear_events/app.accrue untouched. service_role only.';

-- ---------------------------------------------------------------------------
-- 7f. app.advertiser_apply_deposit_reversal — chargeback-after-spend BAD-DEBT write-off.
--
-- Called by the webhook on charge.dispute.funds_withdrawn / charge.refunded for a DEPOSIT. A dispute
-- can land 30-120d later, long after spend drew the balance down — so a naive reversing debit would
-- hit CHECK(>=0), 5xx the webhook, and Stripe-retry forever with the loss unbooked. Instead this
-- books a zero-sum bad-debt group and CLAMPS the balance at 0:
--   v_reclaim = min(R, balance)      (unwind still-held liability)
--   v_bad     = R - v_reclaim        (write off the already-spent gap = max(0, R-balance))
--   balance  := balance - v_reclaim  (= max(0, balance - R); structurally never negative)
--   group: Cr platform_cash -R / Dr advertiser_funds +v_reclaim / Dr advertiser_bad_debt +v_bad
-- IDEMPOTENT on dispute_id (the sub-ledger row is inserted first as the arbiter). Pauses the
-- advertiser's ACTIVE line_items so serving stops instantly (the loss is platform-borne bad debt;
-- the webhook additionally holds downstream publisher payouts — never claws already-paid publishers).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_apply_deposit_reversal(
  p_advertiser uuid, p_dispute_id text, p_amount bigint)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_group   uuid := gen_random_uuid();
  v_hit     uuid;
  v_bal     bigint;
  v_reclaim bigint;
  v_bad     bigint;
BEGIN
  IF p_advertiser IS NULL OR p_dispute_id IS NULL OR p_dispute_id = '' THEN
    RAISE EXCEPTION 'advertiser_apply_deposit_reversal: advertiser + dispute_id are required' USING errcode = '22004';
  END IF;
  IF p_amount IS NULL OR p_amount <= 0 THEN
    RAISE EXCEPTION 'advertiser_apply_deposit_reversal: amount must be positive (got %)', p_amount USING errcode = '22003';
  END IF;

  -- Idempotency arbiter: insert the chargeback row first. A re-delivered dispute event -> no row.
  INSERT INTO public.advertiser_balance_ledger
    (advertiser_id, kind, amount_micros, dispute_id, entry_group_id)
  VALUES
    (p_advertiser, 'chargeback', p_amount, p_dispute_id, v_group)
  ON CONFLICT (dispute_id) DO NOTHING
  RETURNING id INTO v_hit;

  IF v_hit IS NULL THEN
    RETURN jsonb_build_object('reversed', false, 'reason', 'duplicate', 'dispute_id', p_dispute_id);
  END IF;

  -- Lock the balance row and split R into reclaim (still-held) + bad debt (already-spent gap).
  SELECT balance_micros INTO v_bal
    FROM public.advertiser_balances
   WHERE advertiser_id = p_advertiser
   FOR UPDATE;
  v_bal     := COALESCE(v_bal, 0);
  v_reclaim := least(p_amount, v_bal);   -- = min(R, balance)
  v_bad     := p_amount - v_reclaim;      -- = max(0, R - balance)

  -- Clamp the spendable balance at 0 (never a CHECK(>=0) hard-stop). Upsert so an advertiser with
  -- no balance row still books the full amount as bad debt.
  INSERT INTO public.advertiser_balances (advertiser_id, balance_micros, reserved_micros)
  VALUES (p_advertiser, 0, 0)
  ON CONFLICT (advertiser_id)
    DO UPDATE SET balance_micros = public.advertiser_balances.balance_micros - v_reclaim,
                  updated_at = now();

  -- Zero-sum reversal group. platform_cash -R (bank reclaims); advertiser_funds +reclaim (unwind
  -- held liability); advertiser_bad_debt +bad (platform write-off) — omitted when bad = 0.
  INSERT INTO public.ledger_entries
    (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
  VALUES
    (v_group, 'advertiser_chargeback', 'platform_cash',     -p_amount, 'cleared', 'advertiser_dispute', p_advertiser, p_advertiser),
    (v_group, 'advertiser_chargeback', 'advertiser_funds',   v_reclaim, 'cleared', 'advertiser_dispute', p_advertiser, p_advertiser);
  IF v_bad > 0 THEN
    INSERT INTO public.ledger_entries
      (entry_group_id, event_type, account, amount_micros, state, source_type, source_id, advertiser_id)
    VALUES
      (v_group, 'advertiser_chargeback', 'advertiser_bad_debt', v_bad, 'cleared', 'advertiser_dispute', p_advertiser, p_advertiser);
  END IF;

  -- Pause the advertiser's serving line_items so a disputed deposit funds no further delivery.
  -- (line_item status change does NOT trip the advertisers protected-column trigger; the webhook
  --  additionally holds downstream publisher payouts within the exposure window.)
  UPDATE public.line_items li
     SET status = 'paused'
   WHERE li.status = 'active'
     AND li.campaign_id IN (
       SELECT c.id FROM public.campaigns c WHERE c.advertiser_id = p_advertiser);

  RETURN jsonb_build_object('reversed', true, 'advertiser_id', p_advertiser,
                            'amount_micros', p_amount, 'reclaimed_micros', v_reclaim,
                            'bad_debt_micros', v_bad, 'entry_group_id', v_group);
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_apply_deposit_reversal(uuid, text, bigint) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_apply_deposit_reversal(uuid, text, bigint) TO service_role;

COMMENT ON FUNCTION app.advertiser_apply_deposit_reversal IS
  'Chargeback-after-spend bad-debt write-off (idempotent on dispute_id): reclaim=min(R,bal), bad=max(0,R-bal), balance:=max(0,bal-R) (clamped, never CHECK-5xx); books zero-sum Cr platform_cash / Dr advertiser_funds / Dr advertiser_bad_debt and pauses the advertiser''s active line_items. Loss is platform-borne, never clawed from paid publishers. service_role only.';

-- ---------------------------------------------------------------------------
-- 7g. app.advertiser_reconcile_reserved — drift-safe reserved recompute UNDER the row lock.
--
-- reserved_micros is BACKED: it must equal SUM(ad_windows.reserve_micros) over the advertiser's
-- windows (open/credited-undrawn carry >0; drawn/abandoned/void are 0). Clawback/void-before-drawdown
-- timing can drift the cache. This recomputes from the authoritative windows and writes back UNDER
-- the advertiser_balances FOR UPDATE, so it serializes with concurrent reserve/draw-down and can
-- never clobber a hold taken between its read and write (the reconcile-race HIGH fix). Records a
-- reserve_reconcile sub-ledger row (books no money) only when the value actually changed.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.advertiser_reconcile_reserved(p_advertiser uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_before bigint;
  v_after  bigint;
BEGIN
  SELECT reserved_micros INTO v_before
    FROM public.advertiser_balances
   WHERE advertiser_id = p_advertiser
   FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('advertiser_id', p_advertiser, 'changed', false, 'reason', 'no_balance_row');
  END IF;

  -- Single-source invariant math (excludes clawed_back/void windows so a clawback-before-drawdown
  -- self-heals here instead of leaving reserved permanently inflated).
  v_after := app.advertiser_expected_reserved(p_advertiser);

  IF v_after = v_before THEN
    RETURN jsonb_build_object('advertiser_id', p_advertiser, 'changed', false,
                              'reserved_micros', v_before);
  END IF;

  UPDATE public.advertiser_balances
     SET reserved_micros = v_after, updated_at = now()
   WHERE advertiser_id = p_advertiser;

  INSERT INTO public.advertiser_balance_ledger
    (advertiser_id, kind, amount_micros)
  VALUES
    (p_advertiser, 'reserve_reconcile', v_after);

  RETURN jsonb_build_object('advertiser_id', p_advertiser, 'changed', true,
                            'reserved_before', v_before, 'reserved_after', v_after);
END;
$$;
REVOKE ALL ON FUNCTION app.advertiser_reconcile_reserved(uuid) FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION app.advertiser_reconcile_reserved(uuid) TO service_role;

COMMENT ON FUNCTION app.advertiser_reconcile_reserved IS
  'Drift-safe reserved recompute: reserved := SUM(ad_windows.reserve_micros) over the advertiser''s windows, written back UNDER advertiser_balances FOR UPDATE so it serializes with reserve/draw-down and never clobbers a concurrently-taken hold. Records a reserve_reconcile row (no money) only on change. service_role only.';

-- ---------------------------------------------------------------------------
-- 8. public.advertiser_balance_summary() — the self-serve balance read for the portal.
--
-- Self-scoped via app.current_advertiser_id() (only ever the caller's own numbers), RAISE 28000 if
-- the session maps to no org. Clone of publisher_earnings_summary (publisher_earnings_summary.sql
-- :28-71): SECDEF STABLE, REVOKE PUBLIC/anon, GRANT authenticated. Returns spendable/held/available
-- plus lifetime deposited/spent from the sub-ledger.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.advertiser_balance_summary()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_adv       uuid;
  v_balance   bigint;
  v_reserved  bigint;
  v_deposited bigint;
  v_spent     bigint;
BEGIN
  v_adv := (SELECT app.current_advertiser_id());
  IF v_adv IS NULL THEN
    RAISE EXCEPTION 'unauthenticated' USING errcode = '28000';
  END IF;

  SELECT COALESCE(balance_micros, 0), COALESCE(reserved_micros, 0)
    INTO v_balance, v_reserved
    FROM public.advertiser_balances
   WHERE advertiser_id = v_adv;
  v_balance  := COALESCE(v_balance, 0);
  v_reserved := COALESCE(v_reserved, 0);

  SELECT
    COALESCE(SUM(amount_micros) FILTER (WHERE kind = 'deposit'),  0),
    COALESCE(SUM(amount_micros) FILTER (WHERE kind = 'drawdown'), 0)
    INTO v_deposited, v_spent
    FROM public.advertiser_balance_ledger
   WHERE advertiser_id = v_adv;

  RETURN jsonb_build_object(
    'balance_micros',           v_balance,
    'reserved_micros',          v_reserved,
    'available_micros',         v_balance - v_reserved,
    'lifetime_deposited_micros', v_deposited,
    'lifetime_spent_micros',     v_spent
  );
END;
$$;
REVOKE ALL ON FUNCTION public.advertiser_balance_summary() FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.advertiser_balance_summary() TO authenticated;

COMMENT ON FUNCTION public.advertiser_balance_summary IS
  'Self-serve balance read for the advertiser portal: {balance, reserved, available=balance-reserved, lifetime_deposited, lifetime_spent} for the caller''s own advertiser (app.current_advertiser_id()). SECDEF + self-filter; STABLE; granted to authenticated. Clone of publisher_earnings_summary.';

-- ---------------------------------------------------------------------------
-- 9. Migration-tail assertion — anon must hold NO EXECUTE on any function added here.
--
-- The secdef_grant_hardening.sql footgun in code: Supabase auto-grants EXECUTE to PUBLIC (anon
-- inherits) on every new function; revoking only anon leaves it callable. Every fn above ships
-- `REVOKE ALL ... FROM PUBLIC, anon[, authenticated]`; this DO-block fails the migration loudly if
-- any slipped (checks has_function_privilege — false when the function-level ACL denies anon, which
-- holds for the app.* primitives even independent of schema USAGE).
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  v_fn  text;
  v_fns text[] := ARRAY[
    'public.advertiser_balance_summary()',
    'app.advertiser_min_bid_micros()',
    'app.advertiser_expected_reserved(uuid)',
    'app.advertiser_expected_balance(uuid)',
    'app.advertiser_balance_ledger_immutable()',
    'app.advertiser_alert(text, text, text, jsonb)',
    'app.advertiser_credit_deposit(uuid, text, text, text, bigint)',
    'app.advertiser_reserve(uuid, bigint)',
    'app.advertiser_release(uuid, bigint)',
    'app.advertiser_draw_down_batch(uuid, uuid, bigint)',
    'app.advertiser_apply_deposit_reversal(uuid, text, bigint)',
    'app.advertiser_reconcile_reserved(uuid)'
  ];
BEGIN
  FOREACH v_fn IN ARRAY v_fns LOOP
    IF has_function_privilege('anon', v_fn, 'EXECUTE') THEN
      RAISE EXCEPTION 'anon retains EXECUTE on % — REVOKE ALL FROM PUBLIC, anon missing', v_fn;
    END IF;
  END LOOP;
END;
$$;
