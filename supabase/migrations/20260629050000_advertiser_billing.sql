-- lumaline M2-T4 — Stripe billing layer: advertiser_charges table + supporting schema.
--
-- Architecture (how this fits the clearing pipeline):
--   1. close_window() → impression is 'provisional', no ledger yet.
--   2. clear_events() (hourly pg_cron) promotes impressions provisional→cleared and books
--      a balanced 3-leg ledger_entries group (advertiser_billing / publisher_earnings /
--      platform_revenue) with a shared entry_group_id.
--   3. This migration provides:
--        a. advertiser_charges — one row per billing attempt (idempotent by entry_group_id)
--        b. uncharged_advertiser_billings VIEW — finds cleared advertiser_billing entries
--           with no corresponding charge row, joined through to advertiser identity.
--        c. stripe_customer_id on advertisers — persisted after first get-or-create call.
--
-- T4 scopes to cpva_accrual (CPVA = views, the everywhere model). cpc_accrual billing
-- requires a different join path (click → window → impression) and is deferred.
--
-- TRUST INVARIANTS:
--   1. House/sentinel (is_house=true) → always skipped, never billed (layer in view +
--      app guard in edge fn).
--   2. Idempotency: UNIQUE(entry_group_id) is the DB backstop; Stripe idempotency key
--      (lumaline_grp_<entry_group_id>) prevents double-charges even on concurrent retries.
--   3. Only cleared ledger entries are charged (72h clawback window has passed).
--   4. Test mode: STRIPE_SECRET_KEY must be sk_test_* when STRIPE_ASSERT_TEST=true.

-- ---------------------------------------------------------------------------
-- A. stripe_customer_id on advertisers (nullable — populated at first charge)
-- ---------------------------------------------------------------------------
ALTER TABLE public.advertisers
  ADD COLUMN IF NOT EXISTS stripe_customer_id text;

-- ---------------------------------------------------------------------------
-- B. paused line_item_status (safety add — already exists in the enum, no-op)
-- ---------------------------------------------------------------------------
ALTER TYPE public.line_item_status ADD VALUE IF NOT EXISTS 'paused';

-- ---------------------------------------------------------------------------
-- C. advertiser_charges table
--
-- One row per billing attempt. UNIQUE(entry_group_id) is the idempotency backstop —
-- concurrent billing runs cannot create a second charge for the same ledger group.
-- ---------------------------------------------------------------------------
CREATE TABLE public.advertiser_charges (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entry_group_id     uuid NOT NULL UNIQUE,    -- idempotency: one charge per ledger group
  advertiser_id      uuid NOT NULL REFERENCES public.advertisers (id),
  impression_id      uuid REFERENCES public.impressions (id),
  amount_micros      bigint NOT NULL,         -- = advertiser_billing ledger entry amount_micros
  amount_cents       integer NOT NULL,        -- = round(amount_micros / 10000), for Stripe
  stripe_charge_id   text,                   -- set on success (PaymentIntent id)
  stripe_customer_id text,                   -- Stripe customer used for this charge
  status             text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'succeeded', 'failed', 'skipped')),
  failure_reason     text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  attempted_at       timestamptz
);

-- RLS: the ensure_rls event trigger auto-enables RLS on CREATE TABLE; the explicit
-- call here is idempotent and documents intent clearly.
ALTER TABLE public.advertiser_charges ENABLE ROW LEVEL SECURITY;

-- Admins can read and manage all charge records (billing ops, disputes).
CREATE POLICY advertiser_charges_admin ON public.advertiser_charges
  FOR ALL TO authenticated
  USING ((SELECT app.is_admin()))
  WITH CHECK ((SELECT app.is_admin()));

-- service_role is used by the billing edge function (bypasses RLS anyway, but
-- the explicit policy documents the intent and is required for non-service roles).
CREATE POLICY advertiser_charges_service ON public.advertiser_charges
  FOR ALL TO service_role
  USING (true)
  WITH CHECK (true);

GRANT SELECT ON public.advertiser_charges TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.advertiser_charges TO service_role;

-- ---------------------------------------------------------------------------
-- D. uncharged_advertiser_billings VIEW
--
-- Returns cleared cpva_accrual advertiser_billing ledger entries that have not
-- yet been processed (no advertiser_charges row), with the full advertiser
-- resolution chain so the billing function can determine identity in one query.
--
-- Accessible only to service_role — do NOT grant to authenticated or anon.
-- The view resolves the join chain: ledger_entries → impressions → line_items
-- → campaigns → advertisers, LEFT JOIN advertiser_charges to find uncharged rows.
-- ---------------------------------------------------------------------------
CREATE VIEW public.uncharged_advertiser_billings AS
SELECT
  le.entry_group_id,
  le.event_type,
  le.amount_micros,
  le.source_id         AS impression_id,
  i.line_item_id,
  i.publisher_id,
  li.campaign_id,
  c.advertiser_id,
  a.name               AS advertiser_name,
  a.is_house,
  a.stripe_customer_id,
  le.created_at        AS cleared_at
FROM public.ledger_entries le
JOIN public.impressions i  ON i.id  = le.source_id
JOIN public.line_items  li ON li.id = i.line_item_id
JOIN public.campaigns   c  ON c.id  = li.campaign_id
JOIN public.advertisers a  ON a.id  = c.advertiser_id
LEFT JOIN public.advertiser_charges ac ON ac.entry_group_id = le.entry_group_id
WHERE le.account    = 'advertiser_billing'
  AND le.state      = 'cleared'
  AND le.event_type = 'cpva_accrual'   -- cpc_accrual billing deferred to follow-up task
  AND ac.entry_group_id IS NULL;       -- not yet charged (any status)

-- Grant only to service_role — billing function uses the service-role key.
-- Authenticated admins can read advertiser_charges directly for ops visibility.
GRANT SELECT ON public.uncharged_advertiser_billings TO service_role;
