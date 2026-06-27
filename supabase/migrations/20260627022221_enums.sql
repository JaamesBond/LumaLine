-- lumaline Phase 1 schema — enumerated types.
-- Centralized so every table references the same domain. Enum type names do not
-- collide with column names (separate namespaces), so they read plainly.

-- Publisher payout eligibility. `ineligible_country` = accrues earnings but
-- cannot be paid via Stripe Connect (disclosed at signup).
create type payout_status as enum ('none', 'pending', 'verified', 'ineligible_country');

-- Publisher account standing.
create type publisher_status as enum ('active', 'suspended');

-- RFC 8628 device-authorization code lifecycle.
create type device_auth_status as enum ('pending', 'approved', 'denied', 'expired', 'consumed');

-- Advertiser / campaign / line-item / creative booking states (v1 manual booking).
create type advertiser_status as enum ('active', 'suspended');
create type campaign_status   as enum ('draft', 'active', 'paused', 'archived', 'completed');
create type line_item_status  as enum ('draft', 'active', 'paused', 'archived');
create type creative_status   as enum ('pending_review', 'active', 'paused', 'rejected');

-- Budget pacing strategy for a line item.
create type pacing_mode as enum ('even', 'asap');

-- ad_windows lifecycle: open -> credited (billable impression) | abandoned
-- (stale/incomplete) | void (house/no-fill, never billed).
create type ad_window_state as enum ('open', 'credited', 'abandoned', 'void');

-- Durable billable record states. provisional -> cleared (past 72h clawback
-- window) | clawed_back (IVT) | void (house/no-fill).
create type impression_state as enum ('provisional', 'cleared', 'clawed_back', 'void');
create type click_state      as enum ('provisional', 'cleared', 'clawed_back', 'void');

-- Double-entry ledger.
create type ledger_account as enum (
  'advertiser_billing',  -- receivable from advertiser (debit, +)
  'publisher_earnings',  -- owed to publisher (credit, -)
  'platform_revenue',    -- platform take (credit, -)
  'platform_cash'        -- cash moved on payout
);
create type ledger_state as enum ('provisional', 'cleared', 'reversed');

-- Payout lifecycle (Stripe Connect transfer).
create type payout_status_kind as enum ('pending', 'in_transit', 'paid', 'failed', 'canceled');
