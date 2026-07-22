-- lumaline security-hardening (Cluster B / A11): freeze the settle route on each batch at RESERVE time.
--
-- Recovery previously routed a reserved-but-unsettled batch by the advertiser's CURRENT billing_mode.
-- An advertiser flip (postpay<->prepay) between reserve and recovery could re-route a half-settled
-- batch to the OTHER money path (draw prepay balance AND charge a Stripe PI for the same groups =
-- double-collect). Persisting the route at reserve makes recovery deterministic: a batch settles the
-- same way it was reserved, regardless of any later billing_mode flip.
--
-- No function created -> no REVOKE/GRANT tail needed; the column inherits the existing
-- advertiser_charges grants (service_role already has INSERT/UPDATE).

set local lock_timeout = '2s';
set local statement_timeout = '15s';

alter table public.advertiser_charges
  add column if not exists settle_mode text
    check (settle_mode is null or settle_mode in ('postpay', 'prepay'));

comment on column public.advertiser_charges.settle_mode is
  'Money path this row''s batch was reserved to settle by (postpay = Stripe PI, prepay = balance '
  'draw-down), frozen at reserve. Recovery routes by THIS, never the advertiser''s current billing_mode, '
  'so a mode flip mid-recovery cannot double-collect. NULL on legacy rows reserved before this column '
  'existed (recovery falls back to the advertiser''s current billing_mode for those).';
