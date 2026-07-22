-- lumaline security-audit (Cluster D / A5) — namespace the Stripe webhook dedup per function.
--
-- stripe-connect and advertiser-portal share public.stripe_webhook_events, keyed only on the
-- account-global event_id. When both endpoints receive the same event id (Stripe fans a single
-- event out to every subscribed endpoint with the SAME event.id), the fn that records first turns
-- the OTHER fn's dedup check into a permanent no-op -> a money event (e.g. charge.refunded to
-- advertiser-portal, or charge.dispute.* to stripe-connect) is silently lost. Fix: dedup per
-- (event_id, fn) so each function has its own namespace.
--
-- This is the ONE authoritative webhook-dedup schema change for the audit. The stripe-connect
-- dispute handler (Cluster C / A9.2) MUST use this same fn-scoping (fn='stripe-connect') rather
-- than a bare string-prefixed event id; the edge functions are edited to scope by fn.

alter table public.stripe_webhook_events
  add column if not exists fn text not null default 'unknown';

comment on column public.stripe_webhook_events.fn is
  'Which edge function recorded this dedup row (e.g. stripe-connect, advertiser-portal). Dedup is per '
  '(event_id, fn): one Stripe event delivered to two endpoints records one row per fn, so neither '
  'blocks the other. Default unknown only backfills pre-namespace rows.';

-- Swap the single-column PK for the composite (event_id, fn). Existing rows are unique on event_id
-- (the old PK), so (event_id, 'unknown') is unique -> the composite PK builds cleanly.
alter table public.stripe_webhook_events drop constraint if exists stripe_webhook_events_pkey;
alter table public.stripe_webhook_events
  add constraint stripe_webhook_events_pkey primary key (event_id, fn);

-- Re-assert the hardened posture (idempotent; RLS policy + service grants already exist).
revoke all on public.stripe_webhook_events from public, anon;
grant select, insert on public.stripe_webhook_events to service_role;
