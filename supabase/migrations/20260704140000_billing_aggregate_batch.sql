-- lumaline — per-advertiser aggregate charging: stable batch identity + single-flight lock.
--
-- Aggregating an advertiser's sub-minimum impressions into ONE PaymentIntent introduced a
-- double-charge risk (adversarial review F1/F2): the Stripe idempotency key was derived from the
-- live set of uncharged groups, which GROWS as impressions accrue — so a crash/ambiguous-error
-- retry that saw a new impression minted a NEW key and Stripe re-charged the already-billed ones.
--
-- Fix: a stable per-batch identity. When a run reserves an advertiser's groups it stamps them with
-- ONE charge_batch_id and derives the PI idempotency key from THAT (immutable). New accrual forms a
-- new batch; recovery re-issues each existing batch under its own stable key — impressions can never
-- migrate between batches, so a retry can never merge fresh groups into an already-attempted charge.

set local lock_timeout = '2s';
set local statement_timeout = '15s';

alter table public.advertiser_charges
  add column if not exists charge_batch_id uuid;

comment on column public.advertiser_charges.charge_batch_id is
  'Stable identity of the aggregate charge this row belongs to. The Stripe PaymentIntent idempotency '
  'key is derived from it (lumaline_agg_<charge_batch_id>), so a crash-retry re-issues the SAME PI and '
  'never merges freshly-accrued impressions into an already-attempted charge.';

-- Recovery groups reserved-but-unsettled rows by batch; index that hot lookup.
create index if not exists advertiser_charges_pending_batch_idx
  on public.advertiser_charges (charge_batch_id)
  where status = 'pending';

-- ---------------------------------------------------------------------------
-- Single-flight lock for the billing cycle (defense-in-depth atop per-group claiming). One row;
-- claimed with an atomic compare-and-swap + stale-reclaim TTL so a crashed run cannot wedge it shut.
-- ---------------------------------------------------------------------------
create table if not exists public.billing_run_lock (
  id        boolean primary key default true,
  locked_at timestamptz,
  token     uuid,
  constraint billing_run_lock_singleton check (id)
);
insert into public.billing_run_lock (id) values (true) on conflict (id) do nothing;
alter table public.billing_run_lock enable row level security;  -- service_role only; no policies

create or replace function public.billing_lock_acquire(p_ttl interval default interval '10 minutes')
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_token uuid := gen_random_uuid();
begin
  -- Row lock serializes concurrent acquirers; the WHERE re-checks freshness under it, so exactly
  -- one caller can claim a free-or-stale lock.
  update public.billing_run_lock
     set locked_at = now(), token = v_token
   where id = true and (locked_at is null or locked_at < now() - p_ttl);
  if not found then return null; end if;
  return v_token;
end;
$$;
revoke execute on function public.billing_lock_acquire(interval) from anon, authenticated, public;
grant  execute on function public.billing_lock_acquire(interval) to service_role;

create or replace function public.billing_lock_release(p_token uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hit boolean;
begin
  update public.billing_run_lock set locked_at = null, token = null
   where id = true and token = p_token
  returning true into v_hit;
  return coalesce(v_hit, false);
end;
$$;
revoke execute on function public.billing_lock_release(uuid) from anon, authenticated, public;
grant  execute on function public.billing_lock_release(uuid) to service_role;
