-- lumaline Phase 1 schema — double-entry ledger + payouts.
--
-- Sign convention (amount_micros is signed, every entry_group_id sums to 0):
--   accrual of gross G  ->  Dr advertiser_billing +G
--                           Cr publisher_earnings -0.6G   (60% publisher-favored)
--                           Cr platform_revenue   -0.4G
-- A publisher's payable balance is the magnitude of their cleared
-- publisher_earnings (negative) entries, net of any cleared payout debits.

-- ---------------------------------------------------------------------------
-- ledger_entries
-- ---------------------------------------------------------------------------
create table public.ledger_entries (
  id             uuid primary key default gen_random_uuid(),
  entry_group_id uuid not null,                  -- one balanced group per economic event
  event_type     text not null,                  -- e.g. 'cpva_accrual', 'cpc_accrual', 'clawback', 'payout'
  account        ledger_account not null,
  amount_micros  bigint not null,                -- signed; group sums to 0
  state          ledger_state not null default 'provisional',
  source_type    text,                           -- e.g. 'impression', 'click', 'payout'
  source_id      uuid,
  publisher_id   uuid references public.publishers (id) on delete cascade,  -- set on publisher_earnings legs
  created_at     timestamptz not null default now()
);

comment on table public.ledger_entries is
  'Append-only double-entry ledger. The ledger_group_balances constraint trigger enforces SUM(amount_micros)=0 per entry_group_id at COMMIT.';

create index ledger_entries_group_idx               on public.ledger_entries (entry_group_id);
create index ledger_entries_publisher_account_state on public.ledger_entries (publisher_id, account, state);
create index ledger_entries_source_idx              on public.ledger_entries (source_type, source_id);

-- Per-group zero-sum invariant. Deferred to COMMIT so a balanced multi-row group
-- can be inserted across several statements within one transaction. Checks every
-- entry_group_id touched by the row (handles INSERT/UPDATE/DELETE incl. regroup).
create or replace function app.ledger_group_balances()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  g     uuid;
  v_sum bigint;
begin
  for g in
    select x from (values (new.entry_group_id), (old.entry_group_id)) as v (x)
    where x is not null
  loop
    select coalesce(sum(amount_micros), 0) into v_sum
    from public.ledger_entries
    where entry_group_id = g;

    if v_sum <> 0 then
      raise exception 'ledger entry_group_id % does not balance: sum=% (must be 0)', g, v_sum;
    end if;
  end loop;
  return null;
end;
$$;
revoke execute on function app.ledger_group_balances() from public;

create constraint trigger ledger_group_balances_trg
  after insert or update or delete on public.ledger_entries
  deferrable initially deferred
  for each row execute function app.ledger_group_balances();

alter table public.ledger_entries enable row level security;

-- A publisher may read ONLY their own publisher_earnings legs; admins read all.
create policy ledger_entries_select_own on public.ledger_entries
  for select to authenticated
  using (
    (account = 'publisher_earnings' and publisher_id = (select app.current_publisher_id()))
    or (select app.is_admin())
  );
create policy ledger_entries_admin_write on public.ledger_entries
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy ledger_entries_service on public.ledger_entries
  for all to service_role using (true) with check (true);

grant select on public.ledger_entries to authenticated;
grant select, insert, update, delete on public.ledger_entries to service_role;

-- ---------------------------------------------------------------------------
-- payouts
-- ---------------------------------------------------------------------------
create table public.payouts (
  id                 uuid primary key default gen_random_uuid(),
  publisher_id       uuid not null references public.publishers (id) on delete cascade,
  amount_micros      bigint not null check (amount_micros >= 0),
  status             payout_status_kind not null default 'pending',
  stripe_transfer_id text unique,
  hold_until         timestamptz,
  min_payout_micros  bigint not null default 25000000,   -- $25.00
  created_at         timestamptz not null default now()
);

create index payouts_publisher_id_idx on public.payouts (publisher_id);

alter table public.payouts enable row level security;

create policy payouts_select_own on public.payouts
  for select to authenticated
  using (publisher_id = (select app.current_publisher_id()) or (select app.is_admin()));
create policy payouts_admin_write on public.payouts
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy payouts_service on public.payouts
  for all to service_role using (true) with check (true);

grant select on public.payouts to authenticated;
grant select, insert, update, delete on public.payouts to service_role;
