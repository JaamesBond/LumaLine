-- lumaline Phase 1 schema — advertisers, campaigns, line_items, creatives.
-- v1 is manual booking by internal admins; all four tables are admin-only via RLS
-- (plus a service_role policy for edge functions / the serving RPC).

-- ---------------------------------------------------------------------------
-- advertisers
-- ---------------------------------------------------------------------------
create table public.advertisers (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  status     advertiser_status not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger advertisers_set_updated_at
  before update on public.advertisers
  for each row execute function app.set_updated_at();

-- ---------------------------------------------------------------------------
-- campaigns
-- ---------------------------------------------------------------------------
create table public.campaigns (
  id            uuid primary key default gen_random_uuid(),
  advertiser_id uuid not null references public.advertisers (id) on delete cascade,
  name          text not null,
  status        campaign_status not null default 'draft',
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create index campaigns_advertiser_id_idx on public.campaigns (advertiser_id);

create trigger campaigns_set_updated_at
  before update on public.campaigns
  for each row execute function app.set_updated_at();

-- ---------------------------------------------------------------------------
-- line_items — the served / paced / capped unit
-- ---------------------------------------------------------------------------
create table public.line_items (
  id                    uuid primary key default gen_random_uuid(),
  campaign_id           uuid not null references public.campaigns (id) on delete cascade,
  cpva_bid_micros       bigint not null default 0 check (cpva_bid_micros >= 0),  -- per attention-second
  cpc_bid_micros        bigint not null default 0 check (cpc_bid_micros >= 0),
  weight                integer not null default 1 check (weight > 0),
  budget_total_micros   bigint check (budget_total_micros >= 0),
  budget_daily_micros   bigint check (budget_daily_micros >= 0),
  pacing_mode           pacing_mode not null default 'even',
  frequency_cap_per_day integer check (frequency_cap_per_day >= 0),
  start_at              timestamptz,
  end_at                timestamptz,
  targeting             jsonb not null default '{}'::jsonb,    -- v1: global / none
  status                line_item_status not null default 'draft',
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now()
);

create index line_items_campaign_id_idx on public.line_items (campaign_id);
create index line_items_status_idx on public.line_items (status);

create trigger line_items_set_updated_at
  before update on public.line_items
  for each row execute function app.set_updated_at();

-- ---------------------------------------------------------------------------
-- creatives
-- ---------------------------------------------------------------------------
create table public.creatives (
  id           uuid primary key default gen_random_uuid(),
  line_item_id uuid not null references public.line_items (id) on delete cascade,
  line         text not null,                       -- the sponsored status-bar text
  dest_url     text,                                -- click destination (nullable: view-only)
  label        text not null default 'sponsored',
  status       creative_status not null default 'pending_review',
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create index creatives_line_item_id_idx on public.creatives (line_item_id);
create index creatives_status_idx on public.creatives (status);

create trigger creatives_set_updated_at
  before update on public.creatives
  for each row execute function app.set_updated_at();

-- ---------------------------------------------------------------------------
-- RLS — admin-only (v1). Non-admin authenticated users match no rows; the table
-- privilege is still required for the request to reach RLS, so grant DML to
-- authenticated and let the admin policy gate it.
-- ---------------------------------------------------------------------------
alter table public.advertisers enable row level security;
alter table public.campaigns   enable row level security;
alter table public.line_items  enable row level security;
alter table public.creatives   enable row level security;

create policy advertisers_admin_all on public.advertisers
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy advertisers_service on public.advertisers
  for all to service_role using (true) with check (true);

create policy campaigns_admin_all on public.campaigns
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy campaigns_service on public.campaigns
  for all to service_role using (true) with check (true);

create policy line_items_admin_all on public.line_items
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy line_items_service on public.line_items
  for all to service_role using (true) with check (true);

create policy creatives_admin_all on public.creatives
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy creatives_service on public.creatives
  for all to service_role using (true) with check (true);

grant select, insert, update, delete on public.advertisers to authenticated, service_role;
grant select, insert, update, delete on public.campaigns   to authenticated, service_role;
grant select, insert, update, delete on public.line_items  to authenticated, service_role;
grant select, insert, update, delete on public.creatives   to authenticated, service_role;
