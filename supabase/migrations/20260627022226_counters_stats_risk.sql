-- lumaline Phase 1 schema — serving counters, pacing stats, IVT risk flags.
-- Machine-maintained by the serving / clearing RPCs (service_role). Admins may
-- read them in the portal; publishers do not access them directly.

-- ---------------------------------------------------------------------------
-- serve_counters — per (publisher, line_item, day) frequency cap counter
-- (account-keyed so the cap follows the dev across devices)
-- ---------------------------------------------------------------------------
create table public.serve_counters (
  publisher_id uuid not null references public.publishers (id) on delete cascade,
  line_item_id uuid not null references public.line_items (id) on delete cascade,
  day          date not null,
  served       integer not null default 0 check (served >= 0),
  primary key (publisher_id, line_item_id, day)
);

-- PK leads with publisher_id (covers that FK); index the other FK explicitly.
create index serve_counters_line_item_id_idx on public.serve_counters (line_item_id);

alter table public.serve_counters enable row level security;

create policy serve_counters_admin_read on public.serve_counters
  for select to authenticated
  using ((select app.is_admin()));
create policy serve_counters_service on public.serve_counters
  for all to service_role using (true) with check (true);

grant select on public.serve_counters to authenticated;
grant select, insert, update, delete on public.serve_counters to service_role;

-- ---------------------------------------------------------------------------
-- line_item_daily_stats — per (line_item, day) spend for smooth pacing
-- ---------------------------------------------------------------------------
create table public.line_item_daily_stats (
  line_item_id uuid not null references public.line_items (id) on delete cascade,
  day          date not null,
  spent_micros bigint not null default 0 check (spent_micros >= 0),
  primary key (line_item_id, day)
);

alter table public.line_item_daily_stats enable row level security;

create policy line_item_daily_stats_admin_read on public.line_item_daily_stats
  for select to authenticated
  using ((select app.is_admin()));
create policy line_item_daily_stats_service on public.line_item_daily_stats
  for all to service_role using (true) with check (true);

grant select on public.line_item_daily_stats to authenticated;
grant select, insert, update, delete on public.line_item_daily_stats to service_role;

-- ---------------------------------------------------------------------------
-- risk_flags — invalid-traffic (IVT) signals feeding clawback
-- ---------------------------------------------------------------------------
create table public.risk_flags (
  id            uuid primary key default gen_random_uuid(),
  impression_id uuid references public.impressions (id) on delete cascade,
  window_id     uuid,                            -- logical ref to ad_windows (no FK: unlogged)
  reason        text not null,
  created_at    timestamptz not null default now()
);

create index risk_flags_impression_id_idx on public.risk_flags (impression_id);
create index risk_flags_window_id_idx     on public.risk_flags (window_id);

alter table public.risk_flags enable row level security;

create policy risk_flags_admin_read on public.risk_flags
  for select to authenticated
  using ((select app.is_admin()));
create policy risk_flags_service on public.risk_flags
  for all to service_role using (true) with check (true);

grant select on public.risk_flags to authenticated;
grant select, insert, update, delete on public.risk_flags to service_role;
