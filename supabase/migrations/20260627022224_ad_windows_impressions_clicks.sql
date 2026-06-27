-- lumaline Phase 1 schema — ad_windows (transient), impressions + clicks (durable).
--
-- NOTE ON RPC BODIES: this migration creates the *tables* only. The
-- SECURITY DEFINER RPCs that read/write them — window_open_select(),
-- window_beat(), close_window(), clear_events() — are gated on a separate review
-- and land in the NEXT migration. ad_windows is therefore service_role-only here;
-- those RPCs will be the sole client-facing access path.
--
-- ad_windows is UNLOGGED (halves write cost; a crash loses only in-flight,
-- provisional windows — acceptable). Because a permanent table's foreign key may
-- only reference another permanent table, impressions/clicks/risk_flags reference
-- a window by window_id WITHOUT a FK constraint (logical reference only).

-- ---------------------------------------------------------------------------
-- ad_windows — one row per open window, UPDATEd in place per heartbeat
-- ---------------------------------------------------------------------------
create unlogged table public.ad_windows (
  window_id         uuid primary key default gen_random_uuid(),
  publisher_id      uuid not null references public.publishers (id) on delete cascade,
  device_id         uuid not null references public.devices (id) on delete cascade,
  line_item_id      uuid references public.line_items (id) on delete set null,
  creative_id       uuid references public.creatives (id) on delete set null,
  challenge         text not null,              -- per-window HMAC key (shared w/ client by design)
  nonce             text not null,
  seq               integer not null default 0,
  prev_hash         text,                       -- heartbeat hash-chain head
  last_recv_at      timestamptz,
  beats_count       integer not null default 0,
  activity_progress boolean not null default false,
  activity_max_bucket text,                     -- none | low | med | high
  started_at        timestamptz not null default now(),
  dwell_ms          integer not null default 5000,
  hb_interval_ms    integer not null default 1000,
  click_token_hash  text,
  state             ad_window_state not null default 'open',
  created_at        timestamptz not null default now()
);

comment on table public.ad_windows is
  'Transient (UNLOGGED) per-window state. RPC-only access; write RPCs arrive in the next migration. pg_cron sweeps stale open rows -> abandoned.';

create index ad_windows_publisher_id_idx     on public.ad_windows (publisher_id);
create index ad_windows_device_id_idx        on public.ad_windows (device_id);
create index ad_windows_line_item_id_idx     on public.ad_windows (line_item_id);
create index ad_windows_creative_id_idx      on public.ad_windows (creative_id);
create index ad_windows_state_started_at_idx on public.ad_windows (state, started_at);  -- stale sweep
create index ad_windows_click_token_hash_idx on public.ad_windows (click_token_hash);   -- click match

alter table public.ad_windows enable row level security;

-- No client SELECT/DML policy by design — access is exclusively through the
-- (forthcoming) SECURITY DEFINER RPCs. service_role retained for ops/sweeps.
create policy ad_windows_service on public.ad_windows
  for all to service_role
  using (true) with check (true);

grant select, insert, update, delete on public.ad_windows to service_role;

-- ---------------------------------------------------------------------------
-- impressions — durable billable record (one per credited/void window)
-- ---------------------------------------------------------------------------
create table public.impressions (
  id                uuid primary key default gen_random_uuid(),
  window_id         uuid not null unique,        -- logical ref to ad_windows (no FK: unlogged)
  publisher_id      uuid not null references public.publishers (id) on delete cascade,
  line_item_id      uuid references public.line_items (id) on delete set null,
  creative_id       uuid references public.creatives (id) on delete set null,
  attention_seconds integer not null default 0,
  multiplier        numeric not null default 1,
  gross_micros      bigint  not null default 0,
  state             impression_state not null default 'provisional',
  ip_hash           text,
  asn               text,
  created_at        timestamptz not null default now()
);

create index impressions_publisher_created_idx on public.impressions (publisher_id, created_at);
create index impressions_state_created_idx     on public.impressions (state, created_at);
create index impressions_ip_hash_created_idx   on public.impressions (ip_hash, created_at);
create index impressions_line_item_id_idx      on public.impressions (line_item_id);
create index impressions_creative_id_idx       on public.impressions (creative_id);

alter table public.impressions enable row level security;

create policy impressions_select_own on public.impressions
  for select to authenticated
  using (publisher_id = (select app.current_publisher_id()) or (select app.is_admin()));
create policy impressions_admin_write on public.impressions
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy impressions_service on public.impressions
  for all to service_role using (true) with check (true);

grant select on public.impressions to authenticated;
grant select, insert, update, delete on public.impressions to service_role;

-- ---------------------------------------------------------------------------
-- clicks — durable click record; click_token_hash UNIQUE = dedupe
-- ---------------------------------------------------------------------------
create table public.clicks (
  id               uuid primary key default gen_random_uuid(),
  window_id        uuid not null,                -- logical ref to ad_windows (no FK: unlogged)
  publisher_id     uuid not null references public.publishers (id) on delete cascade,
  line_item_id     uuid references public.line_items (id) on delete set null,
  creative_id      uuid references public.creatives (id) on delete set null,
  click_token_hash text not null unique,         -- dedupe: one paid click per token
  gross_micros     bigint not null default 0,
  state            click_state not null default 'provisional',
  created_at       timestamptz not null default now()
);

create index clicks_publisher_created_idx on public.clicks (publisher_id, created_at);
create index clicks_window_id_idx         on public.clicks (window_id);
create index clicks_line_item_id_idx      on public.clicks (line_item_id);
create index clicks_creative_id_idx       on public.clicks (creative_id);

alter table public.clicks enable row level security;

create policy clicks_select_own on public.clicks
  for select to authenticated
  using (publisher_id = (select app.current_publisher_id()) or (select app.is_admin()));
create policy clicks_admin_write on public.clicks
  for all to authenticated
  using ((select app.is_admin())) with check ((select app.is_admin()));
create policy clicks_service on public.clicks
  for all to service_role using (true) with check (true);

grant select on public.clicks to authenticated;
grant select, insert, update, delete on public.clicks to service_role;
