-- lumaline Phase 1 schema — publishers, devices, device_auth_codes.
-- These map a developer's auth identity to a payee and to attested client devices.

-- ---------------------------------------------------------------------------
-- publishers
-- ---------------------------------------------------------------------------
create table public.publishers (
  id                uuid primary key default gen_random_uuid(),
  auth_user_id      uuid not null unique references auth.users (id) on delete cascade,
  handle            text not null unique,
  country           text,                                  -- ISO 3166-1 alpha-2
  stripe_account_id text unique,
  payout_status     payout_status    not null default 'none',
  status            publisher_status not null default 'active',
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

comment on table public.publishers is
  'A developer running the lumaline client; the payee for accrued earnings.';

-- auth.uid() -> publisher id. SECURITY DEFINER + STABLE so RLS policies resolve
-- it once per statement and so it bypasses publishers'' own RLS (no recursion).
-- Used as `(select app.current_publisher_id())` throughout.
create or replace function app.current_publisher_id()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select id
  from public.publishers
  where auth_user_id = (select auth.uid());
$$;
revoke execute on function app.current_publisher_id() from public;
grant execute on function app.current_publisher_id() to authenticated, service_role;

create trigger publishers_set_updated_at
  before update on public.publishers
  for each row execute function app.set_updated_at();

alter table public.publishers enable row level security;

-- Read: own row, or any row for admins.
create policy publishers_select_own on public.publishers
  for select to authenticated
  using ((select auth.uid()) = auth_user_id or (select app.is_admin()));

-- Update: own row only. Column-level grants below restrict *which* columns a
-- publisher may change, so they cannot self-elevate payout_status or un-suspend.
create policy publishers_update_own on public.publishers
  for update to authenticated
  using ((select auth.uid()) = auth_user_id)
  with check ((select auth.uid()) = auth_user_id);

create policy publishers_service on public.publishers
  for all to service_role
  using (true) with check (true);

-- Data API is "always revoked" by default (see config.toml auto_expose note):
-- grant explicitly. Publishers may read the table (RLS limits rows) but may only
-- edit profile fields; trust-sensitive columns (payout_status, status,
-- stripe_account_id) are mutated only by service_role (Stripe webhook / admin fn).
grant select on public.publishers to authenticated;
grant update (handle, country) on public.publishers to authenticated;
grant select, insert, update, delete on public.publishers to service_role;

-- ---------------------------------------------------------------------------
-- devices
-- ---------------------------------------------------------------------------
create table public.devices (
  id             uuid primary key default gen_random_uuid(),
  publisher_id   uuid not null references public.publishers (id) on delete cascade,
  label          text,
  client_version text,
  attested       boolean not null default false,
  revoked_at     timestamptz,
  created_at     timestamptz not null default now()
);

comment on table public.devices is
  'An attested client install. window RPCs check revoked_at IS NULL for instant revocation.';

create index devices_publisher_id_idx on public.devices (publisher_id);

alter table public.devices enable row level security;

-- Publisher sees own devices; service_role manages (device-code flow + revoke).
create policy devices_select_own on public.devices
  for select to authenticated
  using (publisher_id = (select app.current_publisher_id()) or (select app.is_admin()));

create policy devices_service on public.devices
  for all to service_role
  using (true) with check (true);

grant select on public.devices to authenticated;
grant select, insert, update, delete on public.devices to service_role;

-- ---------------------------------------------------------------------------
-- device_auth_codes  (RFC 8628; service_role ONLY — never a client)
-- ---------------------------------------------------------------------------
create table public.device_auth_codes (
  id               uuid primary key default gen_random_uuid(),
  device_code_hash text not null unique,            -- hash of the secret device_code
  user_code        text not null unique,            -- short code the dev types at /activate
  status           device_auth_status not null default 'pending',
  publisher_id     uuid references public.publishers (id) on delete cascade,
  expires_at       timestamptz not null,
  created_at       timestamptz not null default now()
);

comment on table public.device_auth_codes is
  'Device-authorization grants. Handled entirely by the auth-device edge fn (service_role).';

create index device_auth_codes_publisher_id_idx on public.device_auth_codes (publisher_id);

alter table public.device_auth_codes enable row level security;

-- Only service_role. RLS enabled + no authenticated/anon policy = deny-all to them.
create policy device_auth_codes_service on public.device_auth_codes
  for all to service_role
  using (true) with check (true);

grant select, insert, update, delete on public.device_auth_codes to service_role;
