-- lumaline PRODUCTION seed — the anonymous, signed, never-billed self-promo feed.
--
-- This is NOT supabase/seed.sql (that dev seed has an example.com test creative and is
-- loaded by `db reset`). This file is applied ONCE to the live project, by hand, via the
-- Management API SQL runner (or service-role psql). It is idempotent: every insert is
-- guarded so re-running is a no-op.
--
-- WHY gross stays 0 (honest-billing invariant): the line_item has BOTH cpva_bid_micros = 0
-- AND cpc_bid_micros = 0, so close_window computes gross = attention_seconds * 0 = 0 and
-- click_resolve bills 0. The window still opens, dwells, and is counted as a VIEW, but no
-- money is ever booked. The sentinel publisher below is the "anon, never paid" identity that
-- every anonymous install borrows via the lumaline-feed edge function's short-lived JWT.
-- Real per-publisher earnings unlock only with P2 login (post-launch).
--
-- Deterministic UUIDs (mirrored as edge-function secrets LUMALINE_SENTINEL_*):
--   user      5e470000-0000-4000-8000-000000000001
--   publisher 5e470000-0000-4000-8000-0000000000b1
--   device    5e470000-0000-4000-8000-0000000000d1
-- (advertiser a001 / campaign c001 / line_item f001 / creative e001 — all hex-valid)

-- ---------------------------------------------------------------------------
-- Sentinel auth.users row (publishers.auth_user_id is NOT NULL -> must exist).
-- Inserted directly (service-role / SQL only). No password sign-in is ever used; the
-- edge function mints a short-lived device JWT for this identity. Column set mirrors the
-- dev seed so GoTrue's NOT NULL token columns are satisfied.
-- ---------------------------------------------------------------------------
insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change_token_new, email_change)
values
  ('00000000-0000-0000-0000-000000000000', '5e470000-0000-4000-8000-000000000001',
   'authenticated', 'authenticated', 'sentinel@lumaline.local',
   '', now(),
   '{"provider":"email","providers":["email"]}', '{"lumaline_sentinel":true}', now(), now(),
   '', '', '', '')
on conflict (id) do nothing;

-- ---------------------------------------------------------------------------
-- Sentinel publisher + device. "anon sentinel, never paid."
-- ---------------------------------------------------------------------------
insert into public.publishers (id, auth_user_id, handle, country, status) values
  ('5e470000-0000-4000-8000-0000000000b1', '5e470000-0000-4000-8000-000000000001',
   'lumaline-sentinel', 'US', 'active')
on conflict (id) do nothing;

insert into public.devices (id, publisher_id, label, client_version, attested, revoked_at) values
  ('5e470000-0000-4000-8000-0000000000d1', '5e470000-0000-4000-8000-0000000000b1',
   'anon sentinel (shared, never paid)', '0.1.0', false, null)
on conflict (id) do nothing;

-- ---------------------------------------------------------------------------
-- LumaLine self-promo demand chain. EVERY row is explicitly status='active' (defaults are
-- draft / draft / pending_review, which window_open would skip). cpva + cpc bids are 0 so
-- any view OR click stays gross=0 — never billed.
-- ---------------------------------------------------------------------------
insert into public.advertisers (id, name, status, is_house) values
  ('5e470000-0000-4000-8000-00000000a001', 'LumaLine (self-promo)', 'active', true)
on conflict (id) do update set is_house = true;

insert into public.campaigns (id, advertiser_id, name, status) values
  ('5e470000-0000-4000-8000-00000000c001', '5e470000-0000-4000-8000-00000000a001',
   'LumaLine launch self-promo', 'active')
on conflict (id) do nothing;

insert into public.line_items (id, campaign_id, cpva_bid_micros, cpc_bid_micros, weight,
    status, start_at, end_at) values
  ('5e470000-0000-4000-8000-00000000f001', '5e470000-0000-4000-8000-00000000c001',
   0, 0, 1, 'active', now() - interval '1 hour', null)
on conflict (id) do nothing;

insert into public.creatives (id, line_item_id, line, dest_url, label, status) values
  ('5e470000-0000-4000-8000-00000000e001', '5e470000-0000-4000-8000-00000000f001',
   'LumaLine — honest, signed ads for Claude Code',
   'https://luma-line.lovable.app', 'sponsored', 'active')
on conflict (id) do nothing;
