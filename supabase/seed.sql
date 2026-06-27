-- lumaline Phase 1 dev seed. Deterministic UUIDs so contract/adversarial tests can
-- reference rows directly. Loaded by `supabase db reset`. NOT used in production.

-- Two developer identities (publisher A is the actor; publisher B exists to prove RLS
-- cross-tenant isolation). auth.users inserted directly (service-role / SQL seed only).
insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, recovery_token, email_change_token_new, email_change)
values
  ('00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111',
   'authenticated', 'authenticated', 'dev-a@lumaline.local',
   extensions.crypt('devpassword', extensions.gen_salt('bf')), now(),
   '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', ''),
  ('00000000-0000-0000-0000-000000000000', '22222222-2222-2222-2222-222222222222',
   'authenticated', 'authenticated', 'dev-b@lumaline.local',
   extensions.crypt('devpassword', extensions.gen_salt('bf')), now(),
   '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');

insert into public.publishers (id, auth_user_id, handle, country, status) values
  ('a1a1a1a1-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'dev-a', 'US', 'active'),
  ('b1b1b1b1-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222', 'dev-b', 'US', 'active');

insert into public.devices (id, publisher_id, label, client_version, attested) values
  ('d1d1d1d1-0000-0000-0000-000000000001', 'a1a1a1a1-0000-0000-0000-000000000001', 'dev-a laptop', '0.1.0', true),
  ('d2d2d2d2-0000-0000-0000-000000000002', 'b1b1b1b1-0000-0000-0000-000000000002', 'dev-b laptop', '0.1.0', true);

-- One booked, active demand chain so window_open fills (not house).
insert into public.advertisers (id, name, status) values
  ('ad000000-0000-0000-0000-000000000001', 'Matei (demo advertiser)', 'active');
insert into public.campaigns (id, advertiser_id, name, status) values
  ('ca000000-0000-0000-0000-000000000001', 'ad000000-0000-0000-0000-000000000001', 'Matei brand', 'active');
insert into public.line_items (id, campaign_id, cpva_bid_micros, cpc_bid_micros, weight,
    budget_total_micros, budget_daily_micros, status, start_at, end_at) values
  ('11000000-0000-0000-0000-000000000001', 'ca000000-0000-0000-0000-000000000001',
   2000, 50000, 1, 100000000, 10000000, 'active', now() - interval '1 day', now() + interval '30 days');
insert into public.creatives (id, line_item_id, line, dest_url, label, status) values
  ('c0000000-0000-0000-0000-000000000001', '11000000-0000-0000-0000-000000000001',
   'Matei is the best', 'https://example.com/matei', 'sponsored', 'active');
