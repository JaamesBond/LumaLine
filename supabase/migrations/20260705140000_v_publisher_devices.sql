-- lumaline M7 — v_publisher_devices: a device list SAFE to expose to the web portal.
--
-- public.devices carries `refresh_token_hash` (a bearer-equivalent secret). Its SELECT grant
-- to `authenticated` is ROW-scoped by RLS (devices_select_own) but NOT column-scoped, so a
-- `select *` — or any select that names the column — would return the owner's own hash to the
-- browser. The portal's useDevices hook already selects an explicit safe column list, but that
-- is client discipline; this view makes the exclusion DB-ENFORCED (defense-in-depth).
--
-- security_invoker = on → the querying user's RLS on the base `devices` table applies, so a
-- publisher sees only their own devices through the view (same as v_publisher_balance).
CREATE VIEW public.v_publisher_devices
WITH (security_invoker = on) AS
SELECT id, publisher_id, label, client_version, attested, revoked_at, created_at
FROM public.devices;

COMMENT ON VIEW public.v_publisher_devices IS
  'Portal-safe device list (omits refresh_token_hash). RLS-scoped to the publisher''s own devices via the base table policy (security_invoker).';

GRANT SELECT ON public.v_publisher_devices TO authenticated, service_role;
