-- ROLLBACK for migration 20260704120000_refresh_token_grace_window.sql
--
-- NOT in supabase/migrations/ ON PURPOSE — it must never auto-apply. Run it by hand ONLY to revert
-- the grace window during an incident:
--
--   psql "$DB_URL_REMOTE" --single-transaction -v ON_ERROR_STOP=1 \
--     -f docs/ops/reverts/20260704120000_revert_refresh_token_grace_window.sql
--
-- It restores device_refresh + device_revoke to their pre-grace single-arm bodies (from
-- 20260629010000). It deliberately LEAVES the two nullable columns (prev_refresh_token_hash,
-- prev_rotated_at) and the partial unique indexes in place — the restored single-arm function simply
-- ignores the columns, and the indexes are additive/harmless. After reverting, an in-flight crash
-- mid-rotation reverts to the OLD failure mode (publisher drops to €0 until a manual `lumaline login`);
-- that is the known bug this migration fixes, so only revert if the grace window itself is causing harm.

set local lock_timeout = '2s';
set local statement_timeout = '15s';

create or replace function public.device_refresh(
  p_refresh_token_hash     text,
  p_new_refresh_token_hash text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  d        public.devices;
  v_user   uuid;
  v_handle text;
begin
  if p_refresh_token_hash is null or p_new_refresh_token_hash is null then
    return jsonb_build_object('status', 'invalid');
  end if;
  select * into d from public.devices
   where refresh_token_hash = p_refresh_token_hash and revoked_at is null
   for update;
  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;
  update public.devices set refresh_token_hash = p_new_refresh_token_hash where id = d.id;
  select auth_user_id, handle into v_user, v_handle from public.publishers where id = d.publisher_id;
  return jsonb_build_object(
    'status', 'ok',
    'publisher_id', d.publisher_id,
    'device_id', d.id,
    'auth_user_id', v_user,
    'handle', v_handle);
end;
$$;
revoke execute on function public.device_refresh(text, text) from anon, authenticated, public;
grant  execute on function public.device_refresh(text, text) to service_role;

create or replace function public.device_revoke(p_device_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pub uuid := (select app.current_publisher_id());
  v_hit boolean;
begin
  if v_pub is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;
  update public.devices
     set revoked_at = coalesce(revoked_at, now()), refresh_token_hash = null
   where id = p_device_id and publisher_id = v_pub
  returning true into v_hit;
  return jsonb_build_object('ok', coalesce(v_hit, false));
end;
$$;
revoke execute on function public.device_revoke(uuid) from anon, public;
grant  execute on function public.device_revoke(uuid) to authenticated, service_role;
