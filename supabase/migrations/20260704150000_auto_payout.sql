-- supabase/migrations/20260704150000_auto_payout.sql
-- M5-T4 auto-payout: a connect-nudge dedup column, publisher-contact + nudge-candidate RPCs, and a
-- pg_cron target (twin of app.run_monitor) that POSTs the payout batch with the Vault cron secret.
-- All money RPCs are SECURITY DEFINER + service_role-only. run_payout degrades to NOTICE+no-op when
-- Vault/pg_net/secret is absent, so a fresh `supabase db reset` applies and runs cleanly.
set local lock_timeout = '2s';
set local statement_timeout = '15s';

alter table public.publishers add column if not exists connect_nudge_at timestamptz;

-- Contact for a publisher (email + handle) from auth.users. SECDEF: crosses into the auth schema.
create or replace function app.publisher_contact(p_publisher_id uuid)
returns table(email text, handle text)
language sql security definer set search_path = '' as $$
  select u.email::text, p.handle
    from public.publishers p
    join auth.users u on u.id = p.auth_user_id
   where p.id = p_publisher_id
   limit 1;
$$;
revoke all on function app.publisher_contact(uuid) from public, anon, authenticated;
grant execute on function app.publisher_contact(uuid) to service_role;

-- Publishers who have earned >= the minimum but have NOT onboarded a bank, not nudged in ~a week.
create or replace function app.payout_nudge_candidates(p_min_micros bigint, p_hold interval default interval '7 days')
returns table(publisher_id uuid, email text, handle text, payable_micros bigint)
language plpgsql security definer set search_path = '' as $$
begin
  return query
    select p.id, u.email::text, p.handle, app.publisher_payable_micros(p.id, p_hold)
      from public.publishers p
      join auth.users u on u.id = p.auth_user_id
     where p.stripe_account_id is null
       and (p.connect_nudge_at is null or p.connect_nudge_at < now() - interval '6 days')
       and app.publisher_payable_micros(p.id, p_hold) >= p_min_micros;
end;
$$;
revoke all on function app.payout_nudge_candidates(bigint, interval) from public, anon, authenticated;
grant execute on function app.payout_nudge_candidates(bigint, interval) to service_role;

create or replace function app.mark_connect_nudged(p_ids uuid[])
returns void language sql security definer set search_path = '' as $$
  update public.publishers set connect_nudge_at = now() where id = any(p_ids);
$$;
revoke all on function app.mark_connect_nudged(uuid[]) from public, anon, authenticated;
grant execute on function app.mark_connect_nudged(uuid[]) to service_role;

-- pg_cron target. Reads 'lumaline_cron_secret' from Vault and POSTs /payout/batch with the
-- x-lumaline-cron-secret header via pg_net. Vault/secret/pg_net absent -> NOTICE + no-op.
create or replace function app.run_payout()
returns void language plpgsql security definer set search_path = '' as $$
declare v_secret text; v_request_id bigint;
begin
  if to_regclass('vault.decrypted_secrets') is null then
    raise notice 'run_payout: vault.decrypted_secrets missing (fresh local stack?) — no-op'; return;
  end if;
  begin
    execute 'select decrypted_secret from vault.decrypted_secrets where name = $1 limit 1'
       into v_secret using 'lumaline_cron_secret';
  exception when others then raise notice 'run_payout: cannot read vault (%) — no-op', sqlerrm; return; end;
  if v_secret is null or v_secret = '' then
    raise notice 'run_payout: vault secret lumaline_cron_secret absent — no-op'; return;
  end if;
  begin
    execute $q$
      select net.http_post(
        url     := 'https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/stripe-connect/payout/batch',
        body    := '{}'::jsonb,
        headers := jsonb_build_object('Content-Type','application/json','x-lumaline-cron-secret',$1),
        timeout_milliseconds := 120000)
    $q$ into v_request_id using v_secret;
  exception when others then raise notice 'run_payout: net.http_post unavailable/failed (%) — no-op', sqlerrm; return; end;
end;
$$;
revoke all on function app.run_payout() from public, anon, authenticated;
comment on function app.run_payout is
  'pg_cron target: POST the payout batch with the Vault cron secret. Vault/secret/pg_net absent -> NOTICE + no-op. Controller cron.schedule''s this weekly at deploy.';
