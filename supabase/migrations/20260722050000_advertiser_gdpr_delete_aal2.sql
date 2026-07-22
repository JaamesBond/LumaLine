-- lumaline security-audit (Cluster D / C1) — advertiser admin GDPR erase must be aal2, matching
-- gdpr_delete_publisher.
--
-- advertiser_gdpr_delete gated on app.is_admin() (aal1, membership-only) while the publisher mirror
-- was re-hardened to app.is_money_admin() (aal2 + money_admins) in 20260716120000. Re-gate the
-- advertiser admin-support path to is_money_admin() and add the append-only audit write.
-- advertiser_gdpr_self_delete (no arg, self-scoped) stays aal1 — it cannot target another org.
--
-- DEPLOY-ORDERING HAZARD (same as 20260716120000): is_money_admin() needs an aal2 (MFA) session in the
-- money_admins tier. Before applying, confirm at least one money_admin can satisfy aal2, or the admin
-- GDPR-erase support path is locked out. Self-serve erase is unaffected.
create or replace function public.advertiser_gdpr_delete(p_advertiser_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  -- C1 hardening: app.is_admin() -> app.is_money_admin() (aal2 + money tier), mirror gdpr_delete_publisher.
  if not (select app.is_money_admin()) then
    raise exception 'unauthorized' using errcode = '28000';
  end if;
  perform app.log_admin_action('advertiser_gdpr_delete', 'advertiser', p_advertiser_id, '{}'::jsonb);
  return app.advertiser_gdpr_erase(p_advertiser_id);
end;
$$;
revoke all on function public.advertiser_gdpr_delete(uuid) from public, anon;
grant  execute on function public.advertiser_gdpr_delete(uuid) to authenticated;

comment on function public.advertiser_gdpr_delete is
  'Money-admin-only (aal2 + app.money_admins) GDPR erasure (advertiser support path). C1 hardening '
  're-gated it from app.is_admin() to app.is_money_admin() and added an append-only app.log_admin_action() '
  'write; delegates to app.advertiser_gdpr_erase. Idempotent; refuses while money is in flight. '
  'advertiser_gdpr_self_delete (self-scoped) stays aal1.';

-- Migration-tail assertion — anon holds NO EXECUTE (authenticated keeps it; the in-body gate is the check).
do $$
begin
  if has_function_privilege('anon', 'public.advertiser_gdpr_delete(uuid)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.advertiser_gdpr_delete — REVOKE ALL FROM PUBLIC, anon missing';
  end if;
end $$;
