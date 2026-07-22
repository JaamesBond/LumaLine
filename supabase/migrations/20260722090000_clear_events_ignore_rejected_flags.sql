-- lumaline security-audit (Cluster E / A8) — a REJECTED clawback review must release its window for
-- clearing.
--
-- scan_ivt() writes risk_flags + a pending clawback_reviews row; clear_events() excludes any window
-- carrying ANY risk_flag. reject_clawback() only flips the review to 'rejected' and leaves the
-- risk_flag in place, so a false-positive that an admin rejected was excluded from clearing FOREVER
-- (impression never cleared -> publisher never paid, advertiser never charged). Fix: a flag whose
-- review status = 'rejected' no longer blocks clearing. Pending/approved flags still block (approved
-- => clawback() already marked the sources clawed_back, so they are not provisional).
-- This is a CREATE OR REPLACE of the CURRENT clear_events (20260627033345_clearing_and_ledger.sql
-- L113-176); every other line is verbatim, incl. the loud-fail app.accrue NULL contract.
create or replace function public.clear_events(p_older interval default interval '72 hours')
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r     record;
  v_grp uuid;
  v_imp integer := 0;
  v_clk integer := 0;
begin
  for r in
    select i.id, i.publisher_id, i.gross_micros, i.window_id
    from public.impressions i
    where i.state = 'provisional'
      and i.gross_micros > 0
      and i.created_at < now() - p_older
      and not exists (
        select 1 from public.risk_flags rf
        left join public.impressions fi on fi.id = rf.impression_id
        where (rf.window_id = i.window_id or fi.window_id = i.window_id)
          -- A8: a REJECTED review (admin ruled false-positive) releases the flag's window.
          and not exists (
            select 1 from public.clawback_reviews cr
            where cr.risk_flag_id = rf.id and cr.status = 'rejected'
          )
      )
    for update of i skip locked
  loop
    update public.impressions set state = 'cleared' where id = r.id and state = 'provisional';
    if not found then continue; end if;
    v_grp := app.accrue('cpva_accrual', 'impression', r.id, r.publisher_id, r.gross_micros, 'cleared');
    if v_grp is null then
      raise exception 'clear_events: accrue booked nothing for impression % (gross=%)', r.id, r.gross_micros;
    end if;
    v_imp := v_imp + 1;
  end loop;

  for r in
    select c.id, c.publisher_id, c.gross_micros, c.window_id
    from public.clicks c
    where c.state = 'provisional'
      and c.gross_micros > 0
      and c.created_at < now() - p_older
      and exists (select 1 from public.impressions i
                   where i.window_id = c.window_id and i.state = 'cleared')
      and not exists (
        select 1 from public.risk_flags rf
        left join public.impressions fi on fi.id = rf.impression_id
        where (rf.window_id = c.window_id or fi.window_id = c.window_id)
          -- A8: a REJECTED review releases the flag's window for the sibling click too.
          and not exists (
            select 1 from public.clawback_reviews cr
            where cr.risk_flag_id = rf.id and cr.status = 'rejected'
          )
      )
    for update of c skip locked
  loop
    update public.clicks set state = 'cleared' where id = r.id and state = 'provisional';
    if not found then continue; end if;
    v_grp := app.accrue('cpc_accrual', 'click', r.id, r.publisher_id, r.gross_micros, 'cleared');
    if v_grp is null then
      raise exception 'clear_events: accrue booked nothing for click % (gross=%)', r.id, r.gross_micros;
    end if;
    v_clk := v_clk + 1;
  end loop;

  return jsonb_build_object('impressions_cleared', v_imp, 'clicks_cleared', v_clk);
end;
$$;
-- Re-assert least privilege (matches 20260627040000_harden_function_grants.sql final ACL).
revoke execute on function public.clear_events(interval) from public, anon, authenticated;
grant  execute on function public.clear_events(interval) to service_role;

-- Migration-tail assertion — anon holds NO EXECUTE on the clearing money RPC.
do $$
begin
  if has_function_privilege('anon', 'public.clear_events(interval)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.clear_events — REVOKE ... FROM anon missing';
  end if;
end $$;
