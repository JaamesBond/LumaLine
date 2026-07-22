-- lumaline security-audit (Cluster E / C2) — rl_hit defense-in-depth: adopt the codebase empty-string
-- search_path.
-- Body is byte-identical to 20260627041000_rate_limit.sql L26-51 (already fully-qualified); only
-- `set search_path = public, pg_temp` becomes `set search_path = ''`. date_trunc/length/greatest/now
-- are pg_catalog (always searched even with search_path=''), so behavior is identical — this just
-- removes the mutable public/pg_temp from the SECDEF resolution path.
create or replace function public.rl_hit(p_ip_hash text, p_max integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_ws    timestamptz := date_trunc('minute', now());
  v_count integer;
begin
  if p_ip_hash is null or length(p_ip_hash) = 0 then
    return true;
  end if;
  insert into public.rl_buckets (ip_hash, window_start, count)
       values (p_ip_hash, v_ws, 1)
  on conflict (ip_hash, window_start)
       do update set count = public.rl_buckets.count + 1
    returning count into v_count;
  return v_count <= greatest(p_max, 1);
end;
$$;
revoke execute on function public.rl_hit(text, integer) from anon, public;
grant  execute on function public.rl_hit(text, integer) to authenticated, service_role;

-- Migration-tail assertion — anon holds NO EXECUTE (authenticated keeps it; fail-open on empty hash).
do $$
begin
  if has_function_privilege('anon', 'public.rl_hit(text, integer)', 'EXECUTE') then
    raise exception 'anon retains EXECUTE on public.rl_hit — REVOKE ... FROM anon missing';
  end if;
end $$;
