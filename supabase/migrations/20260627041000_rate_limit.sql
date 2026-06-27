-- Abuse / cost guard for the anonymous self-promo feed: a per-client fixed-window rate
-- limiter keyed by a SALTED hash of the IP. The edge function computes
-- sha256(LUMALINE_RL_SALT || ip), discards the raw IP immediately, and only the hash + a
-- short-lived minute counter is ever stored here. The salt makes the hash non-reversible
-- (raw IPv4 space is brute-forceable without it), so this honors the data-minimization
-- invariant while still stopping single-source floods of window_open (which is what creates
-- DB rows + edge invocations). gross=0 means a flood costs no money, only resources; this
-- bounds the resource blast radius.

create table if not exists public.rl_buckets (
  ip_hash      text        not null,
  window_start timestamptz not null,
  count        integer     not null default 0,
  primary key (ip_hash, window_start)
);
alter table public.rl_buckets enable row level security;

-- No anon/authenticated table access; the counter is touched ONLY through the SECURITY
-- DEFINER rl_hit() below. service_role retains full access for ops.
drop policy if exists rl_buckets_service on public.rl_buckets;
create policy rl_buckets_service on public.rl_buckets for all to service_role using (true) with check (true);

-- Atomic "hit": increment this client's counter for the current minute and report whether it
-- is still within budget. Fail-OPEN on a missing hash (no client signal): availability over a
-- perfect block, since nothing is ever billed for the self-promo feed anyway.
create or replace function public.rl_hit(p_ip_hash text, p_max integer)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
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

-- Least privilege (the schema default-priv would otherwise expose this to anon — see
-- 20260627040000): only the edge fn's authenticated sentinel JWT + service_role may call it.
revoke execute on function public.rl_hit(text, integer) from anon, public;
grant  execute on function public.rl_hit(text, integer) to authenticated, service_role;

-- Prune: drop counters older than 5 minutes every 5 minutes (only the current minute matters).
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule(
      'lumaline-rl-prune', '*/5 * * * *',
      $cron$ delete from public.rl_buckets where window_start < now() - interval '5 minutes' $cron$
    );
  else
    raise warning 'pg_cron absent (local?); prune public.rl_buckets externally in prod';
  end if;
end $$;
