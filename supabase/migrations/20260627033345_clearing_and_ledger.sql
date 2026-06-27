-- lumaline Phase 4 — revenue: double-entry accrual, clearing, IVT scan + clawback.
--
-- Design: impressions/clicks are recorded provisional by the Phase 1 hot path (no ledger
-- writes there). The LEDGER is booked at CLEARING time — provisional -> cleared after the
-- 72h clawback window — so a publisher_earnings leg only ever exists for an event that
-- (a) aged past the clawback window and (b) was not IVT-flagged. CPC additionally requires
-- a CLEARED parent impression for its window, so the "open-then-click, never dwell" path
-- can never clear/pay. Every accrual is a balanced 3-leg group (the deferred
-- ledger_group_balances trigger enforces SUM=0). Split is 60/40 publisher-favored, exact
-- in integer micro-USD (publisher = round(0.6G), platform = G - publisher).
--
-- CONCURRENCY (hardened after the Phase 4 trust gate proved a double-book): clear_events
-- claims each provisional row with FOR UPDATE SKIP LOCKED and transitions state with a
-- guarded UPDATE (... where state='provisional'), accruing ONLY when this txn actually won
-- the transition. A partial UNIQUE index on (source_type, source_id, account) for accrual
-- events is the durable backstop: a duplicate accrual fails hard instead of double-paying.
--
-- IVT canonicalization: a window is "flagged" if EITHER a risk_flag carries its window_id
-- OR a risk_flag's impression_id points at an impression on that window. Both clearing
-- loops use the SAME window-canonical predicate, so a flag in either column protects both
-- the impression and its sibling click (the gate showed an impression_id-only flag used to
-- let the click pay, and a window-only flag used to let the impression pay).

-- ---------------------------------------------------------------------------
-- Durable double-book backstop. Each accrual books exactly one (advertiser_billing,
-- publisher_earnings, platform_revenue) leg per source, so (source_type, source_id, account)
-- is unique within accrual events. A second accrual group for the same event collides ->
-- the clearing txn aborts loudly instead of silently paying twice. (Mirrors the hot path's
-- impressions.window_id / clicks.click_token_hash UNIQUE single-credit guarantee.)
-- ---------------------------------------------------------------------------
create unique index if not exists ledger_entries_accrual_unique
  on public.ledger_entries (source_type, source_id, account)
  where event_type in ('cpva_accrual', 'cpc_accrual');

-- ---------------------------------------------------------------------------
-- app.accrue — book one balanced double-entry group for gross G. Returns group id,
-- or NULL when there is nothing to book (gross <= 0: house / view-only / zero bid).
-- Callers that pre-filter gross>0 MUST treat a NULL as a bug (see clear_events).
-- ---------------------------------------------------------------------------
create or replace function app.accrue(
  p_event_type text, p_source_type text, p_source_id uuid,
  p_publisher_id uuid, p_gross bigint, p_state ledger_state default 'provisional')
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  g      uuid := gen_random_uuid();
  v_pub  bigint;
  v_plat bigint;
begin
  if p_gross is null or p_gross <= 0 then
    return null;   -- nothing to book (house / view-only / zero bid)
  end if;
  v_pub  := round(p_gross * 0.6)::bigint;   -- 60% publisher-favored
  v_plat := p_gross - v_pub;                -- remainder -> platform (keeps the group exactly 0)
  insert into public.ledger_entries(entry_group_id, event_type, account, amount_micros, state, source_type, source_id, publisher_id) values
    (g, p_event_type, 'advertiser_billing',  p_gross, p_state, p_source_type, p_source_id, null),
    (g, p_event_type, 'publisher_earnings', -v_pub,   p_state, p_source_type, p_source_id, p_publisher_id),
    (g, p_event_type, 'platform_revenue',   -v_plat,  p_state, p_source_type, p_source_id, null);
  return g;
end;
$$;
revoke execute on function app.accrue(text, text, uuid, uuid, bigint, ledger_state) from public;
grant execute on function app.accrue(text, text, uuid, uuid, bigint, ledger_state) to service_role;

-- ---------------------------------------------------------------------------
-- scan_ivt — v1 invalid-traffic heuristic. Flags provisional impressions from a
-- publisher whose short-window count exceeds what an honest >=5s-dwell cadence allows.
-- The rate count considers only billable (provisional/cleared) impressions so void/house
-- rows don't inflate it. The cron schedules this with a lookback >= its cadence so no
-- impression escapes the rate scan before it ages into clearing. (Deliberately simple +
-- bounded; richer statistical clearing is future work.)
-- ---------------------------------------------------------------------------
create or replace function public.scan_ivt(p_window interval default interval '60 seconds', p_max integer default 20)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_flagged integer := 0;
  r record;
begin
  for r in
    select i.id, i.window_id
    from public.impressions i
    where i.state = 'provisional'
      and i.created_at > now() - p_window
      and not exists (select 1 from public.risk_flags rf where rf.impression_id = i.id)
      and (select count(*) from public.impressions i2
             where i2.publisher_id = i.publisher_id
               and i2.created_at > now() - p_window
               and i2.state in ('provisional', 'cleared')) > p_max
  loop
    insert into public.risk_flags(impression_id, window_id, reason) values (r.id, r.window_id, 'ivt:rate');
    v_flagged := v_flagged + 1;
  end loop;
  return v_flagged;
end;
$$;
revoke execute on function public.scan_ivt(interval, integer) from public;
grant execute on function public.scan_ivt(interval, integer) to service_role;

-- ---------------------------------------------------------------------------
-- clear_events — promote provisional -> cleared past the clawback window, skipping
-- IVT-flagged events, booking the ledger group at clearing. Concurrency-safe: each row is
-- claimed with FOR UPDATE SKIP LOCKED and a guarded state transition, so overlapping runs
-- (hourly cron vs. a manual/retried run) can never accrue the same event twice. CPC
-- requires a CLEARED parent impression for the window. Returns counts.
-- ---------------------------------------------------------------------------
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
        where rf.window_id = i.window_id or fi.window_id = i.window_id
      )
    for update of i skip locked
  loop
    -- guarded transition: only the txn that actually flips provisional->cleared accrues.
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
        where rf.window_id = c.window_id or fi.window_id = c.window_id
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
revoke execute on function public.clear_events(interval) from public;
grant execute on function public.clear_events(interval) to service_role;

-- ---------------------------------------------------------------------------
-- clawback — reverse fraud on a WINDOW. Given any source (impression or click) on the
-- window, reverse EVERY ledger group booked for that window (both the CPVA impression and
-- the CPC click — fraud is the pair, so reversing one source must not leave the sibling
-- paid), mark every billable source clawed_back, and record one window-keyed flag.
-- Marking legs 'reversed' keeps each group summing to 0 (amounts unchanged) and removes
-- them from cleared balance (v_publisher_balance counts only 'cleared'). Validates input
-- and raises on an unknown source_type / missing row so a typo can't look like success.
-- ---------------------------------------------------------------------------
create or replace function public.clawback(p_source_type text, p_source_id uuid, p_reason text default 'ivt')
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_reversed integer;
  v_imp_cb   integer;
  v_clk_cb   integer;
  v_win      uuid;
begin
  if p_source_type not in ('impression', 'click') then
    raise exception 'clawback: unknown source_type %', p_source_type;
  end if;

  if p_source_type = 'impression' then
    select window_id into v_win from public.impressions where id = p_source_id;
  else
    select window_id into v_win from public.clicks where id = p_source_id;
  end if;
  if v_win is null then
    raise exception 'clawback: % % not found', p_source_type, p_source_id;
  end if;

  -- reverse every ledger group for any impression or click on this window
  update public.ledger_entries le set state = 'reversed'
   where le.state <> 'reversed'
     and (
       (le.source_type = 'impression'
          and le.source_id in (select id from public.impressions where window_id = v_win))
       or (le.source_type = 'click'
          and le.source_id in (select id from public.clicks where window_id = v_win))
     );
  get diagnostics v_reversed = row_count;

  -- mark all billable sources on the window clawed_back (idempotent: only provisional/cleared)
  update public.impressions set state = 'clawed_back'
   where window_id = v_win and state in ('provisional', 'cleared');
  get diagnostics v_imp_cb = row_count;
  update public.clicks set state = 'clawed_back'
   where window_id = v_win and state in ('provisional', 'cleared');
  get diagnostics v_clk_cb = row_count;

  -- one window-keyed flag per reason (idempotent — never piles duplicates)
  insert into public.risk_flags (window_id, reason)
  select v_win, p_reason
  where not exists (
    select 1 from public.risk_flags where window_id = v_win and reason = p_reason
  );

  return jsonb_build_object(
    'window_id', v_win,
    'entries_reversed', v_reversed,
    'impressions_clawed_back', v_imp_cb,
    'clicks_clawed_back', v_clk_cb
  );
end;
$$;
revoke execute on function public.clawback(text, uuid, text) from public;
grant execute on function public.clawback(text, uuid, text) to service_role;

-- ---------------------------------------------------------------------------
-- sweep_stale_windows — the Phase 4 cron promised by the window RPCs / ad_windows comment.
-- Abandon 'open' windows left well past any honest dwell and void their still-provisional
-- clicks (a click whose window never closed can never legitimately clear). No money moves
-- (clear_events already refuses an orphan click — no cleared parent impression); this is
-- housekeeping so transient state cannot accumulate forever.
-- ---------------------------------------------------------------------------
create or replace function public.sweep_stale_windows(p_older interval default interval '10 minutes')
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_win integer := 0;
  v_clk integer := 0;
begin
  update public.ad_windows set state = 'abandoned'
   where state = 'open' and started_at < now() - p_older;
  get diagnostics v_win = row_count;

  update public.clicks set state = 'void', gross_micros = 0
   where state = 'provisional'
     and window_id in (select window_id from public.ad_windows where state = 'abandoned');
  get diagnostics v_clk = row_count;

  return jsonb_build_object('windows_abandoned', v_win, 'clicks_voided', v_clk);
end;
$$;
revoke execute on function public.sweep_stale_windows(interval) from public;
grant execute on function public.sweep_stale_windows(interval) to service_role;

-- ---------------------------------------------------------------------------
-- Schedule via pg_cron when available. Local Supabase may or may not load pg_cron; guard
-- so `supabase db reset` never fails when it is absent — but DON'T treat a real scheduling
-- failure as success in prod: warn (visible at default log level, unlike notice) and, when
-- pg_cron IS present, assert the jobs actually registered. scan_ivt's lookback (6m) must
-- exceed its cadence (5m) so no impression escapes the rate scan before clearing.
-- ---------------------------------------------------------------------------
do $$
begin
  create extension if not exists pg_cron;
exception when others then
  raise warning 'pg_cron unavailable (local?); schedule clear_events()/scan_ivt()/sweep_stale_windows() externally in prod: %', sqlerrm;
end $$;

do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule('lumaline-clear-events',  '0 * * * *',   'select public.clear_events()');
    perform cron.schedule('lumaline-scan-ivt',      '*/5 * * * *', 'select public.scan_ivt(interval ''6 minutes'', 120)');
    perform cron.schedule('lumaline-sweep-windows', '*/10 * * * *', 'select public.sweep_stale_windows()');
    if (select count(*) from cron.job
          where jobname in ('lumaline-clear-events', 'lumaline-scan-ivt', 'lumaline-sweep-windows')) <> 3 then
      raise exception 'lumaline cron jobs failed to register';
    end if;
  else
    raise warning 'pg_cron absent (local?); schedule clear_events()/scan_ivt()/sweep_stale_windows() externally in prod';
  end if;
end $$;
