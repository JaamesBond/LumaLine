-- lumaline security-audit hardening pass-2 (cluster P2: publisher self-click CPC farming).
--
-- Recreates public.click_resolve VERBATIM from 20260627025330_window_rpcs.sql:277-331 except:
--   (SC1) NEW 2nd arg p_clicker_ip_hash — the edge-derived SALTED hash of the CLICKER's trusted IP,
--         computed with the SAME salt (LUMALINE_RL_SALT) + SAME derivation (_shared/client-ip.mjs /
--         clientip.ts) that window_open used to stamp ad_windows.ip_hash. A click whose clicker hash ==
--         the serving window's ip_hash is the SAME machine (the honest single-user terminal case) =>
--         recorded VOID, never billed. Makes self-clicking a served ad unprofitable without harming
--         honest revenue (CPVA untouched; CPC is marginal — OSC-8 clicks only work in IDE terminals, #26356).
--   (grant) service_role ONLY (drop the anon + authenticated grant). The shipped client NEVER calls
--         click_resolve; only the `click` edge fn (service_role) does, and it ALWAYS derives the trusted
--         clicker IP. This closes the direct /rest/v1/rpc/click_resolve self-click path and realizes the
--         intent documented in 20260627040000 ("re-grant the MINIMAL role — prefer service_role").
-- Unchanged: token->hash lookup, dest resolution from the booked creative, http(s) guard, 600s TTL,
-- click_token_hash UNIQUE dedup, and "dest always returned so the user still lands".
-- DEPENDS ON: 20260722120000 (ad_windows.ip_hash populated by window_open).

drop function if exists public.click_resolve(text);

create or replace function public.click_resolve(
  p_token           text,
  p_clicker_ip_hash text default null   -- SC1: edge-derived salted hash of the clicker's trusted IP
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash      text := encode(extensions.digest(p_token, 'sha256'), 'hex');
  w           public.ad_windows;
  v_dest      text;
  v_cpc       bigint := 0;
  v_new       boolean := false;
  v_billable  boolean;
  v_selfclick boolean := false;
  v_state     public.click_state;
begin
  select * into w from public.ad_windows where click_token_hash = v_hash;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'unknown window');
  end if;
  if w.creative_id is null then
    return jsonb_build_object('ok', false, 'reason', 'no creative');
  end if;
  select dest_url into v_dest from public.creatives where id = w.creative_id;
  if v_dest is null then
    return jsonb_build_object('ok', false, 'reason', 'no dest');
  end if;
  if v_dest !~* '^https?://' then   -- dest is admin-booked, but enforce http(s) anyway
    return jsonb_build_object('ok', false, 'reason', 'unsafe dest');
  end if;

  -- SC1: SAME-MACHINE SELF-CLICK => VOID. When BOTH the serving window and this click carry a salted
  -- IP hash (salt configured) and they MATCH, the clicker is the serving machine — treat as an owner
  -- self-view and never bill. Honest single-user terminals ARE same-IP, so this IS the honest model.
  -- Inert when either hash is null (no salt) => never a false void.
  v_selfclick := p_clicker_ip_hash is not null and w.ip_hash is not null
                 and p_clicker_ip_hash = w.ip_hash;

  -- A click is billable ONLY if it is NOT a same-machine self-click, bound to a window that earned (or
  -- can still earn) a credited impression, and within the click TTL. A window that never honestly
  -- dwelled yields a VOID click: the user is still redirected, but nothing is billed. close_window
  -- voids clicks for windows that fail to credit; the parent impression must independently CLEAR
  -- (subject to scan_ivt) before clear_events clears the click.
  v_billable := (not v_selfclick)
                and w.state in ('open', 'credited')
                and (extract(epoch from (now() - w.started_at)) <= 600);   -- 10 min TTL
  v_state := case when v_billable then 'provisional'::public.click_state
                  else 'void'::public.click_state end;
  select cpc_bid_micros into v_cpc from public.line_items where id = w.line_item_id;

  insert into public.clicks(window_id, publisher_id, line_item_id, creative_id, click_token_hash, gross_micros, state)
    values (w.window_id, w.publisher_id, w.line_item_id, w.creative_id, v_hash,
            case when v_billable then coalesce(v_cpc, 0) else 0 end, v_state)
    on conflict (click_token_hash) do nothing;
  v_new := found;   -- false on dup -> still redirect (never break the click), just don't re-bill

  -- dest ALWAYS returned (user still lands on a self/void/deduped click — never break the link).
  return jsonb_build_object('ok', true, 'dest', v_dest,
                            'billed', v_billable and v_new, 'deduped', not v_new,
                            'self', v_selfclick);
end;
$$;

-- (grant) service_role ONLY — the click edge fn is the sole caller and always derives the trusted
-- clicker IP; drop the anon + authenticated grant to kill direct-RPC self-clicks.
revoke all on function public.click_resolve(text, text) from public, anon, authenticated;
grant  execute on function public.click_resolve(text, text) to service_role;

comment on function public.click_resolve(text, text) is
  'Click redirect resolver + CPC billability gate. dest resolved ONLY from the booked creative (never '
  'the client); http(s)-guarded; deduped durably on clicks.click_token_hash. P2 (SC1): a click whose '
  'edge-derived salted clicker IP hash equals the serving window''s ad_windows.ip_hash is a same-machine '
  'owner self-view => recorded VOID, never billed (honest single-user terminal model; inert when no salt). '
  'service_role ONLY — the click edge fn is the sole caller; anon + authenticated revoked.';

-- Migration-tail assertion — neither anon NOR authenticated retains EXECUTE on the CPC-booking RPC.
do $$
begin
  if has_function_privilege('anon',          'public.click_resolve(text, text)', 'EXECUTE')
  or has_function_privilege('authenticated', 'public.click_resolve(text, text)', 'EXECUTE') then
    raise exception 'anon/authenticated retains EXECUTE on public.click_resolve — REVOKE missing';
  end if;
end $$;
