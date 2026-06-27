-- lumaline Phase 1 — window protocol RPCs (the trust-critical hot path).
--
-- Ports the gate-hardened in-memory logic (src/server/windows.mjs, clicks.mjs) to
-- SECURITY DEFINER SQL. The browser/CLI reaches these as PostgREST RPCs with a device
-- JWT (claims: sub, publisher_id, device_id); the click redirect calls click_resolve as
-- anon. Trust properties enforced here:
--   * crediting is idempotent and durable — `impressions.window_id` is UNIQUE and the
--     credit path locks the window row and only fires while state='open', so a replayed
--     close cannot double-bill (even across processes/restarts — the gap the in-memory
--     v1 could only paper over);
--   * a window credits only after the FULL server-measured dwell, with >=minBeats honest
--     heartbeats spaced >=500ms apart (anti-batch), each link of an HMAC hash-chain keyed
--     by the per-window challenge;
--   * click dedupe is durable via the UNIQUE click_token_hash; the redirect destination
--     comes from the booked creative (server-side), never from the client — so there is no
--     open-redirect surface and the click token is an opaque, single-use secret (only its
--     hash is stored).
--
-- HONEST LIMIT (unchanged from v1, by design): the activity bucket is client-asserted.
-- The data-minimization invariant forbids shipping raw cost/token counts, so the server
-- cannot independently prove activity; the economic bound is anti-batch + full-dwell +
-- (Phase 2) auth/rate-limits + (Phase 4) statistical IVT clearing & clawback. This matches
-- the spec's honest threat model: it prices and bounds fraud, it does not prove a human looked.
--
-- Tunables (kept in sync with src/config.mjs / the v1 store defaults):
--   dwell_ms=5000, hb_interval_ms=1000, min_beats=3, min_spacing=500ms.

-- ---------------------------------------------------------------------------
-- claim + bucket helpers (private app schema)
-- ---------------------------------------------------------------------------
create or replace function app.jwt_claim(claim text)
returns text
language sql
stable
set search_path = ''
as $$
  select nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> claim;
$$;
revoke execute on function app.jwt_claim(text) from public;
grant execute on function app.jwt_claim(text) to authenticated, service_role, anon;

create or replace function app.activity_rank(bucket text)
returns integer
language sql
immutable
set search_path = ''
as $$
  select case bucket when 'high' then 3 when 'med' then 2 when 'low' then 1 else 0 end;
$$;
revoke execute on function app.activity_rank(text) from public;
grant execute on function app.activity_rank(text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- window_open(p_activity_snapshot) -> { window_id, challenge, nonce, dwell_ms,
--   hb_interval_ms, click_token, ad:{line,label,has_dest | house} }
-- ---------------------------------------------------------------------------
create or replace function public.window_open(p_activity_snapshot text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pub        uuid := nullif(app.jwt_claim('publisher_id'), '')::uuid;
  v_dev        uuid := nullif(app.jwt_claim('device_id'), '')::uuid;
  v_creative   public.creatives;
  v_window_id  uuid;
  v_challenge  text := encode(extensions.gen_random_bytes(16), 'hex');
  v_nonce      text := encode(extensions.gen_random_bytes(8), 'hex');
  v_token      text := encode(extensions.gen_random_bytes(24), 'hex');
  v_dwell      integer := 5000;
  v_hb         integer := 1000;
begin
  if v_pub is null or v_dev is null then
    raise exception 'unauthenticated' using errcode = '28000';
  end if;
  perform 1 from public.devices d
   where d.id = v_dev and d.publisher_id = v_pub and d.revoked_at is null;
  if not found then
    raise exception 'device revoked or unknown' using errcode = '28000';
  end if;

  -- Phase 1 serving: random active, in-flight creative (full rotation/pacing = Phase 3).
  -- Empty demand => house/no-fill (a window still opens, but is voided at close, never billed).
  select c.* into v_creative
    from public.creatives c
    join public.line_items li on li.id = c.line_item_id
    join public.campaigns  cm on cm.id = li.campaign_id
    join public.advertisers a on a.id = cm.advertiser_id
   where c.status = 'active' and li.status = 'active'
     and cm.status = 'active' and a.status = 'active'
     and (li.start_at is null or li.start_at <= now())
     and (li.end_at   is null or li.end_at   >= now())
   order by random()
   limit 1;

  insert into public.ad_windows(
      publisher_id, device_id, line_item_id, creative_id, challenge, nonce,
      prev_hash, click_token_hash, dwell_ms, hb_interval_ms, state)
    values (
      v_pub, v_dev, v_creative.line_item_id, v_creative.id, v_challenge, v_nonce,
      null, encode(extensions.digest(v_token, 'sha256'), 'hex'), v_dwell, v_hb, 'open')
    returning window_id into v_window_id;

  return jsonb_build_object(
    'window_id', v_window_id,
    'challenge', v_challenge,
    'nonce', v_nonce,
    'dwell_ms', v_dwell,
    'hb_interval_ms', v_hb,
    'click_token', v_token,
    'ad', case when v_creative.id is not null
      then jsonb_build_object('line', v_creative.line, 'label', v_creative.label,
                              'has_dest', v_creative.dest_url is not null)
      else jsonb_build_object('house', true) end
  );
end;
$$;
revoke execute on function public.window_open(text) from public;
grant execute on function public.window_open(text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- window_beat(window_id, seq, hmac, activity_delta) -> { ok:true }; raises on invalid
-- ---------------------------------------------------------------------------
create or replace function public.window_beat(
  p_window_id uuid, p_seq integer, p_hmac text, p_activity_delta text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pub      uuid := nullif(app.jwt_claim('publisher_id'), '')::uuid;
  w          public.ad_windows;
  v_prev     text;
  v_expected text;
  v_spacing  numeric;
begin
  select * into w from public.ad_windows where window_id = p_window_id for update;
  if not found or w.state <> 'open' then
    raise exception 'unknown or closed window' using errcode = 'P0002';
  end if;
  if v_pub is null or w.publisher_id <> v_pub then
    raise exception 'not your window' using errcode = '28000';
  end if;
  -- instant revocation also mid-session (not only at open).
  perform 1 from public.devices d where d.id = w.device_id and d.revoked_at is null;
  if not found then
    raise exception 'device revoked' using errcode = '28000';
  end if;
  -- activity bucket must be one of the known coarse values; this also pins the HMAC
  -- message format (a NULL would render as '' and silently diverge from the client).
  if p_activity_delta is null or p_activity_delta not in ('none', 'low', 'med', 'high') then
    raise exception 'invalid activity bucket' using errcode = 'P0001';
  end if;
  if p_seq <> w.beats_count + 1 then
    raise exception 'out-of-order seq' using errcode = 'P0001';
  end if;
  -- anti-batch: honest heartbeats must be wall-clock separated (>=500ms), measured at
  -- the server against the last receipt (or the open time for the first beat).
  v_spacing := extract(epoch from (now() - coalesce(w.last_recv_at, w.started_at))) * 1000;
  if v_spacing < 500 then
    raise exception 'anti-batch: beats too close' using errcode = 'P0001';
  end if;
  v_prev := coalesce(w.prev_hash, w.window_id::text);
  v_expected := encode(
    extensions.hmac(format('%s|%s|%s', p_seq, v_prev, p_activity_delta), w.challenge, 'sha256'),
    'hex');
  if p_hmac is distinct from v_expected then
    raise exception 'bad hmac chain' using errcode = 'P0001';
  end if;

  update public.ad_windows set
      beats_count       = p_seq,
      last_recv_at      = now(),
      prev_hash         = p_hmac,
      activity_progress = activity_progress or (p_activity_delta is not null and p_activity_delta <> 'none'),
      activity_max_bucket = case
        when app.activity_rank(p_activity_delta) > app.activity_rank(coalesce(activity_max_bucket, 'none'))
        then p_activity_delta else activity_max_bucket end
    where window_id = p_window_id;

  return jsonb_build_object('ok', true);
end;
$$;
revoke execute on function public.window_beat(uuid, integer, text, text) from public;
grant execute on function public.window_beat(uuid, integer, text, text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- close_window(window_id) -> { credited, attention_seconds, gross_micros, reason }
-- Idempotent: only fires while state='open'; impressions.window_id UNIQUE is the
-- durable single-credit backstop.
-- ---------------------------------------------------------------------------
create or replace function public.close_window(p_window_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_pub       uuid := nullif(app.jwt_claim('publisher_id'), '')::uuid;
  w           public.ad_windows;
  v_elapsed   numeric;
  v_att       integer;
  v_bid       bigint := 0;
  v_gross     bigint := 0;
begin
  select * into w from public.ad_windows where window_id = p_window_id for update;
  if not found then
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'unknown window');
  end if;
  if v_pub is null or w.publisher_id <> v_pub then
    raise exception 'not your window' using errcode = '28000';
  end if;
  if w.state <> 'open' then   -- idempotent: already closed/credited
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already closed');
  end if;
  perform 1 from public.devices d where d.id = w.device_id and d.revoked_at is null;
  if not found then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'device revoked');
  end if;

  if w.beats_count < 3 then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', format('too few beats (%s)', w.beats_count));
  end if;
  if not w.activity_progress then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'no activity progress');
  end if;
  v_elapsed := extract(epoch from (now() - w.started_at)) * 1000;
  if v_elapsed < w.dwell_ms then
    update public.ad_windows set state = 'abandoned' where window_id = p_window_id;
    update public.clicks set state = 'void', gross_micros = 0 where window_id = p_window_id and state <> 'void';
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'dwell too short');
  end if;

  v_att := round(least(v_elapsed, w.dwell_ms) / 1000.0);

  -- House / no-fill: a valid dwell with no booked creative is recorded void, never billed.
  if w.creative_id is null then
    update public.ad_windows set state = 'void' where window_id = p_window_id;
    insert into public.impressions(window_id, publisher_id, line_item_id, creative_id, attention_seconds, gross_micros, state)
      values (w.window_id, w.publisher_id, null, null, v_att, 0, 'void')
      on conflict (window_id) do nothing;
    return jsonb_build_object('credited', false, 'attention_seconds', v_att, 'gross_micros', 0, 'reason', 'house');
  end if;

  select cpva_bid_micros into v_bid from public.line_items where id = w.line_item_id;
  v_gross := v_att * coalesce(v_bid, 0);   -- CPVA: bid is micro-USD per attention-second

  insert into public.impressions(window_id, publisher_id, line_item_id, creative_id, attention_seconds, gross_micros, state)
    values (w.window_id, w.publisher_id, w.line_item_id, w.creative_id, v_att, v_gross, 'provisional')
    on conflict (window_id) do nothing;
  if not found then
    -- A row already existed for this window (concurrent/replayed close): do not re-credit.
    update public.ad_windows set state = 'credited' where window_id = p_window_id;
    return jsonb_build_object('credited', false, 'attention_seconds', 0, 'gross_micros', 0, 'reason', 'already credited');
  end if;

  update public.ad_windows set state = 'credited' where window_id = p_window_id;
  return jsonb_build_object('credited', true, 'attention_seconds', v_att, 'gross_micros', v_gross, 'reason', 'ok');
end;
$$;
revoke execute on function public.close_window(uuid) from public;
grant execute on function public.close_window(uuid) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- click_resolve(token) -> { ok, dest, deduped, reason }
-- Public (anon) — the click redirect. The destination comes from the booked creative,
-- never the client. Dedupe is durable via clicks.click_token_hash UNIQUE.
-- ---------------------------------------------------------------------------
create or replace function public.click_resolve(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash     text := encode(extensions.digest(p_token, 'sha256'), 'hex');
  w          public.ad_windows;
  v_dest     text;
  v_cpc      bigint := 0;
  v_new      boolean := false;
  v_billable boolean;
  v_state    public.click_state;
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

  -- A click is billable ONLY if it is bound to a window that earned (or can still earn) a
  -- credited impression, and is within the click TTL. A window that never honestly dwelled
  -- yields a VOID click: the user is still redirected, but nothing is billed. close_window
  -- voids clicks for windows that fail to credit; a 'provisional' click on an 'open' window
  -- stays pending until close decides, and the stale-window sweep (Phase 4 cron) voids the rest.
  -- This closes the open-then-instant-click CPC farm: a click never *clears* without a
  -- credited parent impression.
  v_billable := w.state in ('open', 'credited')
                and (extract(epoch from (now() - w.started_at)) <= 600);   -- 10 min TTL
  v_state := case when v_billable then 'provisional'::public.click_state
                  else 'void'::public.click_state end;
  select cpc_bid_micros into v_cpc from public.line_items where id = w.line_item_id;

  insert into public.clicks(window_id, publisher_id, line_item_id, creative_id, click_token_hash, gross_micros, state)
    values (w.window_id, w.publisher_id, w.line_item_id, w.creative_id, v_hash,
            case when v_billable then coalesce(v_cpc, 0) else 0 end, v_state)
    on conflict (click_token_hash) do nothing;
  v_new := found;   -- false on dup -> still redirect (never break the click), just don't re-bill

  return jsonb_build_object('ok', true, 'dest', v_dest, 'billed', v_billable and v_new, 'deduped', not v_new);
end;
$$;
revoke execute on function public.click_resolve(text) from public;
grant execute on function public.click_resolve(text) to anon, authenticated, service_role;
