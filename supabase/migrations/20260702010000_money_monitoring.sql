-- lumaline M5 / M3-T6 — money-path monitoring: alert store + monitor plumbing.
--
-- The monitor edge function (supabase/functions/monitor/index.ts) runs the money checks
-- (ledger zero-sum, stuck/failed payouts, failed charges, billing/payout recon drift) and
-- records outcomes here. THIS migration provides:
--
--   1. app.alert_events            — the alert store (open/resolved, dedup'd, no spam).
--   2. public.monitor_ledger_unbalanced() — READ-ONLY per-group + global ledger sums
--                                    (PostgREST cannot express HAVING, so it's an RPC).
--   3. public.monitor_sync_alerts() — atomic fire+resolve: inserts alerts that are not
--                                    already open (partial-unique dedup), resolves open
--                                    alerts of evaluated checks that no longer fail.
--   4. public.monitor_status()     — last 50 events + per-check current state.
--   5. app.run_monitor()           — pg_cron target: reads the cron secret from Vault and
--                                    net.http_post's the monitor fn. Vault/pg_net absent
--                                    (fresh local stack) -> RAISE NOTICE + no-op, never error.
--
-- DESIGN INVARIANT: the monitor is READ-ONLY on money tables. Nothing in this migration
-- (or the edge fn) mutates ledger_entries / payouts / advertiser_charges — only
-- app.alert_events is written.
--
-- SCHEDULING: deliberately NOT cron.schedule'd here. The controller schedules
-- `select app.run_monitor()` at deploy time so no secret material or environment coupling
-- lands in the repo (the vault secret name 'lumaline_cron_secret' is the only contract).
--
-- SECDEF LESSON (20260629120000): Supabase default privileges auto-grant anon/authenticated
-- EXECUTE on every new public function — every function below explicitly REVOKEs.
-- Idempotent throughout (IF NOT EXISTS / OR REPLACE / DROP POLICY IF EXISTS) so re-apply
-- converges.

-- ---------------------------------------------------------------------------
-- 1. app.alert_events — alert store. Lives in the private `app` schema (NOT in the
--    PostgREST api.schemas list), so it is reachable only via the service_role RPCs
--    below or direct SQL — never through the Data API.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app.alert_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at  timestamptz NOT NULL DEFAULT now(),
  check_name  text NOT NULL,
  severity    text NOT NULL CHECK (severity IN ('critical', 'high', 'medium')),
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
  resolved_at timestamptz,
  dedup_key   text NOT NULL,
  payload     jsonb
);

COMMENT ON TABLE app.alert_events IS
  'Money-path monitor alerts (M3-T6). One OPEN row per (check_name, dedup_key) — the partial unique index is the no-spam guard; a check that passes resolves its open rows.';

-- The no-spam guard: an already-open alert is never re-inserted.
CREATE UNIQUE INDEX IF NOT EXISTS alert_events_open_dedup
  ON app.alert_events (check_name, dedup_key)
  WHERE status = 'open';

CREATE INDEX IF NOT EXISTS alert_events_created_idx ON app.alert_events (created_at DESC);

-- RLS: service_role full (the monitor fn), admins read-only (ops visibility via direct
-- SQL / dashboard). NO anon or non-admin authenticated access. The `app` schema is not
-- API-exposed and anon has no USAGE on it — RLS here is defense in depth.
ALTER TABLE app.alert_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS alert_events_service ON app.alert_events;
CREATE POLICY alert_events_service ON app.alert_events
  FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS alert_events_admin_read ON app.alert_events;
CREATE POLICY alert_events_admin_read ON app.alert_events
  FOR SELECT TO authenticated USING ((SELECT app.is_admin()));

REVOKE ALL ON app.alert_events FROM PUBLIC, anon;
GRANT SELECT ON app.alert_events TO authenticated;           -- admin-gated by RLS
GRANT SELECT, INSERT, UPDATE ON app.alert_events TO service_role;

-- ---------------------------------------------------------------------------
-- 2. pg_net — needed by app.run_monitor() (pg_cron is already installed on the remote).
--    Guarded: a stack without the extension must still apply this migration cleanly.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_net;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'money_monitoring: pg_net unavailable (%) — app.run_monitor() will no-op until installed', SQLERRM;
END $$;

-- ---------------------------------------------------------------------------
-- 3. monitor_ledger_unbalanced — READ-ONLY zero-sum probe.
--    Returns { groups: [{entry_group_id, sum_micros}], global_sum_micros } where groups
--    contains ONLY unbalanced entry groups (HAVING sum<>0, capped at p_limit).
--    NOTE: with the deferred ledger_group_balances constraint trigger this is normally
--    empty — a non-empty result means the trigger was bypassed/disabled (or a T6 drill
--    injected a fault with the trigger off). Detection must not depend on the trigger.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.monitor_ledger_unbalanced(p_limit int DEFAULT 50)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT jsonb_build_object(
    'groups',
      (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                 'entry_group_id', g.entry_group_id, 'sum_micros', g.s)), '[]'::jsonb)
         FROM (SELECT le.entry_group_id, sum(le.amount_micros) AS s
                 FROM public.ledger_entries le
                GROUP BY le.entry_group_id
               HAVING sum(le.amount_micros) <> 0
                LIMIT p_limit) g),
    'global_sum_micros',
      (SELECT COALESCE(sum(le.amount_micros), 0)::bigint FROM public.ledger_entries le)
  );
$$;
REVOKE ALL ON FUNCTION public.monitor_ledger_unbalanced(int) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.monitor_ledger_unbalanced(int) TO service_role;
COMMENT ON FUNCTION public.monitor_ledger_unbalanced IS
  'READ-ONLY: entry groups whose legs do not sum to zero + the global ledger sum. Monitor check (a).';

-- ---------------------------------------------------------------------------
-- 4. monitor_sync_alerts — atomic fire + resolve.
--      p_evaluated_checks: check names that actually EVALUATED this run (pass or fail).
--                          An errored check must NOT resolve its open alerts (it could
--                          not see the data), so the edge fn omits it from this list.
--      p_alerts:           the currently-failing alert set
--                          [{check_name, severity, dedup_key, payload}].
--    Fire:    insert rows not already open (ON CONFLICT on the partial unique -> no spam).
--    Resolve: open rows of evaluated checks whose (check_name, dedup_key) is NOT in the
--             currently-failing set (covers both "check passes" and "this item recovered").
--    Returns { fired: [...], resolved: [...] } — only NEW transitions, for email gating.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.monitor_sync_alerts(p_evaluated_checks text[], p_alerts jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_result jsonb;
BEGIN
  -- One statement so fire + resolve share the same snapshot: the UPDATE cannot see the
  -- rows the sibling INSERT adds (newly-fired alerts can never be resolved in the same
  -- run), and NOT EXISTS(incoming) keeps still-failing alerts open.
  WITH incoming AS (
    SELECT DISTINCT ON (a.check_name, a.dedup_key)
           a.check_name, a.severity, a.dedup_key, a.payload
      FROM jsonb_to_recordset(COALESCE(p_alerts, '[]'::jsonb))
        AS a(check_name text, severity text, dedup_key text, payload jsonb)
  ), ins AS (
    INSERT INTO app.alert_events (check_name, severity, dedup_key, payload)
    SELECT i.check_name, i.severity, i.dedup_key, i.payload FROM incoming i
    ON CONFLICT (check_name, dedup_key) WHERE status = 'open' DO NOTHING
    RETURNING id, check_name, severity, dedup_key
  ), res AS (
    UPDATE app.alert_events e
       SET status = 'resolved', resolved_at = now()
     WHERE e.status = 'open'
       AND e.check_name = ANY (COALESCE(p_evaluated_checks, '{}'::text[]))
       AND NOT EXISTS (
         SELECT 1 FROM incoming i
          WHERE i.check_name = e.check_name AND i.dedup_key = e.dedup_key)
    RETURNING e.id, e.check_name, e.severity, e.dedup_key
  )
  SELECT jsonb_build_object(
    'fired',
      COALESCE((SELECT jsonb_agg(jsonb_build_object(
                  'id', ins.id, 'check_name', ins.check_name,
                  'severity', ins.severity, 'dedup_key', ins.dedup_key)) FROM ins), '[]'::jsonb),
    'resolved',
      COALESCE((SELECT jsonb_agg(jsonb_build_object(
                  'id', res.id, 'check_name', res.check_name,
                  'severity', res.severity, 'dedup_key', res.dedup_key)) FROM res), '[]'::jsonb))
    INTO v_result;

  RETURN v_result;
END;
$$;
REVOKE ALL ON FUNCTION public.monitor_sync_alerts(text[], jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.monitor_sync_alerts(text[], jsonb) TO service_role;
COMMENT ON FUNCTION public.monitor_sync_alerts IS
  'Atomic alert fire+resolve for the monitor fn. Dedup: partial unique on open (check_name, dedup_key). Returns only NEW transitions.';

-- ---------------------------------------------------------------------------
-- 5. monitor_status — last 50 alert events + per-check current state.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.monitor_status()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
  SELECT jsonb_build_object(
    'events',
      (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.created_at DESC), '[]'::jsonb)
         FROM (SELECT * FROM app.alert_events ORDER BY created_at DESC LIMIT 50) e),
    'checks',
      (SELECT COALESCE(jsonb_object_agg(s.check_name, s.st), '{}'::jsonb)
         FROM (SELECT ae.check_name,
                      jsonb_build_object(
                        'open_count',    count(*) FILTER (WHERE ae.status = 'open'),
                        'state',         CASE WHEN count(*) FILTER (WHERE ae.status = 'open') > 0
                                              THEN 'alerting' ELSE 'ok' END,
                        'last_event_at', max(ae.created_at)) AS st
                 FROM app.alert_events ae
                GROUP BY ae.check_name) s)
  );
$$;
REVOKE ALL ON FUNCTION public.monitor_status() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.monitor_status() TO service_role;
COMMENT ON FUNCTION public.monitor_status IS
  'Last 50 alert_events + per-check open/ok state. GET /monitor/status backend.';

-- ---------------------------------------------------------------------------
-- 6. app.run_monitor — the pg_cron target. Reads 'lumaline_cron_secret' from Vault and
--    POSTs the monitor fn with the x-lumaline-cron-secret header via pg_net.
--    Degrades gracefully (NOTICE + no-op, never an error) when Vault, the secret, or
--    pg_net is absent — a fresh local `supabase db reset` must apply and run cleanly.
--    All Vault/net access is via dynamic SQL so the function also CREATEs cleanly there.
--    Never logs the secret value.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app.run_monitor()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  v_secret     text;
  v_request_id bigint;
BEGIN
  IF to_regclass('vault.decrypted_secrets') IS NULL THEN
    RAISE NOTICE 'run_monitor: vault.decrypted_secrets missing (fresh local stack?) — no-op';
    RETURN;
  END IF;

  BEGIN
    EXECUTE 'SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = $1 LIMIT 1'
       INTO v_secret
      USING 'lumaline_cron_secret';
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'run_monitor: cannot read vault (%) — no-op', SQLERRM;
    RETURN;
  END;

  IF v_secret IS NULL OR v_secret = '' THEN
    RAISE NOTICE 'run_monitor: vault secret lumaline_cron_secret absent — no-op';
    RETURN;
  END IF;

  BEGIN
    EXECUTE $q$
      SELECT net.http_post(
        url     := 'https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/monitor/run',
        body    := '{}'::jsonb,
        headers := jsonb_build_object(
                     'Content-Type', 'application/json',
                     'x-lumaline-cron-secret', $1),
        timeout_milliseconds := 60000)
    $q$ INTO v_request_id USING v_secret;
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'run_monitor: net.http_post unavailable/failed (%) — no-op', SQLERRM;
    RETURN;
  END;
END;
$$;
REVOKE ALL ON FUNCTION app.run_monitor() FROM PUBLIC, anon, authenticated;
COMMENT ON FUNCTION app.run_monitor IS
  'pg_cron target: POST the monitor edge fn with the Vault cron secret. Vault/secret/pg_net absent -> NOTICE + no-op. Controller cron.schedule''s this at deploy time.';
