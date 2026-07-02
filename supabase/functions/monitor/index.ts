// supabase/functions/monitor/index.ts
// LumaLine money-path monitoring — M3-T6 (M5 go-live gate).
//
// DESIGN INVARIANT — READ-ONLY ON MONEY TABLES: this function NEVER mutates
// ledger_entries / payouts / advertiser_charges / impressions / clicks. Its only write
// surface is app.alert_events (via the service-role monitor_sync_alerts RPC). Checks
// observe; they never repair.
//
// Endpoints:
//   POST /monitor/run    — run all checks, sync alerts, one summary email on state change.
//   GET  /monitor/status — last 50 alert_events + per-check current state.
//
// AUTH (both endpoints): EITHER the x-lumaline-cron-secret header matching env
// LUMALINE_CRON_SECRET (constant-time compare via SHA-256 digests — pg_cron calls this
// path through app.run_monitor()) OR a bearer that passes the forwardRpc('admin_check')
// gate (same pattern as billing/admin-booking). Anything else -> 401.
//
// CHECKS (decision logic is pure + unit-tested in ../_shared/monitor-logic.mjs):
//   a. ledger_zero_sum     CRITICAL — any entry_group_id sum<>0, or global sum<>0.
//   b. payout_stuck        HIGH     — non-terminal payout (pending/in_transit) older than 6h.
//   c. payout_failed       HIGH     — payouts status='failed' in the last 24h (per-id dedup).
//   d. charge_failed       HIGH     — failed advertiser_charges in 24h + line_items paused
//                                     by billing (decline -> advertiser's items paused).
//   e. billing_recon_drift CRITICAL — mirrors billing /reconcile exactly (DB
//                                     billing_recon_totals vs succeeded source=lumaline PIs).
//   f. payout_recon_drift  CRITICAL — mirrors stripe-connect /reconcile exactly (DB
//                                     payout_recon_totals vs transfers NET of reversals).
//   Recon checks scope to a trailing 35-day window ending now; the others are global
//   (b) or 24h-scoped (c, d). Stripe unreachable -> that check reports status 'error'
//   (HIGH alert; fail loud, never silently green) while the other checks still run.
//
// DRILL SUPPORT: no check special-cases anything — a synthetic imbalanced ledger group
// injected by the controller (memo/metadata marked T6-DRILL) fires ledger_zero_sum
// exactly like a real fault.
//
// EMAIL: one summary via Resend (env RESEND_API_KEY, to env LUMALINE_ALERT_EMAIL), sent
// ONLY when alerts newly fired or newly resolved — never on all-green/no-change runs.
// Email failure never fails the run: app.alert_events is the source of truth.

import { corsHeaders } from "../_shared/cors.ts";
import {
  bearerHeader,
  forwardRpc,
  serviceRpc,
  SUPABASE_URL,
  SERVICE_ROLE_KEY,
} from "../_shared/jwt.ts";
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno";
import {
  buildAlertEmail,
  errorCheck,
  evalBillingStalled,
  evalChargeFailed,
  evalLedgerZeroSum,
  evalPayoutFailed,
  evalPayoutStuck,
  evalReconDrift,
  FAILURE_LOOKBACK_MS,
  RECON_WINDOW_DAYS,
  resolvableCheckNames,
  shouldSendEmail,
  sumLumalinePaymentIntents,
  timingSafeEqualStrings,
} from "../_shared/monitor-logic.mjs";
import { sumLumalineTransfersMicros } from "../_shared/payout-logic.mjs";

const cors = { ...corsHeaders, "Access-Control-Allow-Methods": "GET, POST, OPTIONS" } as const;

function jsonOk(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "content-type": "application/json" },
  });
}
function jsonErr(message: string, status: number, detail?: unknown): Response {
  const body: Record<string, unknown> = { error: message };
  if (detail !== undefined && detail !== null) body.detail = detail;
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "content-type": "application/json" },
  });
}

// Service-role REST helper (READ-ONLY use here) — same shape as billing/index.ts.
async function svc(
  method: string,
  resource: string,
  opts: { body?: unknown; query?: string; prefer?: string } = {},
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const url = `${SUPABASE_URL}/rest/v1/${resource}${opts.query ? `?${opts.query}` : ""}`;
  const headers: Record<string, string> = {
    apikey: SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SERVICE_ROLE_KEY}`,
    accept: "application/json",
    "content-type": "application/json",
  };
  if (opts.prefer) headers["Prefer"] = opts.prefer;
  const resp = await fetch(url, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  let data: unknown = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

// AUTH: cron secret (constant-time) OR admin bearer. 401 otherwise.
async function isAuthorized(req: Request): Promise<boolean> {
  const configured = Deno.env.get("LUMALINE_CRON_SECRET") ?? "";
  const presented = req.headers.get("x-lumaline-cron-secret") ?? "";
  if (configured && presented && await timingSafeEqualStrings(presented, configured)) {
    return true;
  }
  const auth = bearerHeader(req);
  if (auth) {
    const { status, text } = await forwardRpc("admin_check", {}, auth);
    if (status === 200 && text.trim() === "true") return true;
  }
  return false;
}

// Lazy Stripe client — same pattern as billing/stripe-connect. Boots without the key;
// only the recon checks need it, and they degrade to status 'error' when it is absent.
let _stripe: Stripe | null = null;
function getStripe(): Stripe {
  if (_stripe) return _stripe;
  const key = Deno.env.get("STRIPE_SECRET_KEY") ?? "";
  if (!key) throw new Error("STRIPE_SECRET_KEY is not configured");
  if (Deno.env.get("STRIPE_ASSERT_TEST") === "true" && !key.startsWith("sk_test_")) {
    throw new Error("STRIPE_SECRET_KEY must be a test key (sk_test_*) when STRIPE_ASSERT_TEST=true");
  }
  _stripe = new Stripe(key, { apiVersion: "2024-04-10", httpClient: Stripe.createFetchHttpClient() });
  return _stripe;
}

interface CheckResult {
  name: string;
  status: "pass" | "fail" | "error";
  detail: string;
  alerts: Array<{ check_name: string; severity: string; dedup_key: string; payload: unknown }>;
}

// ---------------------------------------------------------------------------
// Checks (all READ-ONLY: GETs + STABLE RPCs + Stripe list calls).
// ---------------------------------------------------------------------------

async function checkLedgerZeroSum(): Promise<CheckResult> {
  const r = await serviceRpc("monitor_ledger_unbalanced", {});
  if (!r.ok) return errorCheck("ledger_zero_sum", `monitor_ledger_unbalanced HTTP ${r.status}`);
  return evalLedgerZeroSum(r.data as Record<string, unknown>);
}

async function checkPayoutStuck(): Promise<CheckResult> {
  const r = await svc("GET", "payouts", {
    query: "status=in.(pending,in_transit)&select=id,status,created_at&limit=500",
  });
  if (!r.ok) return errorCheck("payout_stuck", `payouts query HTTP ${r.status}`);
  return evalPayoutStuck(r.data as Array<Record<string, unknown>>, Date.now());
}

async function checkPayoutFailed(): Promise<CheckResult> {
  // payouts has no failed_at; created_at scopes the 24h visibility window (documented
  // limitation: a payout created earlier that fails late ages out of this check).
  const sinceIso = new Date(Date.now() - FAILURE_LOOKBACK_MS).toISOString();
  const r = await svc("GET", "payouts", {
    query: `status=eq.failed&created_at=gte.${encodeURIComponent(sinceIso)}&select=id,failure_reason,created_at&limit=500`,
  });
  if (!r.ok) return errorCheck("payout_failed", `payouts query HTTP ${r.status}`);
  return evalPayoutFailed(r.data as Array<Record<string, unknown>>);
}

async function checkChargeFailed(): Promise<CheckResult> {
  const sinceIso = new Date(Date.now() - FAILURE_LOOKBACK_MS).toISOString();
  const chargesRes = await svc("GET", "advertiser_charges", {
    query: `status=eq.failed&created_at=gte.${encodeURIComponent(sinceIso)}&select=id,advertiser_id,failure_reason,amount_cents,created_at&limit=500`,
  });
  if (!chargesRes.ok) return errorCheck("charge_failed", `advertiser_charges query HTTP ${chargesRes.status}`);
  const failedCharges = (chargesRes.data as Array<{ advertiser_id?: string }>) ?? [];

  // "Paused by billing" (billing/index.ts): a card decline pauses ALL the advertiser's
  // active/draft line_items — so paused items are scoped to advertisers with a failed
  // charge in the window (the same campaigns->line_items path billing walks).
  let pausedLineItems: Array<Record<string, unknown>> = [];
  const advertiserIds = [...new Set(failedCharges.map((c) => c.advertiser_id).filter(Boolean))];
  if (advertiserIds.length > 0) {
    const campsRes = await svc("GET", "campaigns", {
      query: `advertiser_id=in.(${advertiserIds.join(",")})&select=id,advertiser_id`,
    });
    if (!campsRes.ok) return errorCheck("charge_failed", `campaigns query HTTP ${campsRes.status}`);
    const camps = (campsRes.data as Array<{ id: string; advertiser_id: string }>) ?? [];
    if (camps.length > 0) {
      const liRes = await svc("GET", "line_items", {
        query: `campaign_id=in.(${camps.map((c) => c.id).join(",")})&status=eq.paused&select=id,campaign_id&limit=500`,
      });
      if (!liRes.ok) return errorCheck("charge_failed", `line_items query HTTP ${liRes.status}`);
      const byId = new Map(camps.map((c) => [c.id, c.advertiser_id]));
      pausedLineItems = ((liRes.data as Array<{ id: string; campaign_id: string }>) ?? [])
        .map((li) => ({ ...li, advertiser_id: byId.get(li.campaign_id) ?? null }));
    }
  }
  return evalChargeFailed({ failedCharges, pausedLineItems });
}

// billing_stalled (stateful): advertisers with BOTH currently-paused line_items AND
// uncharged cleared billing groups — the live-mode no_payment_method state (billing
// pauses the items and deliberately writes NO charges row so the group stays retryable).
// Keys on CURRENT state: stays open until the debt is charged or the items unpaused.
async function checkBillingStalled(): Promise<CheckResult> {
  const name = "billing_stalled";
  const liRes = await svc("GET", "line_items", {
    query: "status=eq.paused&select=id,campaign_id&limit=500",
  });
  if (!liRes.ok) return errorCheck(name, `line_items query HTTP ${liRes.status}`);
  const pausedRaw = (liRes.data as Array<{ id: string; campaign_id: string }>) ?? [];

  let pausedLineItems: Array<Record<string, unknown>> = [];
  if (pausedRaw.length > 0) {
    const campIds = [...new Set(pausedRaw.map((li) => li.campaign_id).filter(Boolean))];
    const campsRes = await svc("GET", "campaigns", {
      query: `id=in.(${campIds.join(",")})&select=id,advertiser_id`,
    });
    if (!campsRes.ok) return errorCheck(name, `campaigns query HTTP ${campsRes.status}`);
    const byId = new Map(
      ((campsRes.data as Array<{ id: string; advertiser_id: string }>) ?? [])
        .map((c) => [c.id, c.advertiser_id]),
    );
    pausedLineItems = pausedRaw.map((li) => ({ ...li, advertiser_id: byId.get(li.campaign_id) ?? null }));
  }

  // The uncharged view already excludes house/sentinel from ever being charged, but be
  // explicit: only non-house debt counts as stalled revenue.
  const viewRes = await svc("GET", "uncharged_advertiser_billings", {
    query: "is_house=eq.false&select=advertiser_id,advertiser_name,amount_micros&limit=1000",
  });
  if (!viewRes.ok) return errorCheck(name, `uncharged_advertiser_billings query HTTP ${viewRes.status}`);

  return evalBillingStalled({
    unchargedRows: (viewRes.data as Array<Record<string, unknown>>) ?? [],
    pausedLineItems,
  });
}

// e. Mirrors billing/index.ts /reconcile EXACTLY: DB = billing_recon_totals(from,to)
// (cleared advertiser_billing CPVA+CPC debits); Stripe = succeeded PaymentIntents tagged
// metadata.source=lumaline, pi.amount cents * 10,000 micros. Tolerance: drift === 0.
async function checkBillingReconDrift(fromDate: Date, toDate: Date): Promise<CheckResult> {
  const name = "billing_recon_drift";
  const fromIso = fromDate.toISOString(), toIso = toDate.toISOString();

  const reconRes = await serviceRpc("billing_recon_totals", { from_ts: fromIso, to_ts: toIso });
  if (!reconRes.ok) return errorCheck(name, `billing_recon_totals HTTP ${reconRes.status}`);
  const dbObj = (reconRes.data as { total_micros?: unknown; entry_count?: unknown }) ?? {};
  const dbTotalMicros = Number(dbObj.total_micros ?? 0);
  const dbCount = Number(dbObj.entry_count ?? 0);

  let stripe: Stripe;
  try { stripe = getStripe(); } catch (err) {
    return errorCheck(name, (err as { message?: string }).message ?? "Stripe not configured");
  }

  const fromUnix = Math.floor(fromDate.getTime() / 1000);
  const toUnix = Math.floor(toDate.getTime() / 1000);
  let stripeTotalMicros = 0, stripeCount = 0, hasMore = true;
  let startingAfter: string | undefined;
  try {
    while (hasMore) {
      const params: Stripe.PaymentIntentListParams = { created: { gte: fromUnix, lte: toUnix }, limit: 100 };
      if (startingAfter) params.starting_after = startingAfter;
      const page = await stripe.paymentIntents.list(params);
      const sums = sumLumalinePaymentIntents(
        page.data as unknown as Array<{ amount?: number; status?: string; metadata?: { source?: string } }>,
      );
      stripeTotalMicros += sums.totalMicros;
      stripeCount += sums.count;
      hasMore = page.has_more;
      if (hasMore && page.data.length > 0) startingAfter = page.data[page.data.length - 1].id;
      else hasMore = false;
    }
  } catch (err) {
    return errorCheck(name, `Stripe paymentIntents.list: ${(err as { message?: string }).message ?? "unknown"}`);
  }

  return evalReconDrift(name, dbTotalMicros, stripeTotalMicros, {
    period: { from: fromIso, to: toIso },
    db_count: dbCount,
    stripe_count: stripeCount,
  });
}

// f. Mirrors stripe-connect/index.ts /reconcile EXACTLY: DB = payout_recon_totals(from,to)
// (cleared payout publisher_earnings debits of PAID payouts); Stripe = source=lumaline
// transfers NET of reversals (sumLumalineTransfersMicros). Tolerance: drift === 0.
async function checkPayoutReconDrift(fromDate: Date, toDate: Date): Promise<CheckResult> {
  const name = "payout_recon_drift";
  const fromIso = fromDate.toISOString(), toIso = toDate.toISOString();

  const reconRes = await serviceRpc("payout_recon_totals", { p_from: fromIso, p_to: toIso });
  if (!reconRes.ok) return errorCheck(name, `payout_recon_totals HTTP ${reconRes.status}`);
  const dbObj = (reconRes.data as { payout_debits_micros?: unknown; payout_count?: unknown }) ?? {};
  const dbTotalMicros = Number(dbObj.payout_debits_micros ?? 0);
  const dbCount = Number(dbObj.payout_count ?? 0);

  let stripe: Stripe;
  try { stripe = getStripe(); } catch (err) {
    return errorCheck(name, (err as { message?: string }).message ?? "Stripe not configured");
  }

  const fromUnix = Math.floor(fromDate.getTime() / 1000);
  const toUnix = Math.floor(toDate.getTime() / 1000);
  let stripeTotalMicros = 0, stripeCount = 0, hasMore = true;
  let startingAfter: string | undefined;
  try {
    while (hasMore) {
      const params: Stripe.TransferListParams = { created: { gte: fromUnix, lte: toUnix }, limit: 100 };
      if (startingAfter) params.starting_after = startingAfter;
      const page = await stripe.transfers.list(params);
      stripeTotalMicros += sumLumalineTransfersMicros(
        page.data as unknown as Array<{ amount?: number; amount_reversed?: number; metadata?: { source?: string } }>,
      );
      for (const t of page.data) if (t.metadata?.source === "lumaline") stripeCount++;
      hasMore = page.has_more;
      if (hasMore && page.data.length > 0) startingAfter = page.data[page.data.length - 1].id;
      else hasMore = false;
    }
  } catch (err) {
    return errorCheck(name, `Stripe transfers.list: ${(err as { message?: string }).message ?? "unknown"}`);
  }

  return evalReconDrift(name, dbTotalMicros, stripeTotalMicros, {
    period: { from: fromIso, to: toIso },
    db_count: dbCount,
    stripe_count: stripeCount,
  });
}

// ---------------------------------------------------------------------------
// Email (Resend) — best-effort, never fails the run, never logs secret values.
// ---------------------------------------------------------------------------
async function sendSummaryEmail(
  fired: unknown[],
  resolved: unknown[],
  checks: CheckResult[],
): Promise<string> {
  const apiKey = Deno.env.get("RESEND_API_KEY") ?? "";
  const to = Deno.env.get("LUMALINE_ALERT_EMAIL") ?? "";
  if (!apiKey || !to) {
    console.error("monitor: alert email not configured (RESEND_API_KEY / LUMALINE_ALERT_EMAIL name missing)");
    return "failed:not_configured";
  }
  const { subject, text } = buildAlertEmail(
    fired as Array<Record<string, string>>,
    resolved as Array<Record<string, string>>,
    checks,
  );
  try {
    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({
        from: "LumaLine Alerts <onboarding@resend.dev>",
        to: [to],
        subject,
        text,
      }),
    });
    if (!resp.ok) {
      console.error(`monitor: Resend send failed HTTP ${resp.status}`);
      return `failed:${resp.status}`;
    }
    return "sent";
  } catch (err) {
    console.error(`monitor: Resend send threw: ${(err as { message?: string }).message ?? "unknown"}`);
    return "failed:network";
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const path = new URL(req.url).pathname;

  if (!(await isAuthorized(req))) return jsonErr("Unauthorized", 401);

  // ---- GET /status ---------------------------------------------------------
  if (req.method === "GET" && path.endsWith("/status")) {
    const r = await serviceRpc("monitor_status", {});
    if (!r.ok) return jsonErr("monitor_status failed", 502, r.data);
    const data = (r.data as Record<string, unknown>) ?? {};
    return jsonOk({ ok: true, events: data.events ?? [], checks: data.checks ?? {} });
  }

  // ---- POST /run -----------------------------------------------------------
  if (req.method === "POST" && path.endsWith("/run")) {
    const toDate = new Date();
    const fromDate = new Date(toDate.getTime() - RECON_WINDOW_DAYS * 24 * 60 * 60 * 1000);

    // Every check runs even if others error — an unreachable Stripe must not blind
    // the ledger/payout checks (and vice versa).
    const runners: Array<[string, () => Promise<CheckResult>]> = [
      ["ledger_zero_sum", checkLedgerZeroSum],
      ["payout_stuck", checkPayoutStuck],
      ["payout_failed", checkPayoutFailed],
      ["charge_failed", checkChargeFailed],
      ["billing_stalled", checkBillingStalled],
      ["billing_recon_drift", () => checkBillingReconDrift(fromDate, toDate)],
      ["payout_recon_drift", () => checkPayoutReconDrift(fromDate, toDate)],
    ];
    const checks: CheckResult[] = [];
    for (const [name, run] of runners) {
      try {
        checks.push(await run());
      } catch (err) {
        checks.push(errorCheck(name, (err as { message?: string }).message ?? "unknown"));
      }
    }
    const alerts = checks.flatMap((c) => c.alerts);

    // Atomic fire + resolve. Errored checks are excluded from the resolvable list so an
    // unobservable check never auto-resolves its previously-open alerts.
    const sync = await serviceRpc("monitor_sync_alerts", {
      p_evaluated_checks: resolvableCheckNames(checks),
      p_alerts: alerts,
    });
    if (!sync.ok) return jsonErr("monitor_sync_alerts failed", 502, sync.data);
    const syncData = (sync.data as { fired?: unknown[]; resolved?: unknown[] }) ?? {};
    const fired = Array.isArray(syncData.fired) ? syncData.fired : [];
    const resolved = Array.isArray(syncData.resolved) ? syncData.resolved : [];

    // ONE summary email, only on a state change (fired/resolved non-empty). DB rows are
    // the source of truth; a failed email is reported but never fails the run.
    let email = "skipped";
    if (shouldSendEmail(fired, resolved)) {
      email = await sendSummaryEmail(fired, resolved, checks);
    }

    return jsonOk({
      ok: checks.every((c) => c.status === "pass"),
      checks: checks.map((c) => ({ name: c.name, status: c.status, detail: c.detail })),
      fired,
      resolved,
      email,
    });
  }

  return jsonErr("Not found", 404);
});
