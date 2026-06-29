// supabase/functions/stripe-connect/index.ts
// LumaLine publisher payout rails — Stripe Connect (Express). M3-T1/T2/T3.
//
// Endpoints:
//   POST /stripe-connect/connect/onboard           — auth publisher: get/create Express
//                                                     account + hosted onboarding link.
//   GET  /stripe-connect/connect/status            — auth publisher: payout eligibility.
//   POST /stripe-connect/webhook                   — Stripe → us (signature-verified, deduped).
//   POST /stripe-connect/payout/batch[?dry_run=true]— admin: reserve → transfer → confirm.
//   GET  /stripe-connect/reconcile?from&to         — admin: payout ledger ↔ Stripe transfers.
//
// MONEY-SAFETY (the four traps, baked in):
//   1. Webhook signature is verified over the RAW request body (req.text(), never
//      req.json() first) via stripe.webhooks.constructEventAsync.
//   2. The batch transfers EVERY db-pending payout (status='pending' AND no transfer id),
//      not just the rows this run reserved — so a crash between transfer and confirm is
//      recovered on the next run.
//   3. Before transfers.create we pre-check for an existing transfer by metadata.payout_id
//      (Stripe idempotency keys expire after 24h; the key + UNIQUE(stripe_transfer_id) are
//      backstops, the pre-check is the real guard against a >24h crash-resume double-pay).
//   4. payable counts CPVA only and RAISES if any cpc_accrual earning exists (M4) — the DB
//      function fails loud rather than silently underpaying.
//
// The SQL primitives (payout_batch_reserve / payout_confirm / payout_fail / payout_reverse /
// payout_recon_totals / set_publisher_payout_eligibility) live in
// 20260629100000_payout_rails.sql and are service-role-only. This function is their only caller.

import { corsHeaders } from "../_shared/cors.ts";
import {
  bearerHeader,
  forwardRpc,
  serviceRpc,
  SUPABASE_URL,
  ANON_KEY,
  SERVICE_ROLE_KEY,
} from "../_shared/jwt.ts";
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno";

const cors = { ...corsHeaders, "Access-Control-Allow-Methods": "GET, POST, OPTIONS" } as const;

function jsonOk(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });
}
function jsonErr(message: string, status: number, detail?: unknown): Response {
  const body: Record<string, unknown> = { error: message };
  if (detail !== undefined && detail !== null) body.detail = detail;
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });
}

// Countries LumaLine pays out to (Stripe Connect cross-border + our tax posture). Keep in
// sync with publisher-tos §7.7. account.updated from any other country → ineligible_country.
const SUPPORTED_COUNTRIES = new Set(["US", "CA", "GB", "AU", "IE", "NZ"]);

// Public app URL for hosted-onboarding return/refresh redirects.
const APP_URL = Deno.env.get("LUMALINE_APP_URL") ?? "http://localhost:3000";

// Service-role REST helper (bypasses RLS) — same shape as billing/index.ts.
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
  const resp = await fetch(url, { method, headers, body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
  let data: unknown = null;
  try { data = await resp.json(); } catch { /* empty */ }
  return { ok: resp.ok, status: resp.status, data };
}

// Admin gate — forwards the caller's bearer to admin_check (same as billing/admin-booking).
async function requireAdmin(req: Request): Promise<string | null> {
  const auth = bearerHeader(req);
  if (!auth) return null;
  const { status, text } = await forwardRpc("admin_check", {}, auth);
  return status === 200 && text.trim() === "true" ? auth : null;
}

// Fetch the CALLER's own publisher row via RLS (publishers_select_own). Returns null if the
// bearer doesn't resolve to a publisher. We pass the caller's JWT so RLS scopes to their row.
async function callerPublisher(
  auth: string,
): Promise<{ id: string; country: string | null; stripe_account_id: string | null; payout_status: string } | null> {
  const resp = await fetch(
    `${SUPABASE_URL}/rest/v1/publishers?select=id,country,stripe_account_id,payout_status&limit=1`,
    { headers: { apikey: ANON_KEY, Authorization: auth, accept: "application/json" } },
  );
  if (!resp.ok) return null;
  const rows = (await resp.json()) as Array<Record<string, unknown>>;
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const r = rows[0];
  return {
    id: String(r.id),
    country: (r.country as string) ?? null,
    stripe_account_id: (r.stripe_account_id as string) ?? null,
    payout_status: String(r.payout_status ?? "none"),
  };
}

// micro-USD → Stripe cents (1 cent = 10,000 micros).
function microsToCents(micros: number): number { return Math.round(micros / 10000); }
function payoutIdemKey(payoutId: string): string { return `lumaline_payout_${payoutId}`; }

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

// Map a Stripe account's capability flags to our payout_status enum.
function eligibilityFor(account: { charges_enabled?: boolean; payouts_enabled?: boolean; details_submitted?: boolean; country?: string }): string {
  if (account.country && !SUPPORTED_COUNTRIES.has(account.country)) return "ineligible_country";
  if (account.payouts_enabled && account.details_submitted) return "verified";
  return "pending";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const url = new URL(req.url);
  const path = url.pathname;

  // ---- POST /webhook (UNAUTHENTICATED — Stripe calls it; auth IS the signature) ----------
  // MUST run before the admin gate and MUST read the raw body for signature verification.
  if (req.method === "POST" && path.endsWith("/webhook")) {
    const sig = req.headers.get("stripe-signature");
    if (!sig) return jsonErr("Missing Stripe-Signature", 400);
    const secret = Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? "";
    if (!secret) return jsonErr("Webhook secret not configured", 503);

    const raw = await req.text(); // TRAP #1: raw body, never req.json() first.
    let event: Stripe.Event;
    try {
      event = await getStripe().webhooks.constructEventAsync(raw, sig, secret);
    } catch (err: unknown) {
      return jsonErr(`Signature verification failed: ${(err as { message?: string }).message ?? "bad signature"}`, 400);
    }

    // Replay/dedup guard: record the event id; a duplicate is a no-op (idempotent 200).
    const dedup = await svc("POST", "stripe_webhook_events", {
      body: { event_id: event.id, type: event.type },
      query: "on_conflict=event_id",
      prefer: "return=representation,resolution=ignore-duplicates",
    });
    const inserted = Array.isArray(dedup.data) && (dedup.data as unknown[]).length > 0;
    if (!inserted) return jsonOk({ ok: true, duplicate: true, type: event.type });

    try {
      if (event.type === "account.updated") {
        const account = event.data.object as Stripe.Account;
        const status = eligibilityFor(account);
        await serviceRpc("set_publisher_payout_eligibility", {
          p_stripe_account_id: account.id,
          p_status: status,
        });
        return jsonOk({ ok: true, type: event.type, eligibility: status });
      }

      if (event.type === "transfer.reversed") {
        const transfer = event.data.object as Stripe.Transfer;
        // Map transfer → payout (we store transfer.id on the payout at confirm).
        const poRes = await svc("GET", "payouts", {
          query: `stripe_transfer_id=eq.${transfer.id}&select=id&limit=1`,
        });
        const rows = (poRes.data as Array<{ id: string }>) ?? [];
        if (rows.length === 0) return jsonOk({ ok: true, type: event.type, note: "no matching payout" });
        const r = await serviceRpc("payout_reverse", { p_payout_id: rows[0].id, p_reason: "transfer_reversed" });
        return jsonOk({ ok: true, type: event.type, reverse: r.data });
      }

      // Acknowledge other event types (we subscribed narrowly, but stay tolerant).
      return jsonOk({ ok: true, type: event.type, handled: false });
    } catch (err: unknown) {
      return jsonErr(`Webhook handler error: ${(err as { message?: string }).message ?? "unknown"}`, 500);
    }
  }

  // ---- POST /connect/onboard (auth publisher) -----------------------------------------
  if (req.method === "POST" && path.endsWith("/connect/onboard")) {
    const auth = bearerHeader(req);
    if (!auth) return jsonErr("Unauthorized", 401);
    const pub = await callerPublisher(auth);
    if (!pub) return jsonErr("No publisher for this token", 403);

    let stripe: Stripe;
    try { stripe = getStripe(); } catch (err) { return jsonErr((err as { message?: string }).message ?? "Stripe not configured", 503); }

    const country = pub.country ?? "US";
    if (!SUPPORTED_COUNTRIES.has(country)) {
      await svc("PATCH", "publishers", { body: { payout_status: "ineligible_country" }, query: `id=eq.${pub.id}`, prefer: "return=minimal" });
      return jsonErr(`Payouts are not yet supported in ${country}`, 422);
    }

    try {
      let acctId = pub.stripe_account_id;
      if (!acctId) {
        const account = await stripe.accounts.create({
          type: "express",
          country,
          capabilities: { transfers: { requested: true } },
          metadata: { publisher_id: pub.id },
        });
        acctId = account.id;
        await svc("PATCH", "publishers", {
          body: { stripe_account_id: acctId, payout_status: "pending" },
          query: `id=eq.${pub.id}`,
          prefer: "return=minimal",
        });
      }
      const link = await stripe.accountLinks.create({
        account: acctId,
        refresh_url: `${APP_URL}/payouts/onboard?refresh=1`,
        return_url: `${APP_URL}/payouts/onboard?done=1`,
        type: "account_onboarding",
      });
      return jsonOk({ ok: true, account_id: acctId, onboarding_url: link.url });
    } catch (err: unknown) {
      return jsonErr(`Stripe onboarding error: ${(err as { message?: string }).message ?? "unknown"}`, 502);
    }
  }

  // ---- GET /connect/status (auth publisher) -------------------------------------------
  if (req.method === "GET" && path.endsWith("/connect/status")) {
    const auth = bearerHeader(req);
    if (!auth) return jsonErr("Unauthorized", 401);
    const pub = await callerPublisher(auth);
    if (!pub) return jsonErr("No publisher for this token", 403);
    return jsonOk({
      ok: true,
      payout_status: pub.payout_status,
      onboarded: pub.stripe_account_id != null,
    });
  }

  // ---- Admin-only routes below --------------------------------------------------------
  const adminAuth = await requireAdmin(req);
  if (!adminAuth) return jsonErr("Forbidden", 403);

  // ---- POST /payout/batch[?dry_run=true] (admin) --------------------------------------
  if (req.method === "POST" && path.endsWith("/payout/batch")) {
    const dryRun = url.searchParams.get("dry_run") === "true";

    // Phase 1: reserve pending payouts (no ledger). Idempotent via the one-active index.
    const reserve = await serviceRpc("payout_batch_reserve", {});
    if (!reserve.ok) return jsonErr("reserve failed", reserve.status, reserve.data);

    // TRAP #2: transfer EVERY db-pending payout with no transfer id (recovers crashes),
    // not just the ones reserved this run.
    const pendRes = await svc("GET", "payouts", {
      query: "status=eq.pending&stripe_transfer_id=is.null&select=id,publisher_id,amount_micros&limit=500",
    });
    const pending = (pendRes.data as Array<{ id: string; publisher_id: string; amount_micros: number }>) ?? [];

    if (dryRun) {
      return jsonOk({ ok: true, dry_run: true, reserved: reserve.data, would_transfer: pending });
    }

    let stripe: Stripe;
    try { stripe = getStripe(); } catch (err) { return jsonErr((err as { message?: string }).message ?? "Stripe not configured", 503); }

    const results: Record<string, unknown>[] = [];
    for (const po of pending) {
      // Resolve the publisher's connected account (destination).
      const acctRes = await svc("GET", "publishers", { query: `id=eq.${po.publisher_id}&select=stripe_account_id&limit=1` });
      const acct = ((acctRes.data as Array<{ stripe_account_id: string | null }>) ?? [])[0]?.stripe_account_id ?? null;
      if (!acct) {
        await serviceRpc("payout_fail", { p_payout_id: po.id, p_reason: "no_connected_account" });
        results.push({ payout_id: po.id, status: "failed", reason: "no_connected_account" });
        continue;
      }
      const cents = microsToCents(po.amount_micros);
      try {
        // TRAP #3: pre-check for an existing transfer by metadata.payout_id (the Stripe
        // idempotency key expires after 24h; this guard survives a >24h crash-resume).
        let transferId: string | null = null;
        const existing = await stripe.transfers.list({ destination: acct, limit: 100 });
        for (const t of existing.data) {
          if (t.metadata?.payout_id === po.id) { transferId = t.id; break; }
        }
        if (!transferId) {
          const transfer = await stripe.transfers.create(
            {
              amount: cents,
              currency: "usd",
              destination: acct,
              metadata: { source: "lumaline", payout_id: po.id, publisher_id: po.publisher_id },
            },
            { idempotencyKey: payoutIdemKey(po.id) },
          );
          transferId = transfer.id;
        }
        const conf = await serviceRpc("payout_confirm", { p_payout_id: po.id, p_transfer_id: transferId });
        results.push({ payout_id: po.id, status: "paid", transfer_id: transferId, confirm: conf.data });
      } catch (err: unknown) {
        const msg = (err as { message?: string }).message ?? "transfer_failed";
        await serviceRpc("payout_fail", { p_payout_id: po.id, p_reason: msg.slice(0, 200) });
        results.push({ payout_id: po.id, status: "failed", reason: msg });
      }
    }

    const paid = results.filter((r) => r.status === "paid").length;
    return jsonOk({ ok: true, dry_run: false, reserved: reserve.data, paid, processed: results.length, results });
  }

  // ---- GET /reconcile?from&to (admin) -------------------------------------------------
  if (req.method === "GET" && path.endsWith("/reconcile")) {
    const fromStr = url.searchParams.get("from");
    const toStr = url.searchParams.get("to");
    if (!fromStr || !toStr) return jsonErr("Missing required query params: from, to (ISO 8601)", 400);
    const fromDate = new Date(fromStr), toDate = new Date(toStr);
    if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) return jsonErr("Invalid date — use ISO 8601", 400);
    const fromIso = fromDate.toISOString(), toIso = toDate.toISOString();

    const reconRes = await serviceRpc("payout_recon_totals", { p_from: fromIso, p_to: toIso });
    if (!reconRes.ok) return jsonErr("DB payout reconcile failed", reconRes.status, reconRes.data);
    const dbObj = (reconRes.data as { payout_debits_micros?: unknown; payout_count?: unknown }) ?? {};
    const dbTotalMicros = Number(dbObj.payout_debits_micros ?? 0);
    const dbCount = Number(dbObj.payout_count ?? 0);

    let stripe: Stripe;
    try { stripe = getStripe(); } catch (err) { return jsonErr((err as { message?: string }).message ?? "Stripe not configured", 503); }

    const fromUnix = Math.floor(fromDate.getTime() / 1000), toUnix = Math.floor(toDate.getTime() / 1000);
    let stripeTotalMicros = 0, stripeCount = 0, hasMore = true;
    let startingAfter: string | undefined;
    try {
      while (hasMore) {
        const params: Stripe.TransferListParams = { created: { gte: fromUnix, lte: toUnix }, limit: 100 };
        if (startingAfter) params.starting_after = startingAfter;
        const page = await stripe.transfers.list(params);
        for (const t of page.data) {
          if (t.metadata?.source === "lumaline") {
            stripeTotalMicros += t.amount * 10000; // cents → micros
            stripeCount++;
          }
        }
        hasMore = page.has_more;
        if (hasMore && page.data.length > 0) startingAfter = page.data[page.data.length - 1].id;
        else hasMore = false;
      }
    } catch (err: unknown) {
      return jsonErr(`Stripe transfers.list error: ${(err as { message?: string }).message ?? "unknown"}`, 502);
    }

    const discrepancyMicros = dbTotalMicros - stripeTotalMicros;
    return jsonOk({
      ok: discrepancyMicros === 0,
      period: { from: fromIso, to: toIso },
      db_total_micros: dbTotalMicros,
      stripe_total_micros: stripeTotalMicros,
      discrepancy_micros: discrepancyMicros,
      db_count: dbCount,
      stripe_count: stripeCount,
    });
  }

  return jsonErr("Not found", 404);
});
