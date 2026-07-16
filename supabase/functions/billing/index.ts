// supabase/functions/billing/index.ts
// Admin-triggered billing cycle: idempotent Stripe charges for cleared advertiser
// ledger entries that have not yet been billed. M2-T4.
//
// Endpoints:
//   POST /functions/v1/billing/charge              — run billing cycle (admin-only)
//   POST /functions/v1/billing/charge?dry_run=true — preview plan, no Stripe calls
//   POST /functions/v1/billing/setup-link          — Stripe Checkout setup-mode link so an
//                                                    advertiser can save a card (admin-only)
//
// ADMIN AUTH: same pattern as admin-booking — forwardRpc('admin_check') forwards the
// caller's bearer to PostgREST, which verifies the JWT and calls admin_check() →
// app.is_admin(). No SUPABASE_JWT_SECRET dependency in the edge runtime.
//
// BILLING LOGIC:
//   1. Query uncharged_advertiser_billings view (cleared cpva_accrual entries with no
//      advertiser_charges row).
//   2. For each entry:
//      a. Skip house/sentinel advertisers (is_house=true) → status='skipped'.
//      b. Skip below Stripe minimum ($0.50 = 50 cents) → status='skipped'.
//      c. Get or create Stripe customer (persist stripe_customer_id on advertiser).
//      d. Resolve the payment method via choosePaymentMethod (_shared/billing-logic.mjs):
//         saved default PM > first attached card > pm_card_visa (TEST MODE ONLY).
//         Live mode with no saved PM → the group is reported skipped (reason=
//         no_payment_method) and the advertiser's line_items are paused, but NO
//         advertiser_charges row is written — the group stays in the uncharged view
//         and is charged by a later run once a PM is saved (retryable, not terminal).
//      e. Create+confirm PaymentIntent with the resolved payment method.
//         Idempotency key: lumaline_grp_{entry_group_id} — safe to re-run.
//      f. Insert into advertiser_charges (UNIQUE on entry_group_id = idempotency backstop).
//      g. On card_declined: pause all line_items for this advertiser.
//
// TRUST INVARIANTS (non-negotiable):
//   1. House/sentinel (is_house=true) → always skipped. Never charged.
//   2. Idempotency: UNIQUE(entry_group_id) + Stripe idempotency key prevent double-charges.
//   3. Only cleared ledger entries are charged (72h clawback window has passed).
//   4. Test mode: STRIPE_SECRET_KEY must be sk_test_* when STRIPE_ASSERT_TEST=true.
//
// STRIPE KEY: Lazy-initialised — function boots without STRIPE_SECRET_KEY, so
// auth-gate and dry_run tests work even when the key is absent. Stripe is only
// initialised (and required) when an actual charge is about to be attempted.

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
  choosePaymentMethod,
  isLiveKey,
  microsToCents,
  batchIdempotencyKey,
  planAdvertiserCharges,
  partitionPendingByBatch,
} from "../_shared/billing-logic.mjs";

const billingCors = {
  ...corsHeaders,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
} as const;

function jsonOk(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...billingCors, "content-type": "application/json" },
  });
}

function jsonErr(message: string, status: number, detail?: unknown): Response {
  const body: Record<string, unknown> = { error: message };
  if (detail !== undefined && detail !== null) body.detail = detail;
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...billingCors, "content-type": "application/json" },
  });
}

// Build the /charge response with an honest per-outcome breakdown. `charged` = actual successful
// charges (not results.length); new clients should read `counts` (which sums to `processed`).
function billingResponse(results: Record<string, unknown>[], dryRun: boolean): Response {
  const counts = {
    succeeded:    results.filter((r) => r.status === "succeeded").length,
    skipped:      results.filter((r) => r.status === "skipped").length,
    failed:       results.filter((r) => r.status === "failed").length,
    would_charge: results.filter((r) => r.would_charge === true).length,
  };
  return jsonOk({ charged: counts.succeeded, processed: results.length, counts, dry_run: dryRun, results });
}

// Service-role REST helper — bypasses RLS, same pattern as admin-booking.
async function svc(
  method: string,
  resource: string,
  opts: { body?: unknown; query?: string; prefer?: string } = {},
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const url = `${SUPABASE_URL}/rest/v1/${resource}${opts.query ? `?${opts.query}` : ""}`;
  const headers: Record<string, string> = {
    "apikey": SERVICE_ROLE_KEY,
    "Authorization": `Bearer ${SERVICE_ROLE_KEY}`,
    "accept": "application/json",
    "content-type": "application/json",
  };
  if (opts.prefer) headers["Prefer"] = opts.prefer;
  const resp = await fetch(url, {
    method,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  let data: unknown = null;
  try { data = await resp.json(); } catch { /* empty body is fine */ }
  return { ok: resp.ok, status: resp.status, data };
}

// Admin guard — same as admin-booking. Returns the raw bearer string if admin, null otherwise.
async function requireAdmin(req: Request): Promise<string | null> {
  const auth = bearerHeader(req);
  if (!auth) return null;
  const { status, text } = await forwardRpc("admin_check", {}, auth);
  return status === 200 && text.trim() === "true" ? auth : null;
}

// Money-admin guard — the aal2 + app.money_admins tier (money_admin_check() wraps
// app.is_money_admin()). Re-gates the ONLY money-mutating billing route (POST /refund) so a
// stolen aal1 magic-link session, which still passes requireAdmin, cannot issue a Stripe refund.
// Read-only routes (GET /reconcile) stay on requireAdmin — membership is sufficient there.
async function requireMoneyAdmin(req: Request): Promise<string | null> {
  const auth = bearerHeader(req);
  if (!auth) return null;
  const { status, text } = await forwardRpc("money_admin_check", {}, auth);
  return status === 200 && text.trim() === "true" ? auth : null;
}

// Lazy Stripe client — only initialised when a real charge is about to be attempted.
// This allows the fn to boot and handle dry_run / house-skip / below-min-skip paths
// without STRIPE_SECRET_KEY, keeping no-Stripe integration tests green.
let _stripe: Stripe | null = null;
function getStripe(): Stripe {
  if (_stripe) return _stripe;
  const key = Deno.env.get("STRIPE_SECRET_KEY") ?? "";
  if (!key) {
    throw new Error(
      "STRIPE_SECRET_KEY is not configured — add it to Supabase secrets with " +
      "`supabase secrets set STRIPE_SECRET_KEY=sk_test_...`",
    );
  }
  if (Deno.env.get("STRIPE_ASSERT_TEST") === "true" && !key.startsWith("sk_test_")) {
    throw new Error(
      "STRIPE_SECRET_KEY must be a test key (sk_test_*) when STRIPE_ASSERT_TEST=true (M2)",
    );
  }
  _stripe = new Stripe(key, {
    apiVersion: "2024-04-10",
    httpClient: Stripe.createFetchHttpClient(),
  });
  return _stripe;
}

// True when the configured Stripe key is a LIVE key (sk_live_/rk_live_). Drives the
// choosePaymentMethod live-mode guard: the pm_card_visa test fallback only engages for
// non-live keys. Reads the env (never logs the value).
function stripeIsLive(): boolean {
  return isLiveKey(Deno.env.get("STRIPE_SECRET_KEY") ?? "");
}

// Get-or-create the Stripe customer for an advertiser, persisting stripe_customer_id on
// the advertisers row so future calls skip the create. Shared by the /charge loop and
// the /setup-link endpoint.
async function getOrCreateStripeCustomer(
  stripe: Stripe,
  advertiserId: string,
  advertiserName: string,
  existingCustomerId: string | null,
): Promise<string> {
  if (existingCustomerId) return existingCustomerId;
  const customer = await stripe.customers.create({
    name:     advertiserName,
    metadata: { advertiser_id: advertiserId },
  });
  await svc("PATCH", "advertisers", {
    body:   { stripe_customer_id: customer.id },
    query:  `id=eq.${advertiserId}`,
    prefer: "return=minimal",
  });
  return customer.id;
}

// Pause every active/draft line_item for an advertiser (no credit extension without a
// working payment method). Shared by the card_declined path and the live-mode
// no_payment_method skip path — identical semantics for both.
async function pauseAdvertiserLineItems(advertiserId: string): Promise<void> {
  const campsRes = await svc("GET", "campaigns", {
    query: `advertiser_id=eq.${advertiserId}&select=id`,
  });
  if (campsRes.ok && Array.isArray(campsRes.data) && campsRes.data.length > 0) {
    const ids = (campsRes.data as Array<{ id: string }>).map((r) => r.id).join(",");
    await svc("PATCH", "line_items", {
      body:   { status: "paused" },
      query:  `campaign_id=in.(${ids})&status=in.(active,draft)`,
      prefer: "return=minimal",
    });
  }
}

// Resolve the payment method to charge for a Stripe customer: fetch the customer with
// invoice_settings.default_payment_method expanded, list attached card payment methods,
// and delegate the decision to the pure choosePaymentMethod (_shared/billing-logic.mjs).
// Card-only today: SEPA debit confirms asynchronously (can fail days later), which would
// break the synchronous succeeded/failed recording + /reconcile assumptions.
async function resolvePaymentMethod(
  stripe: Stripe,
  customerId: string,
): Promise<{ pm: string } | { skip: "no_payment_method" }> {
  const customer = await stripe.customers.retrieve(customerId, {
    expand: ["invoice_settings.default_payment_method"],
  });
  let defaultPmId: string | null = null;
  if (!("deleted" in customer && customer.deleted)) {
    const dpm = (customer as Stripe.Customer).invoice_settings?.default_payment_method;
    defaultPmId = typeof dpm === "string" ? dpm : dpm?.id ?? null;
  }
  const attached = await stripe.paymentMethods.list({
    customer: customerId,
    type:     "card",
    limit:    100,
  });
  return choosePaymentMethod({
    liveMode:                 stripeIsLive(),
    defaultPaymentMethodId:   defaultPmId,
    attachedPaymentMethodIds: attached.data.map((pm) => pm.id),
  });
}

interface ChargeRow {
  entry_group_id: string;
  advertiser_id: string;
  impression_id: string | null;
  amount_micros: number;
  amount_cents: number;
  stripe_charge_id?: string | null;
  stripe_customer_id?: string | null;
  status: "pending" | "succeeded" | "failed" | "skipped";
  failure_reason?: string | null;
}

// Insert a row into advertiser_charges. resolution=ignore-duplicates → ON CONFLICT DO NOTHING,
// so a concurrent billing run that already processed this group is silently ignored.
async function insertCharge(row: ChargeRow): Promise<void> {
  const body: Record<string, unknown> = {
    entry_group_id: row.entry_group_id,
    advertiser_id:  row.advertiser_id,
    impression_id:  row.impression_id,
    amount_micros:  row.amount_micros,
    amount_cents:   row.amount_cents,
    status:         row.status,
    attempted_at:   new Date().toISOString(),
  };
  if (row.stripe_charge_id   != null) body.stripe_charge_id   = row.stripe_charge_id;
  if (row.stripe_customer_id != null) body.stripe_customer_id = row.stripe_customer_id;
  if (row.failure_reason     != null) body.failure_reason     = row.failure_reason;

  const res = await svc("POST", "advertiser_charges", {
    body,
    query:  "on_conflict=entry_group_id",  // explicit conflict target for resolution=ignore-duplicates
    prefer: "return=minimal,resolution=ignore-duplicates",
  });
  // 200/201/204 = success; 409 = duplicate without resolution header (older PostgREST) = ok.
  // Any other non-ok status is a real error — log it but don't abort the billing cycle.
  if (!res.ok && res.status !== 409) {
    console.error(
      `billing: insertCharge failed HTTP ${res.status} for group ${row.entry_group_id}:`,
      JSON.stringify(res.data),
    );
  }
}

// ---- Aggregate-charge helpers (per-advertiser billing) ----------------------
// Reserve a plan's groups as `pending` advertiser_charges rows. This removes them from the
// uncharged view (ac.entry_group_id IS NULL) so a concurrent/next run cannot re-select them.
// on_conflict → ignore-duplicates: a group already reserved/charged by a prior run is untouched.
type PendingGroup = { entry_group_id: string; amount_micros: number; impression_id: string | null };

// Reserve a set of groups under ONE stable charge_batch_id (claiming them out of the uncharged
// view). on_conflict=entry_group_id → ignore-duplicates: a group already reserved/charged by another
// batch is left in its owning batch, so each group belongs to exactly one batch (per-group claiming
// = the concurrency guard) and the batch membership is frozen for its stable idempotency key.
async function reservePending(
  groups: PendingGroup[],
  advertiserId: string,
  batchId: string,
): Promise<void> {
  if (groups.length === 0) return;
  const rows = groups.map((g) => ({
    entry_group_id:  g.entry_group_id,
    advertiser_id:   advertiserId,
    impression_id:   g.impression_id,
    amount_micros:   g.amount_micros,
    amount_cents:    microsToCents(g.amount_micros),
    status:          "pending",
    charge_batch_id: batchId,
    attempted_at:    new Date().toISOString(),
  }));
  await svc("POST", "advertiser_charges", {
    body:   rows,
    query:  "on_conflict=entry_group_id",
    prefer: "return=minimal,resolution=ignore-duplicates",
  });
}

// The AUTHORITATIVE set for a batch: its own reserved-but-unsettled rows. A batch never sees another
// batch's groups, so its idempotency key (batchIdempotencyKey) is immutable across retries/recovery.
async function reselectByBatch(batchId: string): Promise<PendingGroup[]> {
  const res = await svc("GET", "advertiser_charges", {
    query:
      `charge_batch_id=eq.${batchId}&status=eq.pending&stripe_charge_id=is.null` +
      `&select=entry_group_id,amount_micros,impression_id&limit=1000`,
  });
  return res.ok && Array.isArray(res.data) ? (res.data as PendingGroup[]) : [];
}

// Release reserved-but-not-charged rows back to the uncharged view (delete the pending rows). Used
// ONLY before any PaymentIntent exists for the batch (sub-minimum / house), never after a charge.
async function releaseBatch(entryGroupIds: string[]): Promise<void> {
  if (entryGroupIds.length === 0) return;
  await svc("DELETE", "advertiser_charges", {
    query:  `entry_group_id=in.(${entryGroupIds.join(",")})&status=eq.pending&stripe_charge_id=is.null`,
    prefer: "return=minimal",
  });
}

// Promote a batch's reserved rows onto a succeeded PaymentIntent. Filtered on status=eq.pending so it
// only ever settles rows still reserved (never overwrites a succeeded/failed row).
async function markPendingCharged(
  entryGroupIds: string[],
  stripeChargeId: string,
  customerId: string,
): Promise<void> {
  if (entryGroupIds.length === 0) return;
  await svc("PATCH", "advertiser_charges", {
    body: {
      status: "succeeded", stripe_charge_id: stripeChargeId,
      stripe_customer_id: customerId, attempted_at: new Date().toISOString(),
    },
    query:  `entry_group_id=in.(${entryGroupIds.join(",")})&status=eq.pending`,
    prefer: "return=minimal",
  });
}

// Promote a PREPAY batch's reserved rows onto a balance draw-down (no Stripe PI): settled_via='balance'
// + stripe_charge_id stays NULL, so /refund routes to the balance-clawback path and /reconcile (which
// counts only source=lumaline PIs) never sees them. Filtered on status=eq.pending like markPendingCharged.
async function markPendingChargedBalance(entryGroupIds: string[]): Promise<void> {
  if (entryGroupIds.length === 0) return;
  await svc("PATCH", "advertiser_charges", {
    body: {
      status: "succeeded", settled_via: "balance", attempted_at: new Date().toISOString(),
    },
    query:  `entry_group_id=in.(${entryGroupIds.join(",")})&status=eq.pending`,
    prefer: "return=minimal",
  });
}

// Terminal-fail a batch's reserved rows — ONLY for a definitive decline. Ambiguous errors
// (network/timeout, where the PI may exist) deliberately leave the rows pending so a recovery run
// retries idempotently with the SAME batch key.
async function markPendingFailed(entryGroupIds: string[], reason: string): Promise<void> {
  if (entryGroupIds.length === 0) return;
  await svc("PATCH", "advertiser_charges", {
    body:   { status: "failed", failure_reason: reason, attempted_at: new Date().toISOString() },
    query:  `entry_group_id=in.(${entryGroupIds.join(",")})&status=eq.pending`,
    prefer: "return=minimal",
  });
}

interface AdvertiserPlan {
  advertiser_id: string;
  advertiser_name: string | null;
  stripe_customer_id: string | null;
  groups: PendingGroup[];
}
interface BatchAdvertiser {
  advertiser_id: string;
  advertiser_name: string | null;
  stripe_customer_id: string | null;
  is_house: boolean;
  billing_mode: string;   // 'postpay' (Stripe PI) | 'prepay' (draw-down); M9
}

// Settle an ALREADY-RESERVED batch onto ONE PaymentIntent, using an already-resolved customer + PM.
// Idempotency key = batchIdempotencyKey(batchId) (IMMUTABLE), so a crash after paymentIntents.create
// is recovered by a later run re-issuing the SAME batch → Stripe returns the SAME PI (no double
// charge). house / sub-minimum batches are RELEASED back to the view (never charged) BEFORE any PI.
async function settleReservedBatch(
  batchId: string,
  adv: BatchAdvertiser,
  customerId: string,
  pm: string,
): Promise<Record<string, unknown>> {
  const chargeSet = await reselectByBatch(batchId);
  if (chargeSet.length === 0) {
    return { advertiser_id: adv.advertiser_id, status: "skipped", reason: "nothing_pending", batch_id: batchId };
  }
  const ids = chargeSet.map((g) => g.entry_group_id);

  // TRUST INVARIANT #1 (F5): house/sentinel is never charged, even via recovery.
  if (adv.is_house) {
    await releaseBatch(ids);
    return { advertiser_id: adv.advertiser_id, status: "skipped", reason: "house_advertiser", batch_id: batchId };
  }

  const sumMicros   = chargeSet.reduce((a, g) => a + Number(g.amount_micros), 0);
  const amountCents = microsToCents(sumMicros);
  if (amountCents < 50) {
    // A concurrent run claimed some of this batch's intended groups → the claimed remainder is
    // sub-minimum. Release it back to the view to re-aggregate (never leave it stranded pending).
    await releaseBatch(ids);
    return {
      advertiser_id: adv.advertiser_id, status: "skipped", reason: "below_stripe_minimum",
      amount_cents: amountCents, batch_id: batchId,
    };
  }

  try {
    const stripe = getStripe();
    const intent = await stripe.paymentIntents.create(
      {
        amount:         amountCents,
        currency:       "eur",
        customer:       customerId,
        payment_method: pm,
        confirm:        true,
        off_session:    true,
        description:    `LumaLine CPVA — ${adv.advertiser_name ?? adv.advertiser_id} — ${chargeSet.length} impression(s)`,
        metadata: {
          source:          "lumaline",         // enables /reconcile Stripe-side filter
          kind:            "cpva_aggregate",
          advertiser_id:   adv.advertiser_id,
          charge_batch_id: batchId,
          group_count:     String(chargeSet.length),
        },
      },
      { idempotencyKey: batchIdempotencyKey(batchId) },   // IMMUTABLE per batch
    );

    await markPendingCharged(ids, intent.id, customerId);

    // Stamp each impression with the PI id so /refund can look it up.
    const impIds = chargeSet.map((g) => g.impression_id).filter((x): x is string => !!x);
    if (impIds.length > 0) {
      await svc("PATCH", "impressions", {
        body:   { stripe_charge_id: intent.id },
        query:  `id=in.(${impIds.join(",")})`,
        prefer: "return=minimal",
      });
    }

    return {
      advertiser_id: adv.advertiser_id, status: "succeeded", stripe_id: intent.id,
      amount_cents: amountCents, group_count: chargeSet.length, batch_id: batchId,
    };
  } catch (err: unknown) {
    const stripeErr = err as { code?: string; type?: string; message?: string };
    const isDecline = stripeErr.code === "card_declined" || stripeErr.type === "StripeCardError";
    const reason = stripeErr.message ?? "unknown";
    if (isDecline) {
      // Definitive decline → terminal-fail this batch's rows + pause. Ambiguous errors are NOT failed:
      // leaving them pending lets recovery retry with the SAME batch key (idempotent, no double charge).
      await markPendingFailed(ids, reason);
      await pauseAdvertiserLineItems(adv.advertiser_id);
    }
    return { advertiser_id: adv.advertiser_id, status: "failed", reason, batch_id: batchId };
  }
}

// Resolve customer + PM for an advertiser. Shared by fresh charge (pre-reserve) and recovery.
async function resolveCustomerAndPm(
  adv: BatchAdvertiser,
): Promise<{ customerId: string; pm: string } | { skip: string } | { error: string }> {
  try {
    const stripe = getStripe();
    const customerId = await getOrCreateStripeCustomer(
      stripe, adv.advertiser_id, adv.advertiser_name ?? "", adv.stripe_customer_id,
    );
    const pmChoice = await resolvePaymentMethod(stripe, customerId);
    if ("skip" in pmChoice) return { skip: "no_payment_method" };
    return { customerId, pm: pmChoice.pm };
  } catch (err: unknown) {
    return { error: (err as { message?: string }).message ?? "unknown" };
  }
}

// FRESH charge from a plan: resolve PM FIRST (no PM ⇒ pause + skip WITHOUT reserving, so the groups
// stay in the view), then mint a batch, reserve, and settle.
async function chargeFreshBatch(plan: AdvertiserPlan): Promise<Record<string, unknown>> {
  const adv: BatchAdvertiser = {
    advertiser_id: plan.advertiser_id, advertiser_name: plan.advertiser_name,
    stripe_customer_id: plan.stripe_customer_id, is_house: false, billing_mode: "postpay",
  };
  const resolved = await resolveCustomerAndPm(adv);
  if ("skip" in resolved) {
    await pauseAdvertiserLineItems(plan.advertiser_id);
    return { advertiser_id: plan.advertiser_id, status: "skipped", reason: resolved.skip, group_count: plan.groups.length };
  }
  if ("error" in resolved) {
    return { advertiser_id: plan.advertiser_id, status: "failed", reason: resolved.error };
  }
  const batchId = crypto.randomUUID();
  await reservePending(plan.groups, plan.advertiser_id, batchId);
  return await settleReservedBatch(batchId, adv, resolved.customerId, resolved.pm);
}

// RECOVERY: finish a batch a crashed prior run left reserved. Resolve PM (no PM ⇒ leave pending for a
// later retry) and settle the SAME batch under its stable key — Stripe returns the same PI if one was
// already created, else creates it.
async function recoverBatch(batchId: string, adv: BatchAdvertiser): Promise<Record<string, unknown>> {
  const resolved = await resolveCustomerAndPm(adv);
  if ("skip" in resolved) {
    return { advertiser_id: adv.advertiser_id, status: "skipped", reason: resolved.skip, batch_id: batchId };
  }
  if ("error" in resolved) {
    return { advertiser_id: adv.advertiser_id, status: "failed", reason: resolved.error, batch_id: batchId };
  }
  return await settleReservedBatch(batchId, adv, resolved.customerId, resolved.pm);
}

// ---- Prepay draw-down settle (M9) -------------------------------------------
// Settle an already-reserved PREPAY batch by drawing down the advertiser's prepay credit instead of
// creating a Stripe PaymentIntent. The DB primitive app.advertiser_draw_down_batch is idempotent on
// charge_batch_id (a retry/recovery re-draws ONCE), atomic + never-negative (draws nothing when the
// balance is short), and fires the loud reserved_underflow / insufficient_balance alarms itself. On:
//   * drawn / duplicate  → mark the batch's rows succeeded via balance (stripe_charge_id NULL).
//   * insufficient       → pause the advertiser's line_items (stop serving) and LEAVE the batch
//                          pending+undrawn so a later run retries after a top-up (retryable, never
//                          terminal-fail — matching the Stripe ambiguous-error policy).
async function settlePrepayBatch(batchId: string, adv: BatchAdvertiser): Promise<Record<string, unknown>> {
  const chargeSet = await reselectByBatch(batchId);
  if (chargeSet.length === 0) {
    return { advertiser_id: adv.advertiser_id, status: "skipped", reason: "nothing_pending", batch_id: batchId };
  }
  const ids = chargeSet.map((g) => g.entry_group_id);

  // Defense: a prepay advertiser is never is_house (ensure_advertiser_user forces false), but never
  // draw a house/sentinel batch — release it back to the view (mirrors the Stripe invariant #1).
  if (adv.is_house) {
    await releaseBatch(ids);
    return { advertiser_id: adv.advertiser_id, status: "skipped", reason: "house_advertiser", batch_id: batchId };
  }

  const sumMicros = chargeSet.reduce((a, g) => a + Number(g.amount_micros), 0);

  // Draw down under the DB primitive (runs inside the caller's single-flight billing_lock).
  const draw = await serviceRpc("advertiser_draw_down_batch", {
    p_advertiser: adv.advertiser_id, p_batch: batchId, p_sum: sumMicros,
  });
  const res = (draw.data ?? {}) as { drawn?: boolean; reason?: string };

  if (draw.ok && (res.drawn === true || res.reason === "duplicate")) {
    // drawn now, OR already drawn by a prior run (recovery) — settle the reserved rows idempotently.
    await markPendingChargedBalance(ids);
    return {
      advertiser_id: adv.advertiser_id, status: "succeeded", settled_via: "balance",
      amount_micros: sumMicros, group_count: chargeSet.length, batch_id: batchId,
      ...(res.reason === "duplicate" ? { reason: "duplicate" } : {}),
    };
  }

  if (res.reason === "insufficient_balance") {
    // Solvency: the RPC already fired the loud critical alarm. Pause serving; leave the batch pending
    // (undrawn) for a retry after top-up. NOT terminal-failed — this is a fundable, retryable state.
    await pauseAdvertiserLineItems(adv.advertiser_id);
    return {
      advertiser_id: adv.advertiser_id, status: "skipped", reason: "insufficient_balance",
      amount_micros: sumMicros, group_count: chargeSet.length, batch_id: batchId,
    };
  }

  // nothing_to_draw / RPC error — leave the batch pending for a later retry (never charge twice).
  return {
    advertiser_id: adv.advertiser_id, status: "skipped",
    reason: res.reason ?? "draw_down_failed", batch_id: batchId,
  };
}

// FRESH prepay charge from a plan: no Stripe customer/PM resolution — mint a batch, reserve, draw down.
async function chargePrepayBatch(plan: AdvertiserPlan): Promise<Record<string, unknown>> {
  const adv: BatchAdvertiser = {
    advertiser_id: plan.advertiser_id, advertiser_name: plan.advertiser_name,
    stripe_customer_id: plan.stripe_customer_id, is_house: false, billing_mode: "prepay",
  };
  const batchId = crypto.randomUUID();
  await reservePending(plan.groups, plan.advertiser_id, batchId);
  return await settlePrepayBatch(batchId, adv);
}

interface UnchargedRow {
  entry_group_id:    string;
  event_type:        string;
  amount_micros:     number;
  impression_id:     string;
  line_item_id:      string;
  publisher_id:      string;
  campaign_id:       string;
  advertiser_id:     string;
  advertiser_name:   string;
  is_house:          boolean;
  stripe_customer_id: string | null;
  cleared_at:        string;
  billing_mode:      string;   // M9: 'prepay' routes to draw-down, not a Stripe PI
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: billingCors });

  const url  = new URL(req.url);
  const path = url.pathname;

  // All routes require a valid admin JWT.
  const adminAuth = await requireAdmin(req);
  if (!adminAuth) return jsonErr("Forbidden", 403);

  // ---- POST /charge (or /charge?dry_run=true) --------------------------------
  if (req.method === "POST" && path.endsWith("/charge")) {
    // Re-gate this money-mutating route to the aal2 money-admin tier: /charge creates real
    // advertiser Stripe charges, so a stolen aal1 magic-link session (which still passes the
    // top-level requireAdmin) must not reach it. There is no cron/automation caller for /charge
    // (only the auto-payout cron hits stripe-connect/payout/batch), so this does not break any
    // automation path. Read-only /reconcile stays on requireAdmin (membership is sufficient there).
    if (!(await requireMoneyAdmin(req))) return jsonErr("Forbidden", 403);

    const dryRun = url.searchParams.get("dry_run") === "true";

    // Fetch uncharged cleared entries (up to 500). Charges MUST aggregate per advertiser — a
    // €0.05/view advertiser never clears Stripe's 50-cent minimum per impression.
    const viewRes = await svc("GET", "uncharged_advertiser_billings", {
      query: "select=*&order=cleared_at.asc&limit=500",
    });
    if (!viewRes.ok) {
      return jsonErr("Failed to fetch uncharged billings", viewRes.status, viewRes.data);
    }
    const uncharged = (viewRes.data as UnchargedRow[]) ?? [];
    const plans = planAdvertiserCharges(uncharged);

    const results: Record<string, unknown>[] = [];

    // DRY-RUN: preview the per-advertiser plan without a lock, reserve, or Stripe call.
    if (dryRun) {
      for (const plan of plans) {
        if (plan.action === "skip_house") {
          for (const g of plan.groups) {
            results.push({
              entry_group_id: g.entry_group_id, advertiser_id: plan.advertiser_id,
              status: "skipped", reason: "house_advertiser",
              amount_micros: g.amount_micros, amount_cents: microsToCents(g.amount_micros),
            });
          }
        } else if (plan.action === "skip_below_min") {
          results.push({
            advertiser_id: plan.advertiser_id, status: "skipped", reason: "below_stripe_minimum",
            amount_micros: plan.sumMicros, amount_cents: plan.sumCents, group_count: plan.groups.length,
          });
        } else if (plan.action === "draw_prepay") {
          // Prepay has no Stripe minimum (exact-micros draw-down) — preview the intended draw.
          results.push({
            advertiser_id: plan.advertiser_id, advertiser_name: plan.advertiser_name,
            settled_via: "balance", amount_micros: plan.sumMicros, group_count: plan.groups.length,
            would_draw: true,
          });
        } else {
          results.push({
            advertiser_id: plan.advertiser_id, advertiser_name: plan.advertiser_name,
            amount_cents: plan.sumCents, group_count: plan.groups.length, would_charge: true,
          });
        }
      }
      return billingResponse(results, true);
    }

    // LIVE: single-flight lock (defense-in-depth atop per-group claiming) — one billing run at a time.
    const lockRes = await svc("POST", "rpc/billing_lock_acquire", { body: {} });
    const lockToken = lockRes.ok && typeof lockRes.data === "string" ? lockRes.data : null;
    if (!lockToken) {
      return jsonOk({
        charged: 0, processed: 0, dry_run: false, results: [], locked: true,
        counts: { succeeded: 0, skipped: 0, failed: 0, would_charge: 0 },
      });
    }

    try {
      // RECOVERY: settle EVERY existing pending batch (a crashed prior run's reserved-but-unsettled
      // rows), grouped by its stable charge_batch_id — independent of the fresh plans below, so a
      // pending batch is never stranded by a same-advertiser skip (adversarial review F3).
      const pendRes = await svc("GET", "advertiser_charges", {
        query: "status=eq.pending&stripe_charge_id=is.null&select=charge_batch_id,advertiser_id,entry_group_id&limit=1000",
      });
      const batches = partitionPendingByBatch(
        Array.isArray(pendRes.data)
          ? (pendRes.data as Array<{ charge_batch_id: string | null; advertiser_id: string; entry_group_id: string }>)
          : [],
      );
      for (const [batchId, batch] of batches) {
        if (!batchId) {
          // Legacy/malformed rows with no batch id: release to the view, never charge.
          await releaseBatch((batch.rows as Array<{ entry_group_id: string }>).map((r) => r.entry_group_id));
          results.push({ advertiser_id: batch.advertiser_id, status: "skipped", reason: "no_batch_id_released" });
          continue;
        }
        const advRes = await svc("GET", "advertisers", {
          query: `id=eq.${batch.advertiser_id}&select=name,stripe_customer_id,is_house,billing_mode&limit=1`,
        });
        const a = (Array.isArray(advRes.data) ? advRes.data[0] : null) as
          | { name?: string; stripe_customer_id?: string | null; is_house?: boolean; billing_mode?: string }
          | null;
        const recAdv: BatchAdvertiser = {
          advertiser_id: batch.advertiser_id, advertiser_name: a?.name ?? null,
          stripe_customer_id: a?.stripe_customer_id ?? null, is_house: a?.is_house === true,
          billing_mode: a?.billing_mode ?? "postpay",
        };
        // Route a recovered PREPAY batch to the draw-down (no Stripe PM), postpay to the Stripe path.
        results.push(
          recAdv.billing_mode === "prepay"
            ? await settlePrepayBatch(batchId, recAdv)
            : await recoverBatch(batchId, recAdv),
        );
      }

      // MAIN: fresh plans. Their charge groups are disjoint from any recovered batch (the view
      // excludes already-reserved groups), so no group is charged twice.
      for (const plan of plans) {
        if (plan.action === "skip_house") {
          // house/sentinel is never charged (invariant #1). Terminal-skip the stray groups.
          for (const g of plan.groups) {
            await insertCharge({
              entry_group_id: g.entry_group_id, advertiser_id: plan.advertiser_id,
              impression_id: g.impression_id, amount_micros: g.amount_micros,
              amount_cents: microsToCents(g.amount_micros), status: "skipped",
              failure_reason: "house_advertiser",
            });
            results.push({
              entry_group_id: g.entry_group_id, advertiser_id: plan.advertiser_id,
              status: "skipped", reason: "house_advertiser",
              amount_micros: g.amount_micros, amount_cents: microsToCents(g.amount_micros),
            });
          }
          continue;
        }
        if (plan.action === "skip_below_min") {
          // NON-terminal: write no row, the groups stay in the view and keep accumulating.
          results.push({
            advertiser_id: plan.advertiser_id, status: "skipped", reason: "below_stripe_minimum",
            amount_micros: plan.sumMicros, amount_cents: plan.sumCents, group_count: plan.groups.length,
          });
          continue;
        }
        if (plan.action === "draw_prepay") {
          // PREPAY: reserve + draw down the balance (no Stripe PI, no 50-cent minimum).
          results.push(await chargePrepayBatch({
            advertiser_id: plan.advertiser_id, advertiser_name: plan.advertiser_name,
            stripe_customer_id: plan.stripe_customer_id, groups: plan.groups,
          }));
          continue;
        }
        results.push(await chargeFreshBatch({
          advertiser_id: plan.advertiser_id, advertiser_name: plan.advertiser_name,
          stripe_customer_id: plan.stripe_customer_id, groups: plan.groups,
        }));
      }
    } finally {
      await svc("POST", "rpc/billing_lock_release", { body: { p_token: lockToken } });
    }

    return billingResponse(results, false);
  }

  // ---- GET /reconcile?from=ISO_DATE&to=ISO_DATE --------------------------------
  // Admin-only reconciliation: asserts sum(cleared advertiser_billing debits) ==
  // sum(succeeded Stripe PaymentIntents tagged source=lumaline) for the period.
  //
  // Only succeeded PaymentIntents count on the Stripe side — a declined card creates
  // a Charge/PI object with amount set but status≠succeeded, and should NOT be counted
  // (it signals a collection failure that should make the report red, not cancel the DB leg).
  //
  // Known structural limitation: ledger entries below the $0.50 Stripe minimum are cleared
  // in the DB but never charged in Stripe → always-red for periods containing sub-minimum
  // entries. House-advertiser entries are exempt: close_window() zeros their gross and
  // clear_events() filters gross_micros>0, so house impressions never produce ledger entries.
  if (req.method === "GET" && path.endsWith("/reconcile")) {
    const fromStr = url.searchParams.get("from");
    const toStr   = url.searchParams.get("to");
    if (!fromStr || !toStr) {
      return jsonErr("Missing required query params: from, to (ISO 8601)", 400);
    }
    const fromDate = new Date(fromStr);
    const toDate   = new Date(toStr);
    if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
      return jsonErr("Invalid date — use ISO 8601 (e.g. 2026-06-01T00:00:00Z)", 400);
    }
    const fromIso = fromDate.toISOString();
    const toIso   = toDate.toISOString();

    // 1. DB side — call billing_recon_totals via service-role REST RPC.
    const reconRes = await svc("POST", "rpc/billing_recon_totals", {
      body: { from_ts: fromIso, to_ts: toIso },
    });
    if (!reconRes.ok) {
      return jsonErr("DB reconcile query failed", reconRes.status, reconRes.data);
    }
    const reconRows =
      (reconRes.data as Array<{ total_micros: unknown; entry_count: unknown }>) ?? [];
    const dbTotalMicros = Number(reconRows[0]?.total_micros ?? 0);
    const dbCount       = Number(reconRows[0]?.entry_count  ?? 0);

    // 2. Stripe side — list succeeded PaymentIntents tagged source=lumaline in period.
    let stripe: Stripe;
    try {
      stripe = getStripe();
    } catch (err: unknown) {
      const msg = (err as { message?: string }).message ?? "Stripe not configured";
      return jsonErr(msg, 503);
    }

    const fromUnix = Math.floor(fromDate.getTime() / 1000);
    const toUnix   = Math.floor(toDate.getTime()   / 1000);

    let stripeTotalMicros = 0;
    let stripeCount       = 0;
    let hasMore           = true;
    let startingAfter: string | undefined;

    try {
      while (hasMore) {
        const params: Stripe.PaymentIntentListParams = {
          created: { gte: fromUnix, lte: toUnix },
          limit:   100,
        };
        if (startingAfter) params.starting_after = startingAfter;

        const page = await stripe.paymentIntents.list(params);

        for (const pi of page.data) {
          // Only count succeeded PIs tagged as LumaLine. A declined PI has amount set
          // but status !== 'succeeded' and must NOT inflate the Stripe total.
          if (pi.metadata?.source === "lumaline" && pi.status === "succeeded") {
            // pi.amount is Stripe cents; 1 cent = 10,000 micro-USD.
            stripeTotalMicros += pi.amount * 10000;
            stripeCount++;
          }
        }

        hasMore = page.has_more;
        if (hasMore && page.data.length > 0) {
          startingAfter = page.data[page.data.length - 1].id;
        } else {
          hasMore = false;
        }
      }
    } catch (err: unknown) {
      const msg = (err as { message?: string }).message ?? "Stripe list failed";
      return jsonErr(`Stripe error: ${msg}`, 502);
    }

    const discrepancyMicros = dbTotalMicros - stripeTotalMicros;

    return jsonOk({
      ok:                  discrepancyMicros === 0,
      period:              { from: fromIso, to: toIso },
      db_total_micros:     dbTotalMicros,
      stripe_total_micros: stripeTotalMicros,
      discrepancy_micros:  discrepancyMicros,
      db_count:            dbCount,
      stripe_count:        stripeCount,
    });
  }

  // ---- POST /refund -------------------------------------------------------
  // Admin-only: issue a Stripe refund for an approved clawback review.
  //
  // Flow:
  //   1. Fetch the clawback_review (must be approved, refund_queued=false).
  //   2. Find the advertiser_charges row for the linked impression (status=succeeded).
  //   3. Issue stripe.refunds.create({ payment_intent: pi_id, amount: cents, reason: 'fraudulent' }).
  //   4. Mark clawback_reviews.refund_queued=true + record the Stripe refund id.
  //
  // Uses payment_intent (pi_*) — not charge — because T4 stores the PaymentIntent id.
  // Amount comes from advertiser_charges.amount_cents (what was actually charged),
  // not recomputed from impression gross, to avoid rounding drift.
  if (req.method === "POST" && path.endsWith("/refund")) {
    // Re-gate this money-mutating route to the aal2 money-admin tier (the top-level
    // requireAdmin only proves app.admins membership; a refund moves real cash).
    const moneyAuth = await requireMoneyAdmin(req);
    if (!moneyAuth) return jsonErr("Forbidden", 403);

    let refundBody: Record<string, unknown> = {};
    try { refundBody = await req.json(); } catch { /* empty body ok */ }

    const reviewId = String(refundBody.review_id ?? "").trim();
    if (!reviewId) return jsonErr("review_id is required", 400);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(reviewId)) {
      return jsonErr("review_id must be a valid UUID", 400);
    }

    // 1. Fetch the clawback_review.
    const reviewRes = await svc("GET", "clawback_reviews", {
      query: `id=eq.${reviewId}&status=eq.approved&refund_queued=eq.false&select=*&limit=1`,
    });
    if (!reviewRes.ok) {
      return jsonErr("Failed to fetch clawback_review", reviewRes.status, reviewRes.data);
    }
    const reviewRows = reviewRes.data as Array<Record<string, unknown>>;
    if (!Array.isArray(reviewRows) || reviewRows.length === 0) {
      return jsonErr("Review not found, not approved, or refund already queued", 404);
    }
    const review = reviewRows[0];
    const impressionId = review.impression_id as string | null;
    if (!impressionId) {
      return jsonErr("Review has no linked impression — cannot refund", 422);
    }

    // 2. Find the succeeded charge for this impression.
    const chargeRes = await svc("GET", "advertiser_charges", {
      query: `impression_id=eq.${impressionId}&status=eq.succeeded&select=stripe_charge_id,amount_cents,settled_via&limit=1`,
    });
    if (!chargeRes.ok) {
      return jsonErr("Failed to fetch advertiser_charges", chargeRes.status, chargeRes.data);
    }
    const chargeRows = chargeRes.data as Array<Record<string, unknown>>;
    if (!Array.isArray(chargeRows) || chargeRows.length === 0) {
      return jsonErr("No succeeded charge found for this impression — nothing to refund", 404);
    }
    const charge = chargeRows[0];
    const piId        = charge.stripe_charge_id as string | null;
    const amountCents = Number(charge.amount_cents ?? 0);
    const settledVia  = (charge.settled_via as string | null) ?? "stripe";

    // BALANCE-settled (prepay draw-down): NEVER a Stripe refund — route to admin_prepay_clawback,
    // which reverses the accrual AND re-credits the advertiser's prepay balance (zero-sum). Forward
    // the caller's aal2 money-admin bearer so the RPC's in-body is_money_admin() gate passes (a
    // service_role call would fail it). This is the "branch on settled_via, never both" refund fix.
    if (settledVia === "balance") {
      const { status, text } = await forwardRpc(
        "admin_prepay_clawback",
        { p_impression_id: impressionId, p_reason: `refund:review_${reviewId}` },
        moneyAuth,
      );
      if (status !== 200) {
        return jsonErr("Balance clawback failed", status === 403 ? 403 : 502, text);
      }
      let cb: Record<string, unknown> = {};
      try { cb = JSON.parse(text); } catch { /* non-JSON body */ }
      if (cb.ok === false) {
        // A guarded refusal (payout_active / earning_already_paid) — surface it, do NOT queue.
        return jsonOk({ ok: false, settled_via: "balance", clawback: cb, impression_id: impressionId }, 200);
      }
      await svc("PATCH", "clawback_reviews", {
        body:   { refund_queued: true },
        query:  `id=eq.${reviewId}`,
        prefer: "return=minimal",
      });
      return jsonOk({ ok: true, settled_via: "balance", clawback: cb, impression_id: impressionId });
    }

    if (!piId) {
      return jsonErr("Stripe PaymentIntent id missing on advertiser_charges row", 422);
    }
    if (amountCents <= 0) {
      return jsonErr("Charge amount is zero or negative — cannot refund", 422);
    }

    // 3. Issue the Stripe refund.
    let stripe: Stripe;
    try {
      stripe = getStripe();
    } catch (err: unknown) {
      const msg = (err as { message?: string }).message ?? "Stripe not configured";
      return jsonErr(msg, 503);
    }

    let refund: { id: string };
    try {
      refund = await stripe.refunds.create({
        payment_intent: piId,
        amount:         amountCents,
        reason:         "fraudulent",
      }, { idempotencyKey: `lumaline_refund_${reviewId}` });
    } catch (err: unknown) {
      const msg = (err as { message?: string }).message ?? "Stripe refund failed";
      return jsonErr(`Stripe refund error: ${msg}`, 502);
    }

    // 4. Mark the review as refund-queued.
    await svc("PATCH", "clawback_reviews", {
      body:   { refund_queued: true, refund_id: refund.id },
      query:  `id=eq.${reviewId}`,
      prefer: "return=minimal",
    });

    return jsonOk({
      ok:           true,
      refund_id:    refund.id,
      amount_cents: amountCents,
      impression_id: impressionId,
    });
  }

  // ---- POST /setup-link -----------------------------------------------------
  // Admin-only: create a Stripe Checkout Session in SETUP mode so an advertiser can
  // save a card for future off-session billing. Body: { advertiser_id }.
  //
  // NOTE: Checkout setup mode ATTACHES the resulting payment method to the customer,
  // so choosePaymentMethod's first-attached branch finds it on the very next billing
  // run — no webhook handling is needed to close the loop. (Setting it as the
  // invoice_settings default is optional polish; first-attached already suffices.)
  if (req.method === "POST" && path.endsWith("/setup-link")) {
    let setupBody: Record<string, unknown> = {};
    try { setupBody = await req.json(); } catch { /* empty body ok */ }

    const advertiserId = String(setupBody.advertiser_id ?? "").trim();
    if (!advertiserId) return jsonErr("advertiser_id is required", 400);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(advertiserId)) {
      return jsonErr("advertiser_id must be a valid UUID", 400);
    }

    // Fetch the advertiser (need name + any existing stripe_customer_id).
    const advRes = await svc("GET", "advertisers", {
      query: `id=eq.${advertiserId}&select=id,name,stripe_customer_id&limit=1`,
    });
    if (!advRes.ok) {
      return jsonErr("Failed to fetch advertiser", advRes.status, advRes.data);
    }
    const advRows = advRes.data as Array<Record<string, unknown>>;
    if (!Array.isArray(advRows) || advRows.length === 0) {
      return jsonErr("Advertiser not found", 404);
    }
    const advertiser = advRows[0];

    let stripe: Stripe;
    try {
      stripe = getStripe();
    } catch (err: unknown) {
      const msg = (err as { message?: string }).message ?? "Stripe not configured";
      return jsonErr(msg, 503);
    }

    try {
      // Reuse the same get-or-create helper as the /charge loop (persists the id).
      const customerId = await getOrCreateStripeCustomer(
        stripe,
        advertiserId,
        String(advertiser.name ?? ""),
        (advertiser.stripe_customer_id as string | null) ?? null,
      );

      const session = await stripe.checkout.sessions.create({
        mode:                 "setup",
        customer:             customerId,
        payment_method_types: ["card"],
        success_url:          "https://lumaline.dev/?billing-setup=success",
        cancel_url:           "https://lumaline.dev/?billing-setup=cancelled",
        metadata:             { source: "lumaline", advertiser_id: advertiserId },
      });

      return jsonOk({ url: session.url, session_id: session.id });
    } catch (err: unknown) {
      const msg = (err as { message?: string }).message ?? "Stripe setup session failed";
      return jsonErr(`Stripe error: ${msg}`, 502);
    }
  }

  return jsonErr("Not found", 404);
});
