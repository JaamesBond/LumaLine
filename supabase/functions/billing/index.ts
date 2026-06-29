// supabase/functions/billing/index.ts
// Admin-triggered billing cycle: idempotent Stripe charges for cleared advertiser
// ledger entries that have not yet been billed. M2-T4.
//
// Endpoints:
//   POST /functions/v1/billing/charge              — run billing cycle (admin-only)
//   POST /functions/v1/billing/charge?dry_run=true — preview plan, no Stripe calls
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
//      d. Create+confirm PaymentIntent (test mode: pm_card_visa).
//         Idempotency key: lumaline_grp_{entry_group_id} — safe to re-run.
//      e. Insert into advertiser_charges (UNIQUE on entry_group_id = idempotency backstop).
//      f. On card_declined: pause all line_items for this advertiser.
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
  SUPABASE_URL,
  SERVICE_ROLE_KEY,
} from "../_shared/jwt.ts";
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno";

const billingCors = {
  ...corsHeaders,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
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

// Convert micro-USD to Stripe cents.
// 1 USD = 1,000,000 micro-USD = 100 cents → 1 cent = 10,000 micro-USD.
export function microsToCents(micros: number): number {
  return Math.round(micros / 10000);
}

// Idempotency key for a billing group — stable across re-runs of the billing cycle.
export function idempotencyKey(entryGroupId: string): string {
  return `lumaline_grp_${entryGroupId}`;
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
    const dryRun = url.searchParams.get("dry_run") === "true";

    // Fetch all uncharged cleared entries from the view (up to 200 per run).
    const viewRes = await svc("GET", "uncharged_advertiser_billings", {
      query: "select=*&order=cleared_at.asc&limit=200",
    });
    if (!viewRes.ok) {
      return jsonErr("Failed to fetch uncharged billings", viewRes.status, viewRes.data);
    }
    const uncharged = (viewRes.data as UnchargedRow[]) ?? [];

    const results: Record<string, unknown>[] = [];

    for (const entry of uncharged) {
      const amountCents = microsToCents(entry.amount_micros);

      // TRUST INVARIANT #1: house/sentinel advertisers are never charged.
      if (entry.is_house) {
        const record = {
          entry_group_id: entry.entry_group_id,
          advertiser_id:  entry.advertiser_id,
          status:         "skipped",
          reason:         "house_advertiser",
          amount_micros:  entry.amount_micros,
          amount_cents:   amountCents,
        };
        if (!dryRun) {
          await insertCharge({
            entry_group_id: entry.entry_group_id,
            advertiser_id:  entry.advertiser_id,
            impression_id:  entry.impression_id,
            amount_micros:  entry.amount_micros,
            amount_cents:   amountCents,
            status:         "skipped",
            failure_reason: "house_advertiser",
          });
        }
        results.push(record);
        continue;
      }

      // Below Stripe minimum ($0.50 = 50 cents = 500,000 micro-USD).
      if (amountCents < 50) {
        const record = {
          entry_group_id: entry.entry_group_id,
          advertiser_id:  entry.advertiser_id,
          status:         "skipped",
          reason:         "below_stripe_minimum",
          amount_micros:  entry.amount_micros,
          amount_cents:   amountCents,
        };
        if (!dryRun) {
          await insertCharge({
            entry_group_id: entry.entry_group_id,
            advertiser_id:  entry.advertiser_id,
            impression_id:  entry.impression_id,
            amount_micros:  entry.amount_micros,
            amount_cents:   amountCents,
            status:         "skipped",
            failure_reason: "below_stripe_minimum",
          });
        }
        results.push(record);
        continue;
      }

      // Dry-run: report what would be charged without hitting Stripe.
      if (dryRun) {
        results.push({
          entry_group_id:   entry.entry_group_id,
          advertiser_id:    entry.advertiser_id,
          advertiser_name:  entry.advertiser_name,
          amount_cents:     amountCents,
          idempotency_key:  idempotencyKey(entry.entry_group_id),
          would_charge:     true,
        });
        continue;
      }

      // ---- Real Stripe charge path ----------------------------------------
      let customerId = entry.stripe_customer_id;

      try {
        const stripe = getStripe();

        // Get or create a Stripe customer for this advertiser.
        if (!customerId) {
          const customer = await stripe.customers.create({
            name:     entry.advertiser_name,
            metadata: { advertiser_id: entry.advertiser_id },
          });
          customerId = customer.id;
          // Persist the customer ID so future charges skip the create step.
          await svc("PATCH", "advertisers", {
            body:   { stripe_customer_id: customerId },
            query:  `id=eq.${entry.advertiser_id}`,
            prefer: "return=minimal",
          });
        }

        // Create and confirm PaymentIntent.
        // Idempotency key: stable per entry_group_id → re-runs return the same intent.
        const intent = await stripe.paymentIntents.create(
          {
            amount:         amountCents,
            currency:       "usd",
            customer:       customerId,
            payment_method: "pm_card_visa",  // test mode only
            confirm:        true,
            off_session:    true,
            description:    `LumaLine impression ${entry.impression_id}`,
            metadata: {
              impression_id:  entry.impression_id,
              entry_group_id: entry.entry_group_id,
              advertiser_id:  entry.advertiser_id,
              publisher_id:   entry.publisher_id,
            },
          },
          { idempotencyKey: idempotencyKey(entry.entry_group_id) },
        );

        await insertCharge({
          entry_group_id:    entry.entry_group_id,
          advertiser_id:     entry.advertiser_id,
          impression_id:     entry.impression_id,
          amount_micros:     entry.amount_micros,
          amount_cents:      amountCents,
          stripe_charge_id:  intent.id,
          stripe_customer_id: customerId,
          status:            "succeeded",
        });

        results.push({
          entry_group_id: entry.entry_group_id,
          status:         "succeeded",
          stripe_id:      intent.id,
          amount_cents:   amountCents,
        });
      } catch (err: unknown) {
        const stripeErr = err as { code?: string; type?: string; message?: string };
        const isDecline =
          stripeErr.code === "card_declined" || stripeErr.type === "StripeCardError";

        await insertCharge({
          entry_group_id: entry.entry_group_id,
          advertiser_id:  entry.advertiser_id,
          impression_id:  entry.impression_id,
          amount_micros:  entry.amount_micros,
          amount_cents:   amountCents,
          status:         "failed",
          failure_reason: stripeErr.message ?? "unknown",
        });

        results.push({
          entry_group_id: entry.entry_group_id,
          status:         "failed",
          reason:         stripeErr.message ?? "unknown",
        });

        // Pause all line_items for this advertiser on card decline.
        if (isDecline) {
          const campsRes = await svc("GET", "campaigns", {
            query: `advertiser_id=eq.${entry.advertiser_id}&select=id`,
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
      }
    }

    return jsonOk({
      charged:  results.length,
      dry_run:  dryRun,
      results,
    });
  }

  return jsonErr("Not found", 404);
});
