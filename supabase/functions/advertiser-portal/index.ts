// supabase/functions/advertiser-portal/index.ts
// LumaLine advertiser prepay funding surface (M9-T9). This edge fn owns ONLY the advertiser Stripe
// deposit path — funding/checkout + the deposit webhook. Every other advertiser read/CRUD goes DIRECT
// via PostgREST rpc()/from() under RLS (no edge proxy), matching the publisher/admin Scheme-A shape.
//
// Endpoints:
//   POST /advertiser-portal/funding/checkout   — auth advertiser (aal1): open a card-only Stripe
//                                                 Checkout session for a prepay top-up. The depositing
//                                                 advertiser is resolved SOLELY from the caller's JWT
//                                                 (public.advertiser_deposit_self_id, which also
//                                                 REFUSES an ERASED org — GDPR P2); a body
//                                                 advertiser_id is IGNORED. A server-stored
//                                                 advertiser_topup_intents row (keyed by the session
//                                                 id) is the authority for WHICH advertiser the
//                                                 deposit credits — never event metadata.
//   POST /advertiser-portal/webhook            — UNAUTHENTICATED (Stripe signature IS the auth): raw-body
//                                                 multi-secret verify + stripe_webhook_events dedup.
//                                                 CREDIT only on checkout.session.completed with
//                                                 payment_status='paid' (card-only ⇒ the PI succeeded);
//                                                 a 'processing'/unpaid session credits NOTHING. REVERSE
//                                                 (bad-debt) on charge.dispute.*/charge.refunded.
//
// MONEY-SAFETY (mirrors billing/stripe-connect):
//   1. Signature verified over the RAW body (req.text(), never req.json() first), multi-secret.
//   2. Deposits credited ONLY on a verified capture, resolving the advertiser from the server-stored
//      topup_intent (NOT client/event metadata) — a checkout body carrying a foreign advertiser_id
//      credits the caller's OWN balance, never the foreign one (the resolver is JWT-derived).
//      GDPR P2: an ERASED advertiser is refused at checkout, BEFORE any Stripe session exists — a
//      post-capture refusal would strand a real charge with no credit (20260726120000 §2).
//   3. Card-only Checkout (payment_method_types=['card']) — immediate capture, so a delayed/failed
//      EUR method (SEPA) can never fund delivery before cash is captured (billing's card-only invariant).
//   4. Idempotent: dedup on Stripe event id + UNIQUE(pi_id) (credit) / UNIQUE(dispute_id) (reversal)
//      in the DB primitives. A replayed webhook is a no-op.
//   5. The advertiser Stripe endpoint secret (ADVERTISER_STRIPE_WEBHOOK_SECRET) is SEPARATE from
//      payouts' STRIPE_WEBHOOK_SECRET (isolation).

import { corsHeaders } from "../_shared/cors.ts";
import {
  bearerHeader,
  forwardRpc,
  serviceRpc,
  SUPABASE_URL,
  SERVICE_ROLE_KEY,
} from "../_shared/jwt.ts";
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno";
import { parseWebhookSecrets } from "../_shared/webhook-secrets.mjs";
import {
  evaluateDepositEvent,
  isAdvertiserDisputeEvent,
  isAdvertiserRefundEvent,
  reversalTargetMicros,
  piIdOf,
} from "../_shared/advertiser-logic.mjs";
import { errorResponseBody, errorDetailEnabled } from "../_shared/http-errors.mjs";

const cors = { ...corsHeaders, "Access-Control-Allow-Methods": "POST, OPTIONS" } as const;

function jsonOk(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });
}
const DEBUG_ERRORS = errorDetailEnabled(Deno.env);
function jsonErr(message: string, status: number, detail?: unknown): Response {
  if (detail !== undefined && detail !== null) {
    try { console.error(`jsonErr ${status}: ${message}`, detail); } catch { /* ignore */ }
  }
  const body = errorResponseBody(message, detail, DEBUG_ERRORS);
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "content-type": "application/json" } });
}

// EUR-micros: 1 EUR = 1,000,000 micros = 100 cents. Card-only, EUR end-to-end (RO platform).
const DEPOSIT_CURRENCY = "eur";
// Owner-tunable deposit bounds (T14). Conservative defaults in EUR-micros.
const MIN_DEPOSIT_MICROS = Number(Deno.env.get("ADVERTISER_MIN_DEPOSIT_MICROS") ?? 5_000_000);   //  €5
const MAX_DEPOSIT_MICROS = Number(Deno.env.get("ADVERTISER_MAX_DEPOSIT_MICROS") ?? 5_000_000_000); // €5000
// Public app URL for the hosted-Checkout return/cancel (hardcoded internal path — no client redirect).
const APP_URL = Deno.env.get("LUMALINE_APP_URL") ?? "http://localhost:3000";

// Service-role REST helper — bypasses RLS, same shape as billing/stripe-connect.
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

// Lazy Stripe — boot without a key so the webhook signature-config path and unit tests work.
let _stripe: Stripe | null = null;
function getStripe(): Stripe {
  if (_stripe) return _stripe;
  const key = Deno.env.get("STRIPE_SECRET_KEY") ?? "";
  if (!key) throw new Error("STRIPE_SECRET_KEY is not configured");
  if (Deno.env.get("STRIPE_ASSERT_TEST") === "true" && !key.startsWith("sk_test_")) {
    throw new Error("STRIPE_SECRET_KEY must be a test key when STRIPE_ASSERT_TEST=true");
  }
  _stripe = new Stripe(key, { apiVersion: "2024-04-10", httpClient: Stripe.createFetchHttpClient() });
  return _stripe;
}

// Resolve the CALLER's own advertiser id from their JWT via public.advertiser_deposit_self_id
// (SECDEF). forwardRpc runs it with the caller's bearer, so a client-passed advertiser_id can never
// influence the result — the whole point (a foreign body id credits nothing).
//
// GDPR P2: the deposit path resolves through advertiser_deposit_self_id, NOT advertiser_self_id.
// The two differ only in that the deposit variant RAISES account_deleted (55000) once the org is
// erased, so an erased account can never open a Checkout session and fund a balance that
// structurally can never serve (window_open excludes deleted_at orgs). The rule lives in SQL
// (20260726120000 §2) — this function only surfaces the database's refusal. advertiser_self_id
// stays ungated for the read-only surfaces, which remain reachable after erasure.
//
// Returns the id, or a discriminated refusal: "none" (session maps to no org) / "erased".
async function callerAdvertiserId(
  auth: string,
): Promise<{ id: string } | { refusal: "none" | "erased" }> {
  const { status, text } = await forwardRpc("advertiser_deposit_self_id", {}, auth);
  if (status !== 200) {
    // The erased refusal must be distinguishable from "not an advertiser" — telling a data subject
    // their deposit failed for an unrelated reason would be a worse answer than the truth.
    return { refusal: /account_deleted/.test(text) ? "erased" : "none" };
  }
  try {
    const v = JSON.parse(text);
    return typeof v === "string" && v.length > 0 ? { id: v } : { refusal: "none" };
  } catch {
    return { refusal: "none" };
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const url = new URL(req.url);
  const path = url.pathname;

  // ---- POST /webhook (UNAUTHENTICATED — Stripe calls it; the signature IS the auth) --------------
  // MUST run before any auth gate and MUST read the raw body for signature verification.
  if (req.method === "POST" && path.endsWith("/webhook")) {
    const sig = req.headers.get("stripe-signature");
    if (!sig) return jsonErr("Missing Stripe-Signature", 400);

    // The advertiser deposit endpoint secret is SEPARATE from payouts (isolation). Multi-secret list.
    const secrets = parseWebhookSecrets(Deno.env.get("ADVERTISER_STRIPE_WEBHOOK_SECRET") ?? "");
    if (secrets.length === 0) return jsonErr("Webhook secret not configured", 503);

    const raw = await req.text(); // raw body, never req.json() first
    let event: Stripe.Event | null = null;
    let lastErr = "bad signature";
    for (const secret of secrets) {
      try { event = await getStripe().webhooks.constructEventAsync(raw, sig, secret); break; }
      catch (err: unknown) { lastErr = (err as { message?: string }).message ?? "bad signature"; }
    }
    if (!event) return jsonErr(`Signature verification failed: ${lastErr}`, 400);

    // Dedup: CHECK first, RECORD only after the handler succeeds (a handler/infra failure must leave
    // NO dedup row so Stripe's retry is not turned into a permanent no-op). The DB primitives are
    // independently idempotent (UNIQUE pi_id / dispute_id), so a replay before the record is harmless.
    const seen = await svc("GET", "stripe_webhook_events", {
      query: `event_id=eq.${encodeURIComponent(event.id)}&fn=eq.advertiser-portal&select=event_id&limit=1`,
    });
    if (seen.ok && Array.isArray(seen.data) && (seen.data as unknown[]).length > 0) {
      return jsonOk({ ok: true, duplicate: true, type: event.type });
    }

    let handled: Record<string, unknown>;
    try {
      const decision = evaluateDepositEvent(event);
      if (decision.action === "credit") {
        // Resolve the advertiser from the SERVER-STORED topup_intent (keyed by session id) — NEVER
        // the event/session metadata. The credited amount is the intent's stored amount, so a
        // tampered session cannot over-credit.
        const sessionId = decision.sessionId;
        const piId = decision.piId;
        if (!sessionId || !piId) {
          handled = { type: event.type, credited: false, reason: "missing_session_or_pi" };
        } else {
          const tiRes = await svc("GET", "advertiser_topup_intents", {
            query: `checkout_session_id=eq.${encodeURIComponent(sessionId)}&select=advertiser_id,amount_micros&limit=1`,
          });
          if (!tiRes.ok) return jsonErr("topup_intent lookup failed", 502, tiRes.data);   // transient → Stripe retries
          const ti = (Array.isArray(tiRes.data) ? tiRes.data[0] : null) as
            | { advertiser_id?: string; amount_micros?: number } | null;
          if (!ti?.advertiser_id) {
            handled = { type: event.type, credited: false, reason: "no_topup_intent" };
          } else {
            const credit = await serviceRpc("advertiser_credit_deposit", {
              p_advertiser: ti.advertiser_id,
              p_session_id: sessionId,
              p_pi_id: piId,
              p_event_id: event.id,
              p_amount: Number(ti.amount_micros ?? 0),
            });
            if (!credit.ok) return jsonErr("deposit credit failed", 502, credit.data);
            handled = { type: event.type, credit: credit.data };
          }
        }
      } else if (isAdvertiserDisputeEvent(event.type)) {
        // Reverse (bad-debt) a disputed/refunded deposit. Resolve the advertiser from the deposit
        // sub-ledger row keyed by the disputed PaymentIntent — never metadata. Idempotent on dispute_id.
        const obj = event.data.object as Record<string, unknown>;
        const piId = piIdOf(obj.payment_intent);
        if (!piId) {
          handled = { type: event.type, reversed: false, reason: "no_payment_intent" };
        } else {
          const depRes = await svc("GET", "advertiser_balance_ledger", {
            query: `stripe_payment_intent_id=eq.${encodeURIComponent(piId)}&kind=eq.deposit&select=advertiser_id,amount_micros&limit=1`,
          });
          if (!depRes.ok) return jsonErr("deposit lookup failed", 502, depRes.data);   // transient → Stripe retries
          const dep = (Array.isArray(depRes.data) ? depRes.data[0] : null) as
            | { advertiser_id?: string; amount_micros?: number } | null;
          if (!dep?.advertiser_id) {
            handled = { type: event.type, reversed: false, reason: "no_matching_deposit" };
          } else if (isAdvertiserRefundEvent(event.type)) {
            // REFUND (partial-capable): obj is a Charge; obj.amount_refunded is the CUMULATIVE
            // refunded amount. Book only the DELTA over what this PI has already reversed (mirrors
            // payout_reverse). Using obj.amount (the full charge) reverses the whole deposit on a
            // partial refund. Per-PI cumulative dedup lives in the RPC: a replay -> delta 0 -> no-op.
            const cumulativeMicros = reversalTargetMicros(event.type, obj);
            if (cumulativeMicros <= 0) {
              handled = { type: event.type, reversed: false, reason: "zero_refund_amount" };
            } else {
              const rev = await serviceRpc("advertiser_apply_deposit_refund", {
                p_advertiser: dep.advertiser_id,
                p_pi_id: piId,
                p_event_id: event.id,
                p_cumulative_micros: cumulativeMicros,
              });
              if (!rev.ok) return jsonErr("deposit refund reversal failed", 502, rev.data);
              handled = { type: event.type, refund: rev.data };
            }
          } else {
            // DISPUTE/chargeback: obj is a Dispute; obj.amount is the disputed amount. Idempotent on
            // the dispute id inside the RPC. Fall back to the full deposit if amount is absent.
            const disputedMicros = reversalTargetMicros(event.type, obj);
            const rMicros = disputedMicros > 0 ? disputedMicros : Number(dep.amount_micros ?? 0);
            const disputeId = String(obj.id ?? `${event.type}:${piId}`);
            const rev = await serviceRpc("advertiser_apply_deposit_reversal", {
              p_advertiser: dep.advertiser_id,
              p_dispute_id: disputeId,
              p_amount: rMicros,
            });
            if (!rev.ok) return jsonErr("deposit reversal failed", 502, rev.data);
            // The reversal RPC already pauses the advertiser's active line_items (stops serving). The
            // downstream publisher-payout hold for the exposure window is an ops follow-up (T14).
            handled = { type: event.type, reversal: rev.data };
          }
        }
      } else {
        // Non-crediting event (e.g. a 'processing' PI, an unpaid session, an unrelated type).
        handled = { type: event.type, handled: false, reason: decision.reason };
      }
    } catch (err: unknown) {
      // Infra exception → 5xx, no dedup row → Stripe retries.
      return jsonErr(`Webhook handler error: ${(err as { message?: string }).message ?? "unknown"}`, 500);
    }

    await svc("POST", "stripe_webhook_events", {
      body: { event_id: event.id, type: event.type, fn: "advertiser-portal" },
      query: "on_conflict=event_id,fn",
      prefer: "return=minimal,resolution=ignore-duplicates",
    });
    return jsonOk({ ok: true, ...handled });
  }

  // ---- POST /funding/checkout (auth advertiser, aal1) --------------------------------------------
  if (req.method === "POST" && path.endsWith("/funding/checkout")) {
    const auth = bearerHeader(req);
    if (!auth) return jsonErr("Unauthorized", 401);

    // The depositing advertiser is resolved SOLELY from the caller's JWT — a body advertiser_id is
    // ignored. Deposits are fine at aal1 (money moves Stripe-side; a foreign body id credits nothing).
    // The erasure gate is enforced by the RPC itself and refuses BEFORE the Stripe session is
    // created, so an erased org is never charged for credit it could never spend.
    const caller = await callerAdvertiserId(auth);
    if ("refusal" in caller) {
      return caller.refusal === "erased"
        ? jsonErr("account_deleted: this advertiser account has been erased and can no longer be funded", 403)
        : jsonErr("No advertiser for this token", 403);
    }
    const advertiserId = caller.id;

    let body: Record<string, unknown> = {};
    try { body = await req.json(); } catch { /* empty body ok */ }

    // Amount is server-validated. Accept amount_micros (the frontend parses euros → micros for the
    // body only; the server is authoritative). Reject non-integer / out-of-bounds.
    const amountMicros = Math.trunc(Number(body.amount_micros ?? NaN));
    if (!Number.isFinite(amountMicros) || amountMicros <= 0) {
      return jsonErr("amount_micros must be a positive integer (EUR-micros)", 400);
    }
    if (amountMicros < MIN_DEPOSIT_MICROS || amountMicros > MAX_DEPOSIT_MICROS) {
      return jsonErr(
        `amount out of range (min ${MIN_DEPOSIT_MICROS}, max ${MAX_DEPOSIT_MICROS} micros)`, 422,
      );
    }
    // Stripe unit is whole cents; a deposit must be a whole number of cents.
    if (amountMicros % 10000 !== 0) {
      return jsonErr("amount must be a whole number of cents", 400);
    }
    const amountCents = amountMicros / 10000;

    let stripe: Stripe;
    try { stripe = getStripe(); } catch (err) { return jsonErr((err as { message?: string }).message ?? "Stripe not configured", 503); }

    try {
      const session = await stripe.checkout.sessions.create({
        mode: "payment",
        payment_method_types: ["card"], // card-only: immediate capture (no delayed SEPA funding)
        line_items: [{
          price_data: {
            currency: DEPOSIT_CURRENCY,
            product_data: { name: "LumaLine ad credit (prepaid, non-refundable)" },
            unit_amount: amountCents,
          },
          quantity: 1,
        }],
        // Server-derived advertiser id in metadata (audit only — the topup_intent row is the credit
        // authority). kind isolates advertiser top-ups from CPVA charges in Stripe.
        metadata: { kind: "advertiser_topup", advertiser_id: advertiserId },
        payment_intent_data: {
          metadata: { kind: "advertiser_topup", advertiser_id: advertiserId },
        },
        success_url: `${APP_URL}/advertiser/funding/return?status=success`,
        cancel_url: `${APP_URL}/advertiser/funding/return?status=cancelled`,
      });

      // Stamp the server-stored authority row: THIS advertiser owns THIS session's deposit. The
      // webhook credits from here, never from event metadata.
      const ins = await svc("POST", "advertiser_topup_intents", {
        body: {
          checkout_session_id: session.id,
          advertiser_id: advertiserId,
          amount_micros: amountMicros,
          status: "pending",
        },
        prefer: "return=minimal",
      });
      if (!ins.ok && ins.status !== 409) {
        return jsonErr("Failed to record top-up intent", 502, ins.data);
      }

      return jsonOk({ checkout_url: session.url, session_id: session.id });
    } catch (err: unknown) {
      return jsonErr(`Stripe checkout error: ${(err as { message?: string }).message ?? "unknown"}`, 502);
    }
  }

  return jsonErr("Not found", 404);
});
