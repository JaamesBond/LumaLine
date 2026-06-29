// supabase/functions/admin-booking/index.ts
// Admin-only edge function for ad booking (M2-T3).
//
// Endpoints:
//   POST   /admin-booking/advertisers              — create advertiser {name}
//   GET    /admin-booking/advertisers              — list advertisers
//   POST   /admin-booking/campaigns               — create campaign {advertiser_id, name}
//   POST   /admin-booking/line-items              — create line_item
//   GET    /admin-booking/line-items              — list line_items
//   POST   /admin-booking/creatives               — create creative {line_item_id, line, ...}
//   PATCH  /admin-booking/creatives/:id/activate  — move creative+line_item+campaign → active
//
// ADMIN AUTH: caller must present a valid Supabase Auth JWT whose sub is in app.admins.
// Uses forwardRpc('admin_check') — PostgREST verifies the JWT natively (no
// SUPABASE_JWT_SECRET dependency in edge runtime) and admin_check() delegates to
// app.is_admin() → app.admins. Non-admin or missing bearer: 403.
//
// TRUST INVARIANTS (non-negotiable):
//   * The admin gate (forwardRpc admin_check) is the trust boundary for all mutations.
//     All mutations use service-role to bypass RLS, so the gate must be airtight.
//   * The is_house CHECK from M2-T2 still fires even through this interface (PostgREST
//     enforces it at the DB layer — the edge function cannot bypass it).
//   * Activate moves status → active only; it does NOT touch billing or ledger rows.
//   * Advertiser status ('active'/'suspended') defaults to 'active' at creation.
//     The activate endpoint does not touch advertiser status — that is an ops action.

import { corsHeaders } from "../_shared/cors.ts";
import {
  bearerHeader,
  forwardRpc,
  SUPABASE_URL,
  SERVICE_ROLE_KEY,
} from "../_shared/jwt.ts";

// Extended CORS headers — admin-booking uses PATCH (/creatives/:id/activate).
// We define local headers rather than modifying _shared/cors.ts to avoid breaking
// other functions that have no PATCH routes.
const bookingCors = {
  ...corsHeaders,
  "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
} as const;

function jsonOk(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...bookingCors, "content-type": "application/json" },
  });
}

function jsonErr(message: string, status: number, detail?: unknown): Response {
  const body: Record<string, unknown> = { error: message };
  if (detail !== undefined && detail !== null) body.detail = detail;
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...bookingCors, "content-type": "application/json" },
  });
}

// Service-role REST helper — bypasses RLS, operates on public schema tables.
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
  try { data = await resp.json(); } catch { /* empty body fine */ }
  return { ok: resp.ok, status: resp.status, data };
}

// Admin guard — returns the raw bearer header string if the caller is admin, null otherwise.
// Forwards the bearer to PostgREST so it verifies the JWT natively (no SUPABASE_JWT_SECRET
// dependency in the edge runtime). PostgREST then calls admin_check() which delegates to
// app.is_admin() — the DB is the single authority.
async function requireAdmin(req: Request): Promise<string | null> {
  const auth = bearerHeader(req);
  if (!auth) return null;
  const { status, text } = await forwardRpc("admin_check", {}, auth);
  return status === 200 && text.trim() === "true" ? auth : null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: bookingCors });

  const path = new URL(req.url).pathname;

  // Admin auth gate — all routes require a valid admin JWT.
  const adminAuth = await requireAdmin(req);
  if (!adminAuth) return jsonErr("Forbidden", 403);

  // ---- PATCH /creatives/:id/activate ----------------------------------------
  // Move the creative (and its chain: line_item, campaign) from draft/pending_review → active.
  // Advertiser defaults to 'active' at creation; ops-level suspend/activate is out of scope here.
  const activateMatch = path.match(/\/creatives\/([0-9a-f-]+)\/activate$/i);
  if (req.method === "PATCH" && activateMatch) {
    const creativeId = activateMatch[1];

    // Fetch creative → line_item_id.
    const creativeRes = await svc("GET", "creatives", {
      query: `id=eq.${creativeId}&select=id,status,line_item_id`,
    });
    if (!creativeRes.ok || !Array.isArray(creativeRes.data) || creativeRes.data.length === 0) {
      return jsonErr("Creative not found", 404);
    }
    const creative = creativeRes.data[0] as Record<string, string>;

    // Fetch line_item → campaign_id.
    const liRes = await svc("GET", "line_items", {
      query: `id=eq.${creative.line_item_id}&select=id,status,campaign_id`,
    });
    if (!liRes.ok || !Array.isArray(liRes.data) || liRes.data.length === 0) {
      return jsonErr("Line item not found", 404);
    }
    const li = liRes.data[0] as Record<string, string>;

    // Fetch campaign → status (we need to know whether to activate it).
    const campRes = await svc("GET", "campaigns", {
      query: `id=eq.${li.campaign_id}&select=id,status`,
    });
    if (!campRes.ok || !Array.isArray(campRes.data) || campRes.data.length === 0) {
      return jsonErr("Campaign not found", 404);
    }
    const camp = campRes.data[0] as Record<string, string>;

    // Activate campaign if draft or paused. Advertiser is already active (new advertisers
    // default to 'active'; suspending/activating an advertiser is a separate ops action).
    if (camp.status === "draft" || camp.status === "paused") {
      await svc("PATCH", "campaigns", {
        body: { status: "active" },
        query: `id=eq.${li.campaign_id}`,
        prefer: "return=minimal",
      });
    }

    // Activate line_item if draft or paused.
    if (li.status === "draft" || li.status === "paused") {
      await svc("PATCH", "line_items", {
        body: { status: "active" },
        query: `id=eq.${creative.line_item_id}`,
        prefer: "return=minimal",
      });
    }

    // Activate the creative (always — this is the point of the call).
    const updRes = await svc("PATCH", "creatives", {
      body: { status: "active" },
      query: `id=eq.${creativeId}`,
      prefer: "return=representation",
    });
    if (!updRes.ok) return jsonErr("Failed to activate creative", updRes.status, updRes.data);
    const updated = Array.isArray(updRes.data) ? updRes.data[0] : updRes.data;
    return jsonOk(updated);
  }

  // ---- POST /advertisers ---------------------------------------------------
  if (req.method === "POST" && path.endsWith("/advertisers")) {
    let body: Record<string, unknown> = {};
    try { body = await req.json(); } catch { /* ok */ }
    if (!body.name || typeof body.name !== "string") return jsonErr("name is required", 400);
    const res = await svc("POST", "advertisers", {
      body: { name: body.name },
      prefer: "return=representation",
    });
    if (!res.ok) return jsonErr("Failed to create advertiser", res.status, res.data);
    const row = Array.isArray(res.data) ? res.data[0] : res.data;
    return jsonOk(row, 201);
  }

  // ---- GET /advertisers ----------------------------------------------------
  if (req.method === "GET" && path.endsWith("/advertisers")) {
    const res = await svc("GET", "advertisers", {
      query: "select=id,name,status,is_house,created_at&order=created_at.desc",
    });
    if (!res.ok) return jsonErr("Failed to list advertisers", res.status);
    return jsonOk(res.data);
  }

  // ---- POST /campaigns -----------------------------------------------------
  if (req.method === "POST" && path.endsWith("/campaigns")) {
    let body: Record<string, unknown> = {};
    try { body = await req.json(); } catch { /* ok */ }
    if (!body.advertiser_id || !body.name) {
      return jsonErr("advertiser_id and name are required", 400);
    }
    const res = await svc("POST", "campaigns", {
      body: { advertiser_id: body.advertiser_id, name: body.name },
      prefer: "return=representation",
    });
    if (!res.ok) return jsonErr("Failed to create campaign", res.status, res.data);
    const row = Array.isArray(res.data) ? res.data[0] : res.data;
    return jsonOk(row, 201);
  }

  // ---- POST /line-items ----------------------------------------------------
  if (req.method === "POST" && path.endsWith("/line-items")) {
    let body: Record<string, unknown> = {};
    try { body = await req.json(); } catch { /* ok */ }
    if (!body.campaign_id) return jsonErr("campaign_id is required", 400);
    const row: Record<string, unknown> = {
      campaign_id:     body.campaign_id,
      cpva_bid_micros: body.cpva_bid_micros ?? 0,
      cpc_bid_micros:  body.cpc_bid_micros ?? 0,
      weight:          body.weight ?? 1,
      pacing_mode:     body.pacing_mode ?? "even",
    };
    // Optional fields — only include if provided to let DB defaults apply.
    for (const k of ["budget_total_micros", "budget_daily_micros", "frequency_cap_per_day",
                     "start_at", "end_at", "targeting"]) {
      if (body[k] !== undefined) row[k] = body[k];
    }
    const res = await svc("POST", "line_items", {
      body: row,
      prefer: "return=representation",
    });
    if (!res.ok) return jsonErr("Failed to create line item", res.status, res.data);
    const created = Array.isArray(res.data) ? res.data[0] : res.data;
    return jsonOk(created, 201);
  }

  // ---- GET /line-items -----------------------------------------------------
  if (req.method === "GET" && path.endsWith("/line-items")) {
    const res = await svc("GET", "line_items", {
      query: "select=*&order=created_at.desc",
    });
    if (!res.ok) return jsonErr("Failed to list line items", res.status);
    return jsonOk(res.data);
  }

  // ---- POST /creatives -----------------------------------------------------
  if (req.method === "POST" && path.endsWith("/creatives")) {
    let body: Record<string, unknown> = {};
    try { body = await req.json(); } catch { /* ok */ }
    if (!body.line_item_id || !body.line) {
      return jsonErr("line_item_id and line are required", 400);
    }
    const row: Record<string, unknown> = {
      line_item_id: body.line_item_id,
      line:         body.line,
      dest_url:     body.dest_url ?? null,
      label:        body.label ?? "sponsored",
      status:       "pending_review",
    };
    const res = await svc("POST", "creatives", {
      body: row,
      prefer: "return=representation",
    });
    if (!res.ok) return jsonErr("Failed to create creative", res.status, res.data);
    const created = Array.isArray(res.data) ? res.data[0] : res.data;
    return jsonOk(created, 201);
  }

  return jsonErr("Not found", 404);
});
