// GET /functions/v1/click?token=<hex>   (or /functions/v1/click/<hex>)
//
// The public click redirect — the server side of the OSC-8 hyperlink. This is the
// IAB/MRC click-tracker pattern: record the click, then 302 to the booked destination.
//
// TRUST INVARIANTS (do not weaken):
//   * UNAUTHENTICATED but server-trusted: it calls public.click_resolve with the SERVICE
//     ROLE key server-side. This function must be deployed with verify_jwt = false
//     (see supabase/config.toml [functions.click]) because a browser navigation carries
//     no Authorization header.
//   * NO OPEN REDIRECT: the destination comes ONLY from click_resolve's reply (resolved
//     from the booked creative via the single-use token's hash). A client-supplied URL is
//     never read, never echoed. Unknown/!ok token -> 404, never a redirect.
//   * The token is opaque and single-use; click_resolve dedupes billing via a UNIQUE hash
//     but still returns the destination so a re-click still lands the user (no double-bill).
import { corsHeaders } from "../_shared/cors.ts";
import { serviceRpc } from "../_shared/jwt.ts";

function extractToken(url: URL): string | null {
  const q = url.searchParams.get("token");
  if (q) return q;
  // Path forms: /click/<token> or /functions/v1/click/<token>
  const parts = url.pathname.split("/").filter(Boolean);
  const idx = parts.lastIndexOf("click");
  if (idx >= 0 && parts.length > idx + 1) return decodeURIComponent(parts[idx + 1]);
  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("method not allowed", { status: 405, headers: corsHeaders });
  }

  const token = extractToken(new URL(req.url));
  if (!token) return new Response("missing token", { status: 400, headers: corsHeaders });

  const { ok, data } = await serviceRpc("click_resolve", { p_token: token });
  if (!ok) return new Response("click resolve failed", { status: 502, headers: corsHeaders });

  const result = (data ?? {}) as { ok?: boolean; dest?: unknown; reason?: string };
  if (result.ok === true && typeof result.dest === "string" && result.dest.length > 0) {
    // 302 so the same token can resolve again (idempotent landing); never cache the hop.
    return new Response(null, {
      status: 302,
      headers: { ...corsHeaders, "Location": result.dest, "Cache-Control": "no-store" },
    });
  }
  // unknown window / no creative / no dest -> 404, no redirect, no client-controlled URL
  return new Response("not found", { status: 404, headers: corsHeaders });
});
