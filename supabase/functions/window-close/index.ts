// POST /functions/v1/window-close
//
// Thin wrapper over public.close_window(p_window_id). Forwards the caller device JWT.
// The RPC is the credit/idempotency gate: it credits only after the full server-measured
// dwell with >=3 honest beats + activity progress, and impressions.window_id UNIQUE makes
// a replayed close a no-op. Returns { credited, attention_seconds, gross_micros, reason }.
//
// Body: { p_window_id: uuid }
// NOTE: the CLI MAY call POST /rest/v1/rpc/close_window directly instead of this wrapper.
import { corsHeaders, json } from "../_shared/cors.ts";
import { bearerHeader, forwardRpc } from "../_shared/jwt.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const auth = bearerHeader(req);
  if (!auth) return json({ error: "missing bearer device JWT" }, 401);

  let windowId: unknown = null;
  try {
    const body = await req.json();
    windowId = body?.p_window_id ?? null;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  if (!windowId) return json({ error: "p_window_id is required" }, 400);

  const { status, text } = await forwardRpc("close_window", { p_window_id: windowId }, auth);
  return new Response(text, {
    status,
    headers: { ...corsHeaders, "content-type": "application/json" },
  });
});
