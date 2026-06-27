// POST /functions/v1/window-beat
//
// Thin wrapper over public.window_beat(p_window_id, p_seq, p_hmac, p_activity_delta).
// Forwards the caller device JWT to PostgREST; the RPC enforces the HMAC hash-chain,
// monotonic seq, and >=500ms anti-batch spacing. DB errors (P0001 bad chain / too close,
// P0002 unknown-or-closed, 28000 not-your-window) pass through verbatim.
//
// Body: { p_window_id: uuid, p_seq: int, p_hmac: hex, p_activity_delta: "high"|"med"|"low"|"none" }
// NOTE: the CLI MAY call POST /rest/v1/rpc/window_beat directly instead of this wrapper.
import { corsHeaders, json } from "../_shared/cors.ts";
import { bearerHeader, forwardRpc } from "../_shared/jwt.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const auth = bearerHeader(req);
  if (!auth) return json({ error: "missing bearer device JWT" }, 401);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }

  const args = {
    p_window_id: body.p_window_id ?? null,
    p_seq: body.p_seq ?? null,
    p_hmac: body.p_hmac ?? null,
    p_activity_delta: body.p_activity_delta ?? null,
  };
  if (!args.p_window_id || args.p_seq == null || !args.p_hmac) {
    return json({ error: "p_window_id, p_seq and p_hmac are required" }, 400);
  }

  const { status, text } = await forwardRpc("window_beat", args, auth);
  return new Response(text, {
    status,
    headers: { ...corsHeaders, "content-type": "application/json" },
  });
});
