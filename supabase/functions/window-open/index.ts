// POST /functions/v1/window-open
//
// Thin wrapper over the public.window_open(p_activity_snapshot) RPC. Forwards the
// caller's device JWT to PostgREST so the SECURITY DEFINER function reads publisher_id /
// device_id from native claims (RLS applies). Body (optional): { p_activity_snapshot }.
//
// NOTE: the lumaline CLI MAY skip this wrapper and call the PostgREST RPC directly
// (POST /rest/v1/rpc/window_open). This function exists to give a clean, stable path.
import { corsHeaders, json } from "../_shared/cors.ts";
import { bearerHeader, forwardRpc } from "../_shared/jwt.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const auth = bearerHeader(req);
  if (!auth) return json({ error: "missing bearer device JWT" }, 401);

  let snapshot: unknown = null;
  try {
    const body = await req.json();
    snapshot = body?.p_activity_snapshot ?? null;
  } catch {
    // empty/invalid body -> open with no activity snapshot
  }

  const { status, text } = await forwardRpc("window_open", { p_activity_snapshot: snapshot }, auth);
  return new Response(text, {
    status,
    headers: { ...corsHeaders, "content-type": "application/json" },
  });
});
