// Shared CORS headers for lumaline edge functions.
//
// The window-* functions are normally called by the lumaline CLI/client (not a
// browser), but exposing CORS keeps them usable from a browser-based debug console
// too. The click function IS hit from a browser (the OSC-8 redirect), so it returns
// a 302 and never needs a CORS preflight for a top-level navigation — but we still
// answer OPTIONS uniformly so all four handlers behave the same.
export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
} as const;

// Convenience JSON responder that always carries CORS + an explicit content-type.
export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "content-type": "application/json" },
  });
}
