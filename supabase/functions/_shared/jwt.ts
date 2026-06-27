// Auth + PostgREST plumbing shared by the lumaline edge functions.
//
// DESIGN CHOICE — forward, don't re-verify.
// The window-* functions are thin wrappers whose only job is to give the CLI clean
// HTTP paths. They FORWARD the caller's `Authorization: Bearer <device JWT>` straight
// to PostgREST. That means PostgREST verifies the JWT against the project secret and
// installs its claims into `request.jwt.claims` itself — so the SECURITY DEFINER RPCs
// (window_open / window_beat / close_window) read `publisher_id` / `device_id` from
// the SAME native claims path as a direct PostgREST call, and RLS applies natively.
// We deliberately do NOT decode or trust the JWT in Deno; the database is the single
// authority. (`verifyDeviceJwt` below exists only as a documented, opt-in alternative.)
//
// The click function is the exception: it is an unauthenticated browser redirect, so it
// calls click_resolve with the SERVICE ROLE key server-side (see `serviceRpc`). The
// destination URL comes ONLY from click_resolve's reply, never from the request.

const LOCAL_API = "http://127.0.0.1:54321";

// In the Supabase edge runtime SUPABASE_URL / ANON / SERVICE_ROLE are auto-injected. We
// REQUIRE them from env rather than embedding any key-shaped string in source (even the
// public local-dev keys), so nothing secret-looking is ever committed. For a bare
// `deno run` against the local stack, export them first (see functions/README.md).
function requireEnv(name: string): string {
  const v = Deno.env.get(name);
  if (!v) {
    throw new Error(
      `${name} is required (auto-injected in the Supabase edge runtime; export it for a bare deno run)`,
    );
  }
  return v;
}
export const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? LOCAL_API;
export const ANON_KEY = requireEnv("SUPABASE_ANON_KEY");
export const SERVICE_ROLE_KEY = requireEnv("SUPABASE_SERVICE_ROLE_KEY");

const RPC_BASE = `${SUPABASE_URL}/rest/v1/rpc`;

/** Return the raw `Authorization` header value (e.g. "Bearer eyJ..."), or null. */
export function bearerHeader(req: Request): string | null {
  const h = req.headers.get("authorization") ?? req.headers.get("Authorization");
  if (!h || !/^Bearer\s+\S/i.test(h)) return null;
  return h;
}

/**
 * Forward an authenticated RPC call to PostgREST using the CALLER's device JWT.
 * PostgREST validates the JWT and applies its claims/RLS natively; we pass the reply
 * (body + status) straight through so DB-raised errors (28000/P0001/P0002) surface
 * verbatim to the client. `apikey` must still be the anon key for the PostgREST gateway.
 */
export async function forwardRpc(
  fnName: string,
  body: Record<string, unknown>,
  authorization: string,
): Promise<{ status: number; text: string }> {
  const resp = await fetch(`${RPC_BASE}/${fnName}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "application/json",
      "apikey": ANON_KEY,
      "authorization": authorization,
    },
    body: JSON.stringify(body),
  });
  return { status: resp.status, text: await resp.text() };
}

/**
 * Call an RPC with the SERVICE ROLE key (server-side, bypasses RLS). Used only by the
 * click redirect to resolve a token -> destination. Returns the parsed JSON result
 * (PostgREST returns the scalar jsonb directly; we unwrap a 1-element array just in case).
 */
export async function serviceRpc(
  fnName: string,
  body: Record<string, unknown>,
): Promise<{ ok: boolean; status: number; data: unknown }> {
  const resp = await fetch(`${RPC_BASE}/${fnName}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "application/json",
      "apikey": SERVICE_ROLE_KEY,
      "authorization": `Bearer ${SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify(body),
  });
  let data: unknown = null;
  try {
    data = await resp.json();
  } catch {
    data = null;
  }
  if (Array.isArray(data)) data = data[0] ?? null;
  return { ok: resp.ok, status: resp.status, data };
}

/**
 * OPTIONAL, NOT USED BY DEFAULT — HS256 verification of a device JWT against the project
 * JWT secret, for an edge function that wants to gate before forwarding. Forwarding is
 * preferred (the DB is the authority), so this is provided only for completeness. Pass
 * the project secret via the SUPABASE_JWT_SECRET env (never hardcode in production).
 */
export async function verifyDeviceJwt(
  token: string,
  secret = Deno.env.get("SUPABASE_JWT_SECRET") ?? "",
): Promise<Record<string, unknown> | null> {
  try {
    const [h, p, s] = token.split(".");
    if (!h || !p || !s || !secret) return null;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const sig = Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
      c.charCodeAt(0),
    );
    const ok = await crypto.subtle.verify(
      "HMAC",
      key,
      sig,
      new TextEncoder().encode(`${h}.${p}`),
    );
    if (!ok) return null;
    const claims = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(atob(p.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)),
      ),
    );
    if (typeof claims.exp === "number" && claims.exp * 1000 < Date.now()) return null;
    return claims;
  } catch {
    return null;
  }
}
