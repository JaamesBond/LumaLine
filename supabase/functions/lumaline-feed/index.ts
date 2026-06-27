// POST /functions/v1/lumaline-feed/window/{open|beat|close}
//
// The ANONYMOUS, SIGNED, NEVER-BILLED self-promo feed (launch MVP, no login yet).
//
// WHAT THIS FUNCTION IS (and deliberately is NOT):
//   It adds exactly two things on top of the existing, gate-hardened window RPCs:
//     (1) a short-lived SENTINEL device JWT so an unauthenticated caller can reach the
//         RPCs under one shared "never paid" identity (seeded with cpva=cpc=0 bids), and
//     (2) Ed25519 signing + snake_case->camelCase reshaping so the zero-dep CLI client
//         (src/client/window.mjs), which refuses unsigned content, accepts the reply.
//   It contains NO trust-critical logic of its own: the dwell gate, HMAC heartbeat chain,
//   anti-batch spacing, idempotent crediting and RLS all live in the SECURITY DEFINER RPCs
//   (window_open / window_beat / close_window). We reuse them verbatim via forwardRpc — the
//   verified hot path stays single-sourced. (See docs/LAUNCH_RUN_PROMPT.md L1.)
//
// TRUST INVARIANTS preserved here:
//   * SIGNED CONTENT ONLY — the client verifies the Ed25519 sig over the EXACT adData bytes
//     against the bundled public key; we sign the literal string we transport and never
//     re-serialize it.
//   * NEVER BILLED — the sentinel line_item has cpva_bid_micros=0 AND cpc_bid_micros=0, so
//     close_window credits a *view* with gross=0 and click_resolve bills 0. Honest billing.
//   * NO OPEN REDIRECT — clickUrl points at the `click` function with the server-minted,
//     single-use click_token; the real destination is resolved server-side from the booked
//     creative (click_resolve), never asserted by this function or echoed from the request.
//   * verify_jwt = false (this is the only public entrypoint; see supabase/config.toml).
import { corsHeaders, json } from "../_shared/cors.ts";
import { SUPABASE_URL, forwardRpc } from "../_shared/jwt.ts";

// Sentinel identity — matches supabase/seed.prod.sql. Not a secret (it is the "anon, never
// paid" publisher); env-overridable for flexibility, defaults to the seeded UUIDs.
const SENTINEL = {
  sub: Deno.env.get("LUMALINE_SENTINEL_USER_ID") ?? "5e470000-0000-4000-8000-000000000001",
  publisher_id: Deno.env.get("LUMALINE_SENTINEL_PUBLISHER_ID") ?? "5e470000-0000-4000-8000-0000000000b1",
  device_id: Deno.env.get("LUMALINE_SENTINEL_DEVICE_ID") ?? "5e470000-0000-4000-8000-0000000000d1",
};

// --- base64url helpers (JWT) ----------------------------------------------------------
const b64urlBytes = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlStr = (s: string) => b64urlBytes(new TextEncoder().encode(s));

// Mint a short-lived (120s) HS256 device JWT for the sentinel identity, signed with the
// project's legacy JWT secret. PostgREST verifies it natively and installs publisher_id /
// device_id into request.jwt.claims, so the SECURITY DEFINER RPCs read the SAME claims path
// as a real device JWT. role=authenticated is required for PostgREST to SET ROLE.
let jwtKeyPromise: Promise<CryptoKey> | null = null;
function jwtKey(): Promise<CryptoKey> {
  if (!jwtKeyPromise) {
    const secret = Deno.env.get("LUMALINE_JWT_SECRET");
    if (!secret) return Promise.reject(new Error("LUMALINE_JWT_SECRET not set"));
    // Null the cache on rejection so a fixed secret recovers without a poisoned worker.
    jwtKeyPromise = crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
    ).catch((e) => { jwtKeyPromise = null; throw e; });
  }
  return jwtKeyPromise;
}
async function mintSentinelJwt(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = b64urlStr(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64urlStr(JSON.stringify({
    role: "authenticated", aud: "authenticated",
    sub: SENTINEL.sub, publisher_id: SENTINEL.publisher_id, device_id: SENTINEL.device_id,
    iat: now, exp: now + 120,
  }));
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", await jwtKey(), new TextEncoder().encode(`${header}.${payload}`)),
  );
  return `${header}.${payload}.${b64urlBytes(sig)}`;
}

// --- Ed25519 ad signing ---------------------------------------------------------------
// Tolerant PEM->DER strip (covers a secret stored with escaped newlines). The key MUST be a
// PKCS8 Ed25519 private key (poc/backend/keygen.mjs / scratchpad genkey.mjs output).
function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\\n/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
let signKeyPromise: Promise<CryptoKey> | null = null;
function signKey(): Promise<CryptoKey> {
  if (!signKeyPromise) {
    const pem = Deno.env.get("LUMALINE_ED25519_PRIVATE_KEY");
    if (!pem) return Promise.reject(new Error("LUMALINE_ED25519_PRIVATE_KEY not set"));
    // Null the cache on rejection (e.g. malformed PEM) so a fixed secret recovers without redeploy.
    signKeyPromise = crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "Ed25519" }, false, ["sign"])
      .catch((e) => { signKeyPromise = null; throw e; });
  }
  return signKeyPromise;
}
async function signAd(adData: string): Promise<string> {
  const sig = await crypto.subtle.sign(
    { name: "Ed25519" }, await signKey(), new TextEncoder().encode(adData),
  );
  // STANDARD base64 (matches Node verifyData -> Buffer.from(sig,'base64')). NOT base64url.
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// --- handler --------------------------------------------------------------------------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const path = new URL(req.url).pathname; // e.g. /lumaline-feed/window/open
  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* empty body ok */ }

  let auth: string;
  try { auth = `Bearer ${await mintSentinelJwt()}`; }
  catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }

  // ---- open: forward RPC, then SIGN + reshape to the client's camelCase envelope ----
  if (path.endsWith("/window/open")) {
    // Validate the Ed25519 signing key FIRST — fail fast with a consistent structured 500
    // BEFORE window_open inserts a DB row, so a missing/broken key never orphans an open window
    // (and the misconfig is distinguishable from a real no-fill, not a silent verify_fail).
    try { await signKey(); }
    catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }

    const snapshot = (body?.activitySnapshot as string) ?? "session";
    const { status, text } = await forwardRpc("window_open", { p_activity_snapshot: snapshot }, auth);
    if (status !== 200) return new Response(text, { status, headers: { ...corsHeaders, "content-type": "application/json" } });

    let rpc: Record<string, unknown>;
    try { rpc = JSON.parse(text); } catch { return json({ error: "bad rpc reply" }, 502); }
    const ad = (rpc.ad ?? {}) as { line?: string; label?: string; house?: boolean };
    // No-fill: never fabricate a line. The client treats a missing adData as verify_fail and
    // shows its plain base status. (Our seed always fills, so this is a defensive branch.)
    if (ad.house || !ad.line) return json({ error: "no fill" }, 503);

    const windowId = rpc.window_id as string;
    // Tracked, gross=0 click: opaque single-use token -> click fn -> 302 to booked dest.
    const clickUrl = `${SUPABASE_URL}/functions/v1/click?token=${rpc.click_token}`;
    // Build the signed string ONCE and transport it verbatim. JSON.parse(adData).windowId
    // MUST equal windowId or the client refuses (window.mjs:41).
    const adData = JSON.stringify({ windowId, line: ad.line, label: ad.label ?? "sponsored", clickUrl });
    let sig: string;
    try { sig = await signAd(adData); }
    catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }
    return json({
      windowId, adData, sig,
      dwellMs: rpc.dwell_ms, hbIntervalMs: rpc.hb_interval_ms, challenge: rpc.challenge,
    });
  }

  // ---- beat: reshape camelCase -> RPC snake_case, forward verbatim ----
  if (path.endsWith("/window/beat")) {
    const args = {
      p_window_id: body.windowId ?? null,
      p_seq: body.seq ?? null,
      p_hmac: body.hmac ?? null,
      p_activity_delta: body.activityDelta ?? null,
    };
    const { status, text } = await forwardRpc("window_beat", args, auth);
    return new Response(text, { status, headers: { ...corsHeaders, "content-type": "application/json" } });
  }

  // ---- close: reshape + forward (idempotent credit gate lives in the RPC) ----
  if (path.endsWith("/window/close")) {
    const { status, text } = await forwardRpc("close_window", { p_window_id: body.windowId ?? null }, auth);
    return new Response(text, { status, headers: { ...corsHeaders, "content-type": "application/json" } });
  }

  return json({ error: "not found" }, 404);
});
