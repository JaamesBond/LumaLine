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
import { forwardRpc, bearerHeader, verifyDeviceJwt } from "../_shared/jwt.ts";

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
// Choose the identity this request forwards under. M1: if the caller presents a VALID device
// JWT (verified HS256 against the same LUMALINE_JWT_SECRET the gateway trusts, unexpired, with
// real publisher_id + device_id claims that are NOT the sentinel), forward THAT token so credit
// binds to the real publisher. Otherwise mint the anonymous sentinel JWT (gross=0). We verify
// here only to DECIDE which token to forward; PostgREST re-verifies + the RPCs re-check
// devices.revoked_at on every call, so this is a routing choice, not the security boundary.
async function chooseAuth(req: Request): Promise<{ auth: string; isReal: boolean }> {
  const hdr = bearerHeader(req);
  if (hdr) {
    const claims = await verifyDeviceJwt(hdr.replace(/^Bearer\s+/i, ""), Deno.env.get("LUMALINE_JWT_SECRET") ?? "");
    if (
      claims && typeof claims.publisher_id === "string" && typeof claims.device_id === "string" &&
      claims.publisher_id !== SENTINEL.publisher_id
    ) {
      return { auth: hdr, isReal: true };
    }
  }
  return { auth: `Bearer ${await mintSentinelJwt()}`, isReal: false };
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

// --- rate limiting (salted IP hash; raw IP never stored) ------------------------------
// Compute sha256(LUMALINE_RL_SALT || client-ip) and immediately discard the IP. Only the
// hash + a minute counter live in public.rl_buckets (see 20260627041000_rate_limit.sql).
// The salt makes the hash non-reversible (raw IPv4 space is otherwise brute-forceable), so
// this stays within the data-minimization invariant. No salt set => rate limiting is OFF
// (fail-open), which makes deploying the code BEFORE the secret exists a no-op.
async function clientIpHash(req: Request): Promise<string | null> {
  const salt = Deno.env.get("LUMALINE_RL_SALT");
  if (!salt) return null;
  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim();
  if (!ip) return null;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(salt + ip));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
// True = allowed. Fail-OPEN on any error / missing config: rate limiting is a cost+abuse
// guard, NOT a security control (signing + least-privilege grants are), and nothing is ever
// billed on this feed — so availability wins over a perfect block on an rl backend hiccup.
async function rateLimitOk(req: Request, auth: string): Promise<boolean> {
  const ipHash = await clientIpHash(req);
  if (!ipHash) return true;
  const max = Number(Deno.env.get("LUMALINE_RL_MAX_PER_MIN") ?? "30");
  try {
    const { status, text } = await forwardRpc("rl_hit", { p_ip_hash: ipHash, p_max: max }, auth);
    if (status !== 200) return true;
    return JSON.parse(text) === true;
  } catch { return true; }
}

// --- handler --------------------------------------------------------------------------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const path = new URL(req.url).pathname; // e.g. /lumaline-feed/window/open
  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* empty body ok */ }

  let auth: string;
  let isReal: boolean;
  try { ({ auth, isReal } = await chooseAuth(req)); }
  catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }

  // ---- open: forward RPC, then SIGN + reshape to the client's camelCase envelope ----
  if (path.endsWith("/window/open")) {
    // Validate the Ed25519 signing key FIRST — fail fast with a consistent structured 500
    // BEFORE window_open inserts a DB row, so a missing/broken key never orphans an open window
    // (and the misconfig is distinguishable from a real no-fill, not a silent verify_fail).
    try { await signKey(); }
    catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }

    // Cost/abuse guard: rate-limit by salted IP hash BEFORE window_open inserts a DB row.
    if (!(await rateLimitOk(req, auth))) return json({ error: "rate limited" }, 429);

    const snapshot = (body?.activitySnapshot as string) ?? "session";
    let { status, text } = await forwardRpc("window_open", { p_activity_snapshot: snapshot }, auth);
    // Honest fallback: a real device token that the RPC rejects (revoked/unknown device, or a
    // token the gateway expired) must not blank the line. Retry the open under the sentinel so
    // the user still sees a gross=0 ad — nothing accrues to them, nothing accrues to anyone.
    if (status !== 200 && isReal) {
      const sentinel = `Bearer ${await mintSentinelJwt()}`;
      ({ status, text } = await forwardRpc("window_open", { p_activity_snapshot: snapshot }, sentinel));
    }
    if (status !== 200) return new Response(text, { status, headers: { ...corsHeaders, "content-type": "application/json" } });

    let rpc: Record<string, unknown>;
    try { rpc = JSON.parse(text); } catch { return json({ error: "bad rpc reply" }, 502); }
    const ad = (rpc.ad ?? {}) as { line?: string; label?: string; house?: boolean };
    // No-fill: never fabricate a line. The client treats a missing adData as verify_fail and
    // shows its plain base status. (Our seed always fills, so this is a defensive branch.)
    if (ad.house || !ad.line) return json({ error: "no fill" }, 503);

    const windowId = rpc.window_id as string;
    // Tokenized click redirect through the branded domain (c.lumaline.dev/c/<token>) so clicks
    // are tracked → CPC. The opaque single-use token was minted by window_open and rides ONLY
    // embedded in the Ed25519-signed adData.clickUrl (never returned separately); the `click` fn
    // resolves it to a 302 at the advertiser dest. No open-redirect risk: the URL is signed by us
    // and the client re-validates http(s). Falls back to the direct dest if no token was minted
    // (defensive). LUMALINE_CLICK_BASE defaults to the branded proxy; override for local dev.
    const dest = Deno.env.get("LUMALINE_SELFPROMO_DEST") ?? "https://luma-line.lovable.app";
    const clickBase = Deno.env.get("LUMALINE_CLICK_BASE") ?? "https://c.lumaline.dev";
    const token = rpc.click_token as string | undefined;
    const clickUrl = token ? `${clickBase}/c/${token}` : dest;
    // Build the signed string ONCE and transport it verbatim. JSON.parse(adData).windowId
    // MUST equal windowId or the client refuses (window.mjs:41).
    const adData = JSON.stringify({ windowId, line: ad.line, label: ad.label ?? "sponsored", clickUrl });
    let sig: string;
    try { sig = await signAd(adData); }
    catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }
    // Rotation-safe key selection: advertise WHICH bundled public key signed this envelope.
    // KEY_ID = the active signing key's fingerprint (keyFingerprint() in src/lib/crypto.mjs:
    // sha256(spki-der)[:16]). The client selects the matching trusted key from its bundle and
    // verifies. Omitted when unset, so the client falls back to its legacy/default key — making
    // this an additive, backward-compatible change. To rotate: ship clients trusting the next
    // key, THEN set LUMALINE_ED25519_PRIVATE_KEY=next + LUMALINE_ED25519_KEY_ID=fp(next).
    // Normalize (trim + lowercase) so a stray space / upper-case hex in the env can't desync
    // from the client's lower-case content fingerprint and cause an unknown-keyid blackout.
    const keyid = Deno.env.get("LUMALINE_ED25519_KEY_ID")?.trim().toLowerCase() || undefined;
    return json({
      windowId, adData, sig, keyid,
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
