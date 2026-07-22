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
//   * NO OPEN REDIRECT — clickUrl points at the `click` function with the edge-minted, single-use
//     click token embedded ONLY inside the signed adData; window_open stores only its hash and never
//     returns the raw token to any caller. The real destination is resolved server-side from the
//     booked creative (click_resolve), never asserted by this function or echoed from the request.
//   * verify_jwt = false (this is the only public entrypoint; see supabase/config.toml).
import { corsHeaders, json } from "../_shared/cors.ts";
import { forwardRpc, bearerHeader, verifyDeviceJwt } from "../_shared/jwt.ts";
import { createMemoryLimiter } from "../_shared/ratelimit.mjs";
import { resolveClientIp, saltedIpHash } from "../_shared/client-ip.mjs";

// sha256 hex — MUST match Postgres encode(digest(token,'sha256'),'hex') so click_resolve resolves
// the token window_open stored as click_token_hash.
async function sha256hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
// Opaque single-use click token (48 hex chars, == the old window_open gen_random_bytes(24)).
function mintClickToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(24)),
    (b) => b.toString(16).padStart(2, "0")).join("");
}

// D1: per-isolate in-memory fallback limiter (raw IP kept only in this Map, never persisted). This
// is the fail-CLOSED floor for the no-DB paths and when LUMALINE_RL_SALT is unset. Separate buckets
// so a burst on /window/open cannot exhaust /line's budget.
const memLimit = createMemoryLimiter({ max: Number(Deno.env.get("LUMALINE_RL_MEM_PER_MIN") ?? "120"), windowMs: 60000 });
let rlSaltWarned = false;
// TRUSTED client-IP resolution (see _shared/client-ip.mjs). OLD code used xff[0] (fully
// client-controlled). Precedence now: worker-vouched (x-lumaline-client-ip + LUMALINE_EDGE_PROOF)
// -> cf-connecting-ip -> leftmost XFF -> x-real-ip. Direct-to-*.supabase.co callers that bypass the
// worker still forge headers => IP is DEFENSE-IN-DEPTH; the hard bound is window_open's in-DB
// per-device/per-publisher velocity caps (migration 20260722120000).
async function resolveIp(req: Request): Promise<string> {
  const { ip } = await resolveClientIp(req.headers, Deno.env.get("LUMALINE_EDGE_PROOF") ?? "");
  return ip;
}

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
async function clientIpHash(ip: string): Promise<string | null> {
  const salt = Deno.env.get("LUMALINE_RL_SALT");
  if (!salt || !ip) return null;
  return await saltedIpHash(salt, ip);   // standard base64 of sha256(salt||ip); byte-identical to legacy
}
// D1: cost/abuse guard applied to EVERY endpoint. Two layers:
//   (1) an in-memory per-isolate limiter that ALWAYS runs (the fail-CLOSED floor — bounds a flood
//       even with no salt and no DB), and
//   (2) the durable salted-IP DB limiter (rl_hit) when LUMALINE_RL_SALT is set (cross-isolate).
// When the salt is unset we emit a one-time misconfig alert (edge logs) and rely on layer (1) —
// the no-DB path is no longer silently fail-open. Rate limiting is still NOT the security control
// (signing + least-privilege grants are) and nothing bills on this feed, so a DB hiccup fails open
// on layer (2) only; layer (1) always applies.
async function rateLimitOk(ip: string, auth: string, bucket: string): Promise<boolean> {
  const now = Date.now();
  if (ip && !memLimit.hit(`${bucket}:${ip}`, now)) return false;   // layer (1): fail-closed floor

  const salt = Deno.env.get("LUMALINE_RL_SALT");
  if (!salt) {
    if (!rlSaltWarned) {
      rlSaltWarned = true;
      console.error("lumaline-feed: LUMALINE_RL_SALT unset — durable salted-IP rate limit OFF; " +
        "relying on the per-isolate in-memory limiter only. Set LUMALINE_RL_SALT in prod.");
    }
    return true;   // in-memory layer already applied
  }
  const ipHash = await clientIpHash(ip);
  if (!ipHash) return true;
  const max = Number(Deno.env.get("LUMALINE_RL_MAX_PER_MIN") ?? "30");
  try {
    const { status, text } = await forwardRpc("rl_hit", { p_ip_hash: ipHash, p_max: max }, auth);
    if (status !== 200) return true;            // DB hiccup: layer (1) still applied
    return JSON.parse(text) === true;
  } catch { return true; }
}

// --- handler --------------------------------------------------------------------------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const path = new URL(req.url).pathname; // e.g. /lumaline-feed/window/open
  const clientIp = await resolveIp(req);  // trusted-source client IP for RL + IVT/ip binding
  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* empty body ok */ }

  // ---- line: display-only SIGNED self-promo, NO window (the anonymous / logged-out path) ----
  // A logged-out client shows THIS static, Ed25519-signed line instead of opening a server window.
  // The sentinel is gross=0 and can never earn, so running the per-second heartbeat window protocol
  // for it is pure waste — in prod that churned ~44k windows + a matching invocation storm off ONE
  // logged-out machine. This endpoint has NO DB write, NO click token, NO auth (skips chooseAuth,
  // so no sentinel-JWT mint), and is safe for the client to cache for hours. It is signed with the
  // SAME key + keyid as /window/open, so the client's signed-content-only rule is fully preserved.
  if (path.endsWith("/line")) {
    // D1: /line is cached hours client-side but still floodable — bound it (in-memory only; /line
    // deliberately mints no JWT, so no DB rl_hit here).
    if (clientIp && !memLimit.hit(`line:${clientIp}`, Date.now())) {
      return json({ error: "rate limited" }, 429);
    }
    try { await signKey(); }
    catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }
    const line  = Deno.env.get("LUMALINE_SELFPROMO_LINE")  ?? "LumaLine — honest, signed ads for Claude Code";
    const label = Deno.env.get("LUMALINE_SELFPROMO_LABEL") ?? "sponsored";
    const dest  = Deno.env.get("LUMALINE_SELFPROMO_DEST")  ?? "https://lumaline.dev";
    // Display-only: adData carries NO windowId (there is no window). The client's anonymous path
    // parses {line,label,clickUrl}, verifies the sig, and renders — it never runs the state machine.
    const adData = JSON.stringify({ line, label, clickUrl: dest });
    let sig: string;
    try { sig = await signAd(adData); }
    catch (e) { return json({ error: "feed misconfigured", detail: (e as Error).message }, 500); }
    const keyid = Deno.env.get("LUMALINE_ED25519_KEY_ID")?.trim().toLowerCase() || undefined;
    return json({ adData, sig, keyid });
  }

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
    if (!(await rateLimitOk(clientIp, auth, "open"))) return json({ error: "rate limited" }, 429);

    const snapshot = (body?.activitySnapshot as string) ?? "session";
    // B4: the token is minted HERE (edge) and rides ONLY inside the Ed25519-signed adData.clickUrl.
    // window_open receives only its sha256 hash and never returns the raw token to any caller. Also
    // pass the salted IP hash so scan_ivt can be per-IP aware (ad_windows.ip_hash).
    const clickToken = mintClickToken();
    const clickTokenHash = await sha256hex(clickToken);
    const ipHash = await clientIpHash(clientIp);   // salted, trusted-source; null when RL_SALT unset
    const openArgs = {
      p_activity_snapshot: snapshot,
      p_click_token_hash: clickTokenHash,
      p_client_ip_hash: ipHash,
    };
    let { status, text } = await forwardRpc("window_open", openArgs, auth);
    // Honest fallback: a real device token the RPC rejects (revoked/unknown device, gateway-expired,
    // OR now an over-cap rate-limit) must not blank the line. Retry the open under the sentinel
    // (cap-EXEMPT, gross=0) so the user still sees an ad — nothing accrues to them or anyone.
    if (status !== 200 && isReal) {
      const sentinel = `Bearer ${await mintSentinelJwt()}`;
      ({ status, text } = await forwardRpc("window_open", openArgs, sentinel));
    }
    if (status !== 200) return new Response(text, { status, headers: { ...corsHeaders, "content-type": "application/json" } });

    let rpc: Record<string, unknown>;
    try { rpc = JSON.parse(text); } catch { return json({ error: "bad rpc reply" }, 502); }
    const ad = (rpc.ad ?? {}) as { line?: string; label?: string; house?: boolean; has_dest?: boolean };
    // No-fill: never fabricate a line. The client treats a missing adData as verify_fail and
    // shows its plain base status. (Our seed always fills, so this is a defensive branch.)
    if (ad.house || !ad.line) return json({ error: "no fill" }, 503);

    const windowId = rpc.window_id as string;
    // Tokenized click redirect through the branded domain (c.lumaline.dev/c/<clickToken>) so clicks
    // are tracked → CPC. B4: the opaque single-use token is minted HERE (edge) and rides ONLY inside
    // the Ed25519-signed adData.clickUrl — window_open stores only its sha256 hash and no longer
    // returns the raw token to any caller. The `click` fn resolves it (click_resolve hashes the token
    // to the stored click_token_hash) to a 302 at the advertiser dest. No open-redirect risk: the URL
    // is signed by us and the client re-validates http(s). LUMALINE_CLICK_BASE defaults to the branded
    // proxy; override for local dev.
    const clickBase = Deno.env.get("LUMALINE_CLICK_BASE") ?? "https://c.lumaline.dev";
    // View-only creatives (no booked dest_url) surface NO click URL. Resolving c.lumaline.dev/c/<token>
    // for a destination-less creative 404s — and the client would render that as a dead inline link
    // (worse in terminals where the OSC-8 hyperlink is stripped, so the raw URL shows as text). Emit a
    // clickUrl ONLY when the creative has a destination (has_dest); otherwise null → the client shows none.
    const clickUrl = ad.has_dest ? `${clickBase}/c/${clickToken}` : null;
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
