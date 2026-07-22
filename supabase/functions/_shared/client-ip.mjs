// supabase/functions/_shared/client-ip.mjs
// Shared, dependency-free trusted client-IP resolution for the edge functions.
//
// TOPOLOGY: client -> Cloudflare worker (feed.lumaline.dev / auth-device / c.lumaline.dev)
//           -> Supabase edge fn (Deno) -> PostgREST.
// Two proxy hops. The rightmost XFF entry at the Deno fn is Cloudflare's SHARED egress IP (same for
// every client) -> useless as a per-client key. cf-connecting-ip is the only header with a real
// per-client value on the legit path (Cloudflare OVERWRITES any client-supplied value). To make it
// TRUSTED against a caller that bypasses Cloudflare, our worker also sets:
//     x-lumaline-client-ip : <cf-connecting-ip>            (the real client IP it observed)
//     x-lumaline-edge-proof: <LUMALINE_EDGE_PROOF secret>  (proves the request transited our worker)
// The edge verifies the proof (constant-time) and only then marks the IP `trusted`.
//
// NOT a security control by itself — a cost/abuse + IVT signal. The hard bound is the in-DB
// per-device/per-publisher velocity caps in window_open. A direct-to-*.supabase.co caller with no
// valid proof always resolves trusted:false.

function hget(headers, k) {
  if (!headers) return "";
  const v = typeof headers.get === "function" ? headers.get(k) : headers[k];
  return typeof v === "string" ? v : "";
}

// PURE, SYNC. `proofOk` = did the worker-vouch secret verify (computed by edgeProofOk).
// Precedence: (1) worker-vouched real IP (trusted) -> (2) cf-connecting-ip (best-effort, correct
// per-client on the CF path) -> (3) LEFTMOST XFF (legacy fallback / local dev) -> (4) x-real-ip.
// Note we deliberately do NOT use the rightmost XFF hop: in this two-hop topology it is CF's shared
// egress IP and would collapse all clients to one bucket.
export function pickClientIp(headers, { proofOk = false } = {}) {
  const vouched = hget(headers, "x-lumaline-client-ip").trim();
  if (proofOk && vouched) return { ip: vouched, trusted: true, source: "edge-proof" };

  const cf = hget(headers, "cf-connecting-ip").trim();
  if (cf) return { ip: cf, trusted: false, source: "cf-connecting-ip" };

  const xff = hget(headers, "x-forwarded-for").split(",").map((s) => s.trim()).filter(Boolean);
  if (xff.length) return { ip: xff[0], trusted: false, source: "xff-left" };

  const real = hget(headers, "x-real-ip").trim();
  if (real) return { ip: real, trusted: false, source: "x-real-ip" };

  return { ip: "", trusted: false, source: "none" };
}

// Deno + Node>=19 expose WebCrypto as globalThis.crypto; Node 18 (CI) only under node:crypto.
async function subtle() {
  return globalThis.crypto?.subtle ?? (await import("node:crypto")).webcrypto.subtle;
}

// Constant-time proof check. Empty/unset secret or absent header => false (proof path disabled,
// resolver falls back to cf-connecting-ip). Mirrors monitor-logic.timingSafeEqualStrings.
export async function edgeProofOk(headers, secret) {
  const presented = hget(headers, "x-lumaline-edge-proof");
  if (typeof secret !== "string" || secret.length === 0 || presented.length === 0) return false;
  const s = await subtle();
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    s.digest("SHA-256", enc.encode(presented)),
    s.digest("SHA-256", enc.encode(secret)),
  ]);
  const ba = new Uint8Array(da), bb = new Uint8Array(db);
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

// EXACT reproduction of lumaline-feed's current clientIpHash: standard base64 of sha256(salt||ip).
// Returns null when salt or ip is empty (rate-limit OFF / no signal). MUST stay byte-identical so
// window-time (ad_windows.ip_hash), rl_buckets, and any click-time hash (P2) compare equal.
export async function saltedIpHash(salt, ip) {
  if (!salt || !ip) return null;
  const s = await subtle();
  const buf = await s.digest("SHA-256", new TextEncoder().encode(salt + ip));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

// Convenience: resolve {ip, trusted, source} from a Request's headers + the proof secret.
export async function resolveClientIp(headers, proofSecret) {
  const proofOk = await edgeProofOk(headers, proofSecret ?? "");
  return pickClientIp(headers, { proofOk });
}
