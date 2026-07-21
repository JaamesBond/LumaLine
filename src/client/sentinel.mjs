// src/client/sentinel.mjs — the ANONYMOUS (logged-out) display path.
//
// A logged-out client shows a static, Ed25519-signed self-promo line WITHOUT opening a server
// window. The sentinel identity is gross=0 and can NEVER earn, so running the per-second heartbeat
// window protocol for it is pure waste — in prod that was ~44k churned windows + a matching
// edge-invocation storm off a single logged-out machine. Instead the client fetches the signed
// /line at most once per ttlMs (the content is static, so the TTL is hours) and renders from a
// local cache in between: no window, no beats, and no per-tick network.
//
// TRUST: signed-content-only is preserved end-to-end. The cache is re-verified against the trusted
// keyring on EVERY tick (never trusted blindly) — a tampered cache file fails verify and is dropped.
// Fully unit-testable: fetch, clock, verifier, and cache are all injected.
import { safeClickUrl } from '../lib/url.mjs';

// `★ <line>  ·  <url>  ·  <label>` — mirrors the authed adLine (client/window.mjs) minus the "(Ns)"
// dwell countdown (there is no window). Returns nulls if adData is missing/unparseable/malformed,
// so the caller cleanly falls back to its plain base status (never a blank or a fabricated line).
function render(adData, showUrl) {
  let ad;
  try { ad = JSON.parse(adData); } catch { return { status: null, clickUrl: null }; }
  if (!ad || typeof ad.line !== 'string' || !ad.line) return { status: null, clickUrl: null };
  const u = showUrl === false ? null : (ad.clickUrl ? safeClickUrl(ad.clickUrl) : null);
  const status = `★ ${ad.line}${u ? `  ·  ${u}` : ''}  ·  ${ad.label ?? 'sponsored'}`;
  return { status, clickUrl: ad.clickUrl ?? null };
}

// One anonymous tick. Returns { cache, status, clickUrl }:
//   - cache:    the (possibly refreshed) sentinel cache object to persist, or null.
//   - status:   the line to display, or null → the caller shows its plain base status.
//   - clickUrl: the sponsored destination, or null.
export async function sentinelStep({ now, fetchLine, verifyAd, cache, ttlMs, showUrl }) {
  const ttl = ttlMs ?? 6 * 60 * 60 * 1000;
  // A cache entry is only "usable" if it still verifies under the trusted keyring — signed content
  // only, re-checked every tick so a stale-but-honest line is fine but a tampered one is not.
  const usable = (c) => !!(c && c.adData && verifyAd(c.adData, c.sig, c.keyid));

  // Fresh, still-verifying cache → render with NO network call (the overwhelmingly common tick).
  if (usable(cache) && now - (cache.fetchedAt ?? 0) < ttl) {
    return { cache, ...render(cache.adData, showUrl) };
  }

  // Cache stale/absent → fetch the signed line ONCE. fetchLine may reject (network/timeout) or
  // resolve to an error body without adData; either way we fall through to the cache/base fallback.
  let fresh = null;
  try { fresh = await fetchLine(); } catch { /* fall through */ }
  if (fresh && fresh.adData && verifyAd(fresh.adData, fresh.sig, fresh.keyid)) {
    const next = { adData: fresh.adData, sig: fresh.sig, keyid: fresh.keyid, fetchedAt: now };
    return { cache: next, ...render(next.adData, showUrl) };
  }

  // Fetch failed or unverifiable → keep showing a still-verifying cached line if we have one (even
  // past its TTL — a stale honest line beats a blank), else nothing (caller shows base status).
  if (usable(cache)) return { cache, ...render(cache.adData, showUrl) };
  return { cache: null, status: null, clickUrl: null };
}
