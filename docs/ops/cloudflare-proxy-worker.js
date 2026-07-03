// LumaLine branded-domain reverse proxy (Cloudflare Worker) — AS-BUILT record.
//
// Deployed 2026-07-01 as Worker `lumaline-proxy` on account aa86d62940bf3c56b67e9e36877deaeb,
// zone lumaline.dev (28a0e8867b12d3b35abf869c6a577399), attached via Workers Custom Domains:
//   feed.lumaline.dev  (domain id 3c3e65231a14fcea11522455b1bcf3dcb163e62a)
//   c.lumaline.dev     (domain id ebaf8c32aa1c8309eceec17755e87af7838bb6ff)
// Worker settings: compatibility_date 2026-01-01, no bindings, standard usage.
//
// Purpose: serve the Supabase edge functions under the branded domain with Cloudflare TLS, with
// NO change to the signed payload. GA clients pin these hostnames (installed clients don't
// self-update, so they can never be moved off *.supabase.co later). The feed is ed25519-signed and
// verified client-side, so this proxy cannot forge an ad — trust thesis holds through the proxy.
//
// Mapping (host + path rewrite, header/body passthrough, redirects NOT followed):
//   feed.lumaline.dev/<fn>/...  ->  prmsonskzrubqsazmpwd.supabase.co/functions/v1/<fn>/...
//   c.lumaline.dev/c/<token>    ->  prmsonskzrubqsazmpwd.supabase.co/functions/v1/click/c/<token>
//
// >>> 2026-07-03 — DEPLOYED (lumaline-proxy updated in place via CF API; Custom Domains + compat
//     date 2026-01-01 preserved). For the /auth-device/activate approval page, restore BOTH
//     text/html AND the function's intended scoped CSP. Supabase's Edge Runtime forces
//     `content-type: text/plain` + `content-security-policy: default-src 'none'; sandbox` (+ nosniff)
//     on EVERY function response (anti-XSS on the shared *.supabase.co functions domain): text/plain
//     shows the page as raw source, and the bare `sandbox` blocks its inline style + script, leaving
//     it unstyled with a dead form. That page is our own, under our branded domain, so we rewrite
//     ONLY that one exact GET: content-type -> text/html (keeping nosniff) and CSP -> the exact
//     scoped policy the function author wrote (auth-device/index.ts). Verified live in a browser:
//     styled, ?user_code autofills, 0 console errors; feed signed JSON, c.lumaline.dev click (404 on
//     bogus), and auth JSON APIs all unchanged (byte-identical passthrough).

addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  const ORIGIN = 'https://prmsonskzrubqsazmpwd.supabase.co';
  let prefix;
  if (url.hostname === 'c.lumaline.dev') prefix = '/functions/v1/click';
  else if (url.hostname === 'feed.lumaline.dev') prefix = '/functions/v1';
  else { event.respondWith(new Response('not found', { status: 404 })); return; }
  const target = ORIGIN + prefix + url.pathname + url.search;
  const headers = new Headers(req.headers);
  headers.delete('host');
  const proxied = new Request(target, { method: req.method, headers, body: req.body, redirect: 'manual' });
  event.respondWith(handle(proxied, url, req.method));
});

async function handle(request, url, method) {
  const res = await fetch(request);
  // The ONLY special case: the human approval page. Restore text/html so the browser renders it.
  // Tight by construction:
  //   - EXACT path match (not endsWith — an unanchored suffix would let ".../auth-device/activate"
  //     appended to any other route inherit the rewrite).
  //   - only when the origin actually served the platform's text/plain downgrade — never override
  //     a real content-type the function chose (JSON error, etc.).
  //   - KEEP X-Content-Type-Options: nosniff — an explicit text/html renders fine with nosniff set,
  //     and it stays a MIME-confusion defence. The page also carries its own CSP from the function.
  if (method === 'GET'
      && url.hostname === 'feed.lumaline.dev'
      && url.pathname === '/auth-device/activate'
      && (res.headers.get('content-type') || '').toLowerCase().startsWith('text/plain')) {
    const h = new Headers(res.headers);
    h.set('content-type', 'text/html; charset=utf-8');
    // Supabase's platform ALSO replaces the function's CSP with `default-src 'none'; sandbox`,
    // whose bare `sandbox` blocks the page's own inline <style> + inline <script> + pinned
    // supabase-js — leaving it unstyled with a dead form. Restore the function's INTENDED,
    // scoped CSP (mirrors supabase/functions/auth-device/index.ts): the page may run ONLY its own
    // inline script + the pinned esm.sh supabase-js, style itself, and connect ONLY to this
    // project + esm.sh; no base-uri, no form-action. This is not a loosening — it re-applies the
    // exact policy the function author wrote, which the platform clobbered.
    h.set('content-security-policy',
      "default-src 'none'; script-src 'unsafe-inline' https://esm.sh; style-src 'unsafe-inline'; " +
      "connect-src https://prmsonskzrubqsazmpwd.supabase.co https://esm.sh; base-uri 'none'; form-action 'none'");
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
  }
  return res;   // everything else: byte-identical passthrough (feed, beats, clicks, JSON APIs)
}
