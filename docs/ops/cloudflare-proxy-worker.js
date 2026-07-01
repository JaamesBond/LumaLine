// LumaLine branded-domain reverse proxy (Cloudflare Worker) — AS-BUILT record.
//
// Deployed 2026-07-01 as Worker `lumaline-proxy` on account aa86d62940bf3c56b67e9e36877deaeb,
// zone lumaline.dev (28a0e8867b12d3b35abf869c6a577399), attached via Workers Custom Domains:
//   feed.lumaline.dev  (domain id 3c3e65231a14fcea11522455b1bcf3dcb163e62a)
//   c.lumaline.dev     (domain id ebaf8c32aa1c8309eceec17755e87af7838bb6ff)
//
// Purpose: serve the Supabase edge functions under the branded domain with Cloudflare TLS, with
// NO change to the signed payload. GA clients pin these hostnames (installed clients don't
// self-update, so they can never be moved off *.supabase.co later). The feed is ed25519-signed and
// verified client-side, so this proxy cannot forge an ad — trust thesis holds through the proxy.
//
// Mapping (host + path rewrite, header/body passthrough, redirects NOT followed):
//   feed.lumaline.dev/<fn>/...  ->  prmsonskzrubqsazmpwd.supabase.co/functions/v1/<fn>/...
//       (covers /lumaline-feed, /lumaline-feed/window/*, /auth-device/* — preserves the <host>/<fn>
//        shape src/config.mjs AUTH_BASE derivation needs)
//   c.lumaline.dev/c/<token>    ->  prmsonskzrubqsazmpwd.supabase.co/functions/v1/click/c/<token>
//
// The client sends no Supabase apikey (only content-type + optional Authorization: Bearer device
// token), so the proxy injects nothing. Host is dropped so the origin sees supabase.co (its router
// dispatches by subdomain). Verified 2026-07-01: signed feed verifies through feed.lumaline.dev
// (keyid 8720926064dfdf50); c.lumaline.dev/c/<bogus> -> 404 (click fn reached).

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
  event.respondWith(fetch(proxied));
});
