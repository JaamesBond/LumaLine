// POST /functions/v1/auth-device/device/{code|token|refresh|logout}
// POST /functions/v1/auth-device/earnings
// GET  /functions/v1/auth-device/activate
//
// The publisher LOGIN surface (RFC 8628 device-authorization grant). It is the ONLY thing that
// mints a REAL per-publisher device JWT — the analogue of lumaline-feed's mintSentinelJwt(), but
// for an authenticated developer instead of the shared, never-billed sentinel.
//
// WHAT IT IS (and is NOT):
//   * It owns NO trust-critical billing logic. Crediting, the HMAC dwell gate, idempotency and
//     RLS all live in the SECURITY DEFINER window RPCs. This fn only (a) drives the device-code
//     lifecycle via service_role RPCs (device_code_start/redeem/refresh), (b) mints the short-
//     lived HS256 device JWT PostgREST verifies natively, and (c) proxies the transparent
//     earnings views with the caller's own token (RLS scopes the rows).
//   * verify_jwt = false (see supabase/config.toml): /device/code carries no bearer. The
//     authenticated endpoints (/earnings, /device/logout) FORWARD the caller's bearer to
//     PostgREST, which verifies it — we never trust an unverified claim for a privileged action.
//
// TRUST INVARIANTS preserved:
//   * Honest billing — a real device JWT only ever credits the publisher the device-code grant
//     was approved by; the sentinel (gross=0) stays the fallback in lumaline-feed for anyone not
//     presenting a valid token. This fn books nothing itself.
//   * Secret custody — LUMALINE_JWT_SECRET (the HS256 mint key) and the service-role key stay
//     server-side. Only HASHES of the device_code and refresh token reach the DB; the raw
//     secrets exist transiently here and on the client. No token/secret is logged.
//   * Data minimization — the minted JWT carries ONLY UUIDs (sub/publisher_id/device_id); no
//     email/PII rides in any impression traffic.
import { corsHeaders, json } from "../_shared/cors.ts";
import { serviceRpc, forwardRpc, bearerHeader, SUPABASE_URL, ANON_KEY } from "../_shared/jwt.ts";

// Device access JWT TTL. Kept SHORT (15 min) because the client silently refreshes near expiry
// (src/client/auth.mjs getValidAccessToken), so a short TTL costs nothing — and it bounds the
// window in which an already-minted, stateless JWT survives a logout/revoke for any endpoint that
// does not re-check devices.revoked_at (the window RPCs do; the earnings read does not).
const ACCESS_TTL = Number(Deno.env.get("LUMALINE_ACCESS_TTL") ?? "900"); // device access JWT seconds
const CODE_TTL = Number(Deno.env.get("LUMALINE_DEVICE_CODE_TTL") ?? "600"); // device-code grant seconds
const POLL_INTERVAL = Number(Deno.env.get("LUMALINE_DEVICE_POLL_INTERVAL") ?? "5");
// The page a developer visits to approve a device. Defaults to this function's own /activate.
const VERIFY_URI = Deno.env.get("LUMALINE_VERIFY_URI") ?? `${SUPABASE_URL}/functions/v1/auth-device/activate`;
const PRIVACY_URL = Deno.env.get("LUMALINE_PRIVACY_URL") ?? "https://github.com/JaamesBond/LumaLine/blob/main/docs/legal/privacy-policy.md";
const TOS_URL = Deno.env.get("LUMALINE_TOS_URL") ?? "https://github.com/JaamesBond/LumaLine/blob/main/docs/legal/publisher-tos.md";

// --- base64url + crypto helpers -------------------------------------------------------
const b64urlBytes = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64urlStr = (s: string) => b64urlBytes(new TextEncoder().encode(s));
const randB64url = (n: number) => b64urlBytes(crypto.getRandomValues(new Uint8Array(n)));
async function sha256hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
// User code: 8 chars from an unambiguous alphabet (no 0/O/1/I), grouped XXXX-XXXX for display.
// We store the NORMALIZED form (no dash, uppercase) — exactly what device_code_approve compares.
const UC_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
function genUserCode(): { display: string; normalized: string } {
  const r = crypto.getRandomValues(new Uint8Array(8));
  const chars = Array.from(r, (b) => UC_ALPHABET[b % UC_ALPHABET.length]);
  const normalized = chars.join("");
  return { display: `${normalized.slice(0, 4)}-${normalized.slice(4)}`, normalized };
}

// --- HS256 device-JWT mint (same recipe + secret as lumaline-feed's sentinel mint) ----
let jwtKeyPromise: Promise<CryptoKey> | null = null;
function jwtKey(): Promise<CryptoKey> {
  if (!jwtKeyPromise) {
    const secret = Deno.env.get("LUMALINE_JWT_SECRET");
    if (!secret) return Promise.reject(new Error("LUMALINE_JWT_SECRET not set"));
    jwtKeyPromise = crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
    ).catch((e) => { jwtKeyPromise = null; throw e; });
  }
  return jwtKeyPromise;
}
async function mintDeviceJwt(
  ident: { sub: string; publisher_id: string; device_id: string },
): Promise<{ token: string; exp: number }> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ACCESS_TTL;
  const header = b64urlStr(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64urlStr(JSON.stringify({
    role: "authenticated", aud: "authenticated",
    sub: ident.sub, publisher_id: ident.publisher_id, device_id: ident.device_id,
    iat: now, exp,
  }));
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", await jwtKey(), new TextEncoder().encode(`${header}.${payload}`)),
  );
  return { token: `${header}.${payload}.${b64urlBytes(sig)}`, exp };
}

type Json = Record<string, unknown>;
const svc = async (fn: string, body: Json) => (await serviceRpc(fn, body)).data as Json | null;

// --- handler --------------------------------------------------------------------------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const path = new URL(req.url).pathname;

  // ---- GET /activate — the human approval page -------------------------------------
  if (req.method === "GET" && path.endsWith("/activate")) {
    // Lock the credential-issuing page down: it may only run its own inline script + the pinned
    // supabase-js, and may only talk to this project + esm.sh. Defence-in-depth against a hijacked
    // CDN/script on the surface that collects the developer's OTP and approves devices.
    const csp = [
      "default-src 'none'",
      "script-src 'unsafe-inline' https://esm.sh",
      "style-src 'unsafe-inline'",
      `connect-src ${SUPABASE_URL} https://esm.sh`,
      "base-uri 'none'",
      "form-action 'none'",
    ].join("; ");
    return new Response(activatePage(), {
      headers: { ...corsHeaders, "content-type": "text/html; charset=utf-8", "content-security-policy": csp },
    });
  }

  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
  let body: Json = {};
  try { body = await req.json(); } catch { /* empty ok */ }

  // ---- POST /device/code — start a device-authorization grant ----------------------
  if (path.endsWith("/device/code")) {
    const deviceCode = randB64url(32);
    const { display, normalized } = genUserCode();
    let started: Json | null;
    try {
      started = await svc("device_code_start", {
        p_device_code_hash: await sha256hex(deviceCode),
        p_user_code: normalized,
        p_ttl_seconds: CODE_TTL,
        p_interval: POLL_INTERVAL,
      });
    } catch (e) { return json({ error: "could not start device flow", detail: (e as Error).message }, 500); }
    if (!started) return json({ error: "could not start device flow" }, 500);
    return json({
      device_code: deviceCode,
      user_code: display,
      verification_uri: VERIFY_URI,
      verification_uri_complete: `${VERIFY_URI}?user_code=${encodeURIComponent(display)}`,
      expires_in: Number(started.expires_in ?? CODE_TTL),
      interval: Number(started.interval ?? POLL_INTERVAL),
    });
  }

  // ---- POST /device/token — poll; on approval, mint the device JWT -----------------
  if (path.endsWith("/device/token")) {
    const deviceCode = String(body.device_code ?? "");
    if (!deviceCode) return json({ error: "invalid_request" }, 400);
    // Generate the refresh token up front; redeem stores ONLY its hash, on the device row it
    // creates. The raw is returned to the client exactly once (on the approving poll).
    const refresh = randB64url(32);
    let r: Json | null;
    try {
      r = await svc("device_code_redeem", {
        p_device_code_hash: await sha256hex(deviceCode),
        p_label: body.label ?? null,
        p_client_version: body.client_version ?? null,
        p_refresh_token_hash: await sha256hex(refresh),
      });
    } catch (e) { return json({ error: "server_error", detail: (e as Error).message }, 500); }

    const status = String(r?.status ?? "invalid");
    if (status === "authorization_pending") return json({ error: "authorization_pending" }, 400);
    if (status === "expired") return json({ error: "expired_token" }, 400);
    if (status === "denied") return json({ error: "access_denied" }, 400);
    if (status === "consumed") return json({ error: "expired_token" }, 400); // one-shot already used
    if (status !== "approved") return json({ error: "invalid_grant" }, 400);

    let minted: { token: string; exp: number };
    try {
      minted = await mintDeviceJwt({
        sub: String(r!.auth_user_id), publisher_id: String(r!.publisher_id), device_id: String(r!.device_id),
      });
    } catch (e) { return json({ error: "server_error", detail: (e as Error).message }, 500); }
    const { token, exp } = minted;
    return json({
      access_token: token, token_type: "Bearer", expires_in: exp - Math.floor(Date.now() / 1000),
      refresh_token: refresh,
      publisher_id: r!.publisher_id, device_id: r!.device_id, handle: r!.handle,
    });
  }

  // ---- POST /device/refresh — rotate the refresh token, re-mint the access JWT -----
  if (path.endsWith("/device/refresh")) {
    const refresh = String(body.refresh_token ?? "");
    if (!refresh) return json({ error: "invalid_grant" }, 400);
    const newRefresh = randB64url(32);
    let r: Json | null;
    try {
      r = await svc("device_refresh", {
        p_refresh_token_hash: await sha256hex(refresh),
        p_new_refresh_token_hash: await sha256hex(newRefresh),
      });
    } catch (e) { return json({ error: "server_error", detail: (e as Error).message }, 500); }
    if (String(r?.status ?? "") !== "ok") return json({ error: "invalid_grant" }, 400);

    // NOTE: device_refresh already ROTATED the stored hash. If the mint throws (a
    // LUMALINE_JWT_SECRET misconfiguration — the whole service is then down, not a per-user
    // fault), we surface a clean 500; the client re-logs in. Guarding avoids a bare unhandled 500.
    let minted: { token: string; exp: number };
    try {
      minted = await mintDeviceJwt({
        sub: String(r!.auth_user_id), publisher_id: String(r!.publisher_id), device_id: String(r!.device_id),
      });
    } catch (e) { return json({ error: "server_error", detail: (e as Error).message }, 500); }
    const { token, exp } = minted;
    return json({
      access_token: token, token_type: "Bearer", expires_in: exp - Math.floor(Date.now() / 1000),
      refresh_token: newRefresh,
      publisher_id: r!.publisher_id, device_id: r!.device_id, handle: r!.handle,
    });
  }

  // ---- POST /device/logout — revoke this device (best-effort; forwards caller token) -
  if (path.endsWith("/device/logout")) {
    const auth = bearerHeader(req);
    if (!auth) return json({ error: "unauthenticated" }, 401);
    // device_revoke is scoped to app.current_publisher_id(), so a caller can only revoke a
    // device they own. p_device_id comes from the client (its own device); ownership is enforced
    // server-side by the RPC, not trusted from the body.
    try {
      const { status, text } = await forwardRpc("device_revoke", { p_device_id: body.device_id ?? null }, auth);
      return new Response(text, { status, headers: { ...corsHeaders, "content-type": "application/json" } });
    } catch (e) { return json({ error: "server_error", detail: (e as Error).message }, 500); }
  }

  // ---- POST /earnings — transparent ledger read (RLS-scoped by the caller's token) -
  if (path.endsWith("/earnings")) {
    const auth = bearerHeader(req);
    if (!auth) return json({ error: "unauthenticated" }, 401);
    const get = (view: string, q: string) =>
      fetch(`${SUPABASE_URL}/rest/v1/${view}?${q}`, {
        headers: { apikey: ANON_KEY, authorization: auth, accept: "application/json" },
      });
    try {
      const [balRes, winRes] = await Promise.all([
        get("v_publisher_balance", "select=*"),
        get("v_publisher_window_clearing", "select=*&order=created_at.desc&limit=50"),
      ]);
      if (!balRes.ok) {
        return new Response(await balRes.text(), { status: balRes.status, headers: { ...corsHeaders, "content-type": "application/json" } });
      }
      const balRows = await balRes.json();
      const windows = winRes.ok ? await winRes.json() : [];
      return json({
        balance: Array.isArray(balRows) && balRows.length
          ? balRows[0]
          : { earned_micros: 0, paid_micros: 0, reversed_micros: 0, balance_micros: 0 },
        windows,
      });
    } catch (e) { return json({ error: "server_error", detail: (e as Error).message }, 500); }
  }

  return json({ error: "not found" }, 404);
});

// --- /activate page -------------------------------------------------------------------
// Minimal, dependency-light approval page. The developer signs in with Supabase Auth (email
// OTP — owner must enable an email provider/SMTP), then this page provisions their publisher
// row (ensure_publisher) and approves the device code (device_code_approve), both via PostgREST
// with the session JWT. No secrets here: SUPABASE_URL + the anon key are public by design.
function activatePage(): string {
  // Embed config as JSON in an inline <script>. JSON.stringify does NOT escape '<' or the JS line
  // separators, so a value containing "</script>" (or U+2028/9) could break out — escape them even
  // though every value here is deploy-time operator config, not user input (defence-in-depth).
  // Escape '<' and the JS line separators (U+2028/U+2029) so a config value can never break out
  // of the inline <script>. Built via String.fromCharCode to keep this source pure-ASCII (a raw
  // U+2028 in a regex literal is itself a parse error). Operator config, not user input \u2014 d-i-d.
  const LS = String.fromCharCode(0x2028), PS = String.fromCharCode(0x2029);
  const cfg = JSON.stringify({ url: SUPABASE_URL, anon: ANON_KEY, privacy: PRIVACY_URL, tos: TOS_URL })
    .split("<").join("\\u003c").split(LS).join("\\u2028").split(PS).join("\\u2029");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Activate a LumaLine device</title>
<style>
  :root{color-scheme:dark light}
  body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}
  h1{font-size:1.4rem} .g{color:#11c281}
  input,button{font:inherit;padding:.55rem .7rem;border-radius:.5rem;border:1px solid #8884;width:100%;box-sizing:border-box}
  button{background:#11c281;color:#012;border:0;font-weight:600;cursor:pointer;margin-top:.6rem}
  .row{margin:1rem 0} .muted{opacity:.7;font-size:.9rem} #msg{min-height:1.4rem;margin-top:.8rem}
  a{color:#11c281}
</style></head>
<body>
  <h1><span class="g">★</span> Activate a LumaLine device</h1>
  <p class="muted">Logging in attributes the sponsored-line earnings on this device to your account.
  Before login, the line runs anonymously and is never billed. By approving, you agree to the
  <a id="tos" href="#" target="_blank" rel="noopener">Publisher Terms</a> and
  <a id="privacy" href="#" target="_blank" rel="noopener">Privacy Policy</a>.</p>

  <div class="row">
    <label>Device code<br/><input id="code" placeholder="ABCD-EFGH" autocomplete="off"/></label>
  </div>
  <div id="step-email" class="row">
    <label>Your email<br/><input id="email" type="email" placeholder="you@example.com" autocomplete="email"/></label>
    <button id="send">Email me a sign-in code</button>
  </div>
  <div id="step-otp" class="row" hidden>
    <label>Sign-in code (check your email)<br/><input id="otp" inputmode="numeric" autocomplete="one-time-code"/></label>
    <button id="verify">Verify &amp; approve device</button>
  </div>
  <div id="msg" class="muted"></div>

<script type="module">
  import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";
  const CFG = ${cfg};
  const safeUrl = (u) => (typeof u === 'string' && /^https?:\\/\\//i.test(u)) ? u : '#';
  document.getElementById('privacy').href = safeUrl(CFG.privacy);
  document.getElementById('tos').href = safeUrl(CFG.tos);
  const sb = createClient(CFG.url, CFG.anon);
  const $ = (id) => document.getElementById(id);
  const msg = (t) => { $('msg').textContent = t; };
  const qp = new URLSearchParams(location.search);
  if (qp.get('user_code')) $('code').value = qp.get('user_code');

  $('send').onclick = async () => {
    const email = $('email').value.trim();
    if (!email) return msg('Enter your email.');
    msg('Sending…');
    const { error } = await sb.auth.signInWithOtp({ email });
    if (error) return msg('Could not send code: ' + error.message);
    $('step-email').hidden = true; $('step-otp').hidden = false;
    msg('Check your email for a 6-digit code, then enter it above.');
  };

  async function approve() {
    const code = $('code').value.trim();
    if (!code) return msg('Enter the device code shown in your terminal.');
    msg('Approving…');
    const ep = await sb.rpc('ensure_publisher', { p_handle: null });
    if (ep.error) return msg('Could not set up your publisher account: ' + ep.error.message);
    const ap = await sb.rpc('device_code_approve', { p_user_code: code });
    if (ap.error) return msg('Approval error: ' + ap.error.message);
    if (ap.data && ap.data.ok) msg('✓ Device approved. Return to your terminal — it will finish automatically.');
    else msg('Could not approve: ' + ((ap.data && ap.data.reason) || 'unknown') + '. The code may have expired; restart lumaline login.');
  }

  $('verify').onclick = async () => {
    const token = $('otp').value.trim();
    const email = $('email').value.trim();
    msg('Verifying…');
    const { error } = await sb.auth.verifyOtp({ email, token, type: 'email' });
    if (error) return msg('Verification failed: ' + error.message);
    await approve();
  };

  // If already signed in (returning visitor), skip straight to approval.
  sb.auth.getSession().then(({ data }) => {
    if (data.session) { $('step-email').hidden = true; $('step-otp').hidden = true; msg('Signed in. Enter the device code and it will approve automatically.'); $('code').onchange = approve; }
  });
</script>
</body></html>`;
}
