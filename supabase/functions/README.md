# lumaline edge functions (Phase 1)

Thin Deno/TypeScript wrappers over the trust-critical window-protocol RPCs
(`supabase/migrations/20260627025330_window_rpcs.sql`). They exist to give the CLI clean,
stable HTTP paths — **the CLI may also call the PostgREST RPCs directly**
(`POST /rest/v1/rpc/window_open|window_beat|close_window`); these wrappers are equivalent.

| Function       | Method | Auth                         | Backs RPC               |
| -------------- | ------ | ---------------------------- | ----------------------- |
| `window-open`  | POST   | device JWT (forwarded)       | `public.window_open`    |
| `window-beat`  | POST   | device JWT (forwarded)       | `public.window_beat`    |
| `window-close` | POST   | device JWT (forwarded)       | `public.close_window`   |
| `click`        | GET    | **none** (`verify_jwt=false`)| `public.click_resolve`  |

## Design

- **`_shared/cors.ts`** — shared CORS headers + a `json()` responder.
- **`_shared/jwt.ts`** — the plumbing. `bearerHeader(req)` pulls the caller's
  `Authorization: Bearer <device JWT>`; `forwardRpc()` **forwards** it to PostgREST so the
  JWT is verified there and `request.jwt.claims` (publisher_id / device_id) is populated
  natively — RLS and the SECURITY DEFINER functions see the same claims as a direct call.
  We deliberately do **not** decode/trust the JWT in Deno (the DB is the authority);
  `verifyDeviceJwt()` is included only as a documented opt-in alternative.
  `serviceRpc()` calls an RPC with the **service-role** key, used only by `click`.
- The three `window-*` functions forward the device JWT and pass the RPC's JSON/status
  through verbatim, so DB errors surface as-is (`28000` not-your-window, `P0001` bad
  hmac-chain / anti-batch, `P0002` unknown-or-closed-window).
- **`click`** is the public redirect: it resolves the token server-side with the service
  role, then `302 Location: <dest>` on success or `404` otherwise. The destination comes
  **only** from `click_resolve` (the booked creative) — a client-supplied URL is never
  read or echoed (no open-redirect surface). It must run with `verify_jwt = false`
  (set in `supabase/config.toml [functions.click]`).

## Serve locally

```bash
# Serves every function in this directory against the running local stack.
# Per-function `verify_jwt` is read from supabase/config.toml. For a quick smoke test you
# can also bypass the gateway JWT check entirely:
supabase functions serve --no-verify-jwt
# (omit --no-verify-jwt to honor config; `click` is already verify_jwt=false there.)

# Base URL once served:
#   http://127.0.0.1:54321/functions/v1/<name>
```

## Mint a device JWT (zero-dep)

```bash
DEVICE_JWT=$(node -e 'const c=require("crypto");const b=o=>Buffer.from(JSON.stringify(o)).toString("base64url");const h=b({alg:"HS256",typ:"JWT"});const p=b({role:"authenticated",aud:"authenticated",sub:"11111111-1111-1111-1111-111111111111",publisher_id:"a1a1a1a1-0000-0000-0000-000000000001",device_id:"d1d1d1d1-0000-0000-0000-000000000001",iat:1700000000,exp:2000000000});const s=c.createHmac("sha256",process.argv[1]).update(h+"."+p).digest("base64url");console.log(h+"."+p+"."+s)' "super-secret-jwt-token-with-at-least-32-characters-long")
```

## Curl each function

### window-open

```bash
curl -s -X POST http://127.0.0.1:54321/functions/v1/window-open \
  -H "Authorization: Bearer $DEVICE_JWT" \
  -H "content-type: application/json" \
  -d '{"p_activity_snapshot":"session"}'
# -> { "window_id":"...", "challenge":"...", "nonce":"...", "dwell_ms":5000,
#      "hb_interval_ms":1000, "click_token":"<hex>", "ad":{...} }
```

### window-beat

Heartbeat chain (must match the RPC):
`hmac_hex = HMAC-SHA256(key=challenge, msg=`seq|prevHash|activityDelta`)`,
where `prevHash` starts as the `window_id` and then becomes the previous accepted hmac.
Beats must be **>=500ms apart** in real wall-clock, **>=3** of them, and the window must
stay open the **full 5000ms** dwell before `window-close` credits.

```bash
# Compute beat 1 (prevHash = window_id), then POST it:
HMAC=$(node -e 'const c=require("crypto");const [chal,seq,prev,delta]=process.argv.slice(1);console.log(c.createHmac("sha256",chal).update(`${seq}|${prev}|${delta}`).digest("hex"))' "$CHALLENGE" 1 "$WINDOW_ID" high)
curl -s -X POST http://127.0.0.1:54321/functions/v1/window-beat \
  -H "Authorization: Bearer $DEVICE_JWT" -H "content-type: application/json" \
  -d "{\"p_window_id\":\"$WINDOW_ID\",\"p_seq\":1,\"p_hmac\":\"$HMAC\",\"p_activity_delta\":\"high\"}"
# -> { "ok": true }   (then sleep >=0.6s, set prev=$HMAC, seq=2, repeat for >=3 beats)
```

### window-close

```bash
curl -s -X POST http://127.0.0.1:54321/functions/v1/window-close \
  -H "Authorization: Bearer $DEVICE_JWT" -H "content-type: application/json" \
  -d "{\"p_window_id\":\"$WINDOW_ID\"}"
# -> { "credited":true, "attention_seconds":5, "gross_micros":10000, "reason":"ok" }
#    (or credited:false with a reason if a gate failed)
```

### click (302 redirect)

Uses the `click_token` returned by `window-open`. `-i` shows the redirect; `-L` follows it.

```bash
curl -si "http://127.0.0.1:54321/functions/v1/click?token=$CLICK_TOKEN" | head -n 5
# HTTP/1.1 302 Found
# location: https://example.com/matei
# Unknown/!ok token -> HTTP/1.1 404 Not Found
```

The path form also works: `.../functions/v1/click/$CLICK_TOKEN`.
