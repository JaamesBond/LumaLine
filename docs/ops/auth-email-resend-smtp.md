# Device-login email + Resend SMTP — AS-BUILT record

Deployed 2026-07-03. Records how LumaLine's `trustline login` device-code flow delivers its
sign-in email, and why the activation page consumes a **link** rather than a code.

## The problem

The activation page (`supabase/functions/auth-device/index.ts` `activatePage()`) originally ran a
6-digit **OTP-code** flow: `signInWithOtp({ email })` → user types the code → `verifyOtp`. But
Supabase only sends whatever the email template renders, and the project ran on **free tier with
Supabase's default email sender**, which means:

- The template is fixed to `{{ .ConfirmationURL }}` — a magic **link**, never `{{ .Token }}`.
  Template editing is **blocked on free tier + default sender** (`PATCH …/config/auth` →
  `"Email template modification is not available for free tier projects using the default email
  provider"`).
- The default sender is hard-capped at **2 emails/hour**.

So the page waited for a code the setup could never send, and the emailed link (pointing at
`site_url`) never reached the page that approves the device. Login was impossible.

## The fix (two parts)

### 1. Activation page consumes the magic link
`activatePage()` now:
- `signInWithOtp({ email, options: { emailRedirectTo: <this page>?user_code=<device code> } })`
  so the emailed link returns to the activation page **with the device code** (also stashed in
  `localStorage` as a fallback).
- On return, detects the session (`onAuthStateChange` + `getSession`, guarded to run once) and
  auto-runs `approve()` — the unchanged `ensure_publisher` + `device_code_approve` RPCs. Manual
  "Approve" button shown only if the code is somehow absent.
- The 6-digit OTP step is removed. UX is now "click the link," which the free-tier default email
  can actually deliver.

Works for both user states: existing users get the **magic_link** template, brand-new users get
the **confirmation** (signup) template — both render a `ConfirmationURL` link that establishes a
session on the activation page, so `onSession` fires either way.

### 2. Resend SMTP (removes the rate limit + unlocks templates)
The pre-existing Resend domain `updates.lumaline.com` is **not** on the Cloudflare account, so it
was unusable. `lumaline.dev` **is**, so a fresh sending subdomain was created there:

- **Resend domain `send.lumaline.dev`** (region `eu-west-1`) — created + **verified**.
- **DNS added to the `lumaline.dev` Cloudflare zone** (`28a0e8867b12d3b35abf869c6a577399`):
  | type | name | value |
  |---|---|---|
  | TXT (DKIM) | `resend._domainkey.send.lumaline.dev` | `p=MIGf…IDAQAB` |
  | MX (return-path) | `send.send.lumaline.dev` | `feedback-smtp.eu-west-1.amazonses.com` (prio 10) |
  | TXT (SPF) | `send.send.lumaline.dev` | `v=spf1 include:amazonses.com ~all` |
- **Supabase auth `config/auth`** (via Management API, `SUPABASE_ACCESS_TOKEN_REMOTE`):
  - `smtp_host = smtp.resend.com`
  - `smtp_port = "465"`  ← **string** (a number → `400 Expected string`)
  - `smtp_user = resend`
  - `smtp_pass = $RESEND_API_KEY`
  - `smtp_admin_email = login@send.lumaline.dev`
  - `smtp_sender_name = LumaLine`
  - `rate_limit_email_sent = 30`  (was 2)
- **`uri_allow_list`** += `https://feed.lumaline.dev` + `https://feed.lumaline.dev/**` so the
  magic-link `redirect_to` (the activation page) is honored. (URL config IS editable on free
  tier — only templates aren't.)

## Verified end-to-end (2026-07-03)

`generate_link` (prod service role, `redirect_to` **top-level**) → navigated the clean magic link
→ activation page detected the owner session (`matheygaming4@gmail.com`) → auto-approved the test
device → `POST /auth-device/device/token` returned `access_token` + `refresh_token` +
`publisher_id`. That is the exact path the CLI poll completes.

Resend delivery confirmed live: real email received from `login@send.lumaline.dev`, no rate-limit
error.

## Notes / follow-ups

- Custom SMTP now **unlocks email-template editing** — the templates are still the generic
  Supabase defaults ("Confirm your email address" / "Your sign-in link"). Optional polish: brand
  them to LumaLine copy via `PATCH …/config/auth` (`mailer_templates_*` / `mailer_subjects_*`).
- **`.env` gotcha:** bare `SUPABASE_URL/ANON_KEY/SERVICE_ROLE_KEY` are the **local** stack
  (`127.0.0.1:54321`). Prod creds carry the **`_REMOTE`** suffix. Prod URL =
  `https://prmsonskzrubqsazmpwd.supabase.co`.
- The Cloudflare proxy already restores `text/html` + the function's scoped CSP for the
  `/auth-device/activate` GET (see `docs/ops/cloudflare-proxy-worker.js`) — required for the page
  to render + run its inline script.
