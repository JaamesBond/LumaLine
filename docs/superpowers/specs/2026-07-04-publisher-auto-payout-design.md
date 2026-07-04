# Publisher auto-payout + `lumaline connect` — design

**Date:** 2026-07-04
**Status:** approved (owner), pre-implementation
**Milestone:** M5-T4 (first self-serve payout system) → feeds M6/T8

## Goal

Publishers get paid **without the owner deciding when**. Today the payout rail exists and is
proven, but the only trigger is a hand-run admin batch and there is no publisher-facing surface.
This adds the two missing pieces for a basic-but-proper system:

1. **`lumaline connect`** — a client command so a publisher self-onboards their bank (IBAN) through
   Stripe's existing hosted flow.
2. **Automatic weekly payouts** — a pg_cron job runs the existing payout batch on a schedule; money
   flows to every eligible, onboarded publisher with no human in the loop.

Plus branded email notifications (paid confirmation + connect nudge).

## Non-goals (explicitly deferred — see "Future work")

- **On-demand withdraw** (`lumaline withdraw` / `/payout/self`). Owner deferred; scheduled-only for now.
- **Graphical publisher/advertiser portals** and an **owner dashboard** (see Future work).
- Changing the transfer/confirm/reconcile money core — it is proven and stays untouched.

## Decisions (owner-approved)

| Decision | Value |
|---|---|
| Payout minimum | **€1** (`LUMALINE_PAYOUT_MIN_MICROS=1000000`, env-tunable, no migration to change) |
| Cadence | **Weekly, Monday 09:00 UTC** (`0 9 * * 1`) |
| Notifications | **Both** — paid confirmation + connect-nudge — as **branded HTML** emails (Resend) |
| Trigger auth | pg_cron → Vault `lumaline_cron_secret` → fn cron-secret path (mirrors the live monitor) |

## What already exists (reused, not rebuilt)

- `stripe-connect` fn: `POST /connect/onboard` (publisher-token authed; creates an Express account +
  hosted account link, EEA country gate, returns `onboarding_url`), `GET /connect/status`,
  `POST /payout/batch` (admin; `payout_batch_reserve` → per-payout Stripe transfer with
  `payoutIdemKey(po.id)` + `UNIQUE(stripe_transfer_id)` + ambiguous-error self-heal → `payout_confirm`),
  `GET /reconcile`, `POST /webhook`.
- `public.payout_batch_reserve(p_hold, p_min_micros default 25000000, ...)` — reserves one `pending`
  payout per publisher where `stripe_account_id IS NOT NULL` **AND** `payable ≥ p_min_micros`. So
  **un-onboarded and sub-minimum publishers are already excluded** by construction.
- `app.publisher_payable_micros(id, hold)` — matured (7-day-held) earnings − already-paid, cent-floored.
- The **monitor cron** (`app.run_monitor()` reads Vault `lumaline_cron_secret` → `net.http_post` the
  edge fn; `cron.schedule`d by the controller at deploy; no-op if Vault/pg_net absent) — the exact
  template this design mirrors.
- Resend email (monitor already POSTs `https://api.resend.com/emails`; env `RESEND_API_KEY`). Verified
  sender domain `send.lumaline.dev`. Brand asset: green favicon (`src/assets/lumaline_favicon_green_*`).

## Architecture

Three units, each independently testable:

### Unit 1 — `lumaline connect` (client, zero new deps)

- `bin/lumaline.mjs`: new `case 'connect'` → `src/client/auth.mjs connect()`.
- `connect()`: obtain a valid access token via the grace-safe `getValidAccessToken()`. Then
  `GET {STRIPE_CONNECT_BASE}/connect/status`:
  - `onboarded: true` → print `✓ Bank connected — weekly payouts active (€1 minimum).`
  - else → `POST {STRIPE_CONNECT_BASE}/connect/onboard` → print the `onboarding_url` with a one-line
    instruction ("Open to connect your bank; you'll enter your IBAN on Stripe's secure page").
    On `422 ineligible_country`, print the supported-region note plainly.
- `src/config.mjs`: add `STRIPE_CONNECT_BASE`, default
  `https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/stripe-connect` (env-overridable; the
  stripe-connect fn is not behind the Cloudflare proxy).
- Update the stale `earnings` copy ("payouts begin only at go-live") → "Weekly auto-payout, €1
  minimum. Run `lumaline connect` to receive it."
- Help text (`lumaline` usage) gains the `connect` line. Client version bump + `npm publish` via the
  existing tag→release.yml path.

### Unit 2 — weekly auto-payout (cron + fn cron-auth)

- **Migration**:
  - `app.run_payout()` — a twin of `app.run_monitor()`: read Vault `lumaline_cron_secret`,
    `net.http_post` `https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/stripe-connect/payout/batch`
    with `Authorization: Bearer <secret>`. Vault/secret/pg_net absent → `RAISE NOTICE` + no-op (so a
    fresh local stack is inert). `REVOKE ALL … FROM PUBLIC, anon, authenticated`.
  - **NOT** `cron.schedule`d in the migration (same as monitor — no environment coupling in the repo).
    The controller runs `select cron.schedule('lumaline-payout-weekly','0 9 * * 1','select app.run_payout()')`
    at deploy time.
- **`/payout/batch` auth**: add a **cron-secret path** beside the existing admin gate. A new
  `requirePrivileged(req)` returns true when the bearer constant-time-equals `LUMALINE_CRON_SECRET`
  (env), else falls back to `requireAdmin(req)`. The transfer→confirm body is **unchanged**.
- **€1 minimum**: `/payout/batch` reads `LUMALINE_PAYOUT_MIN_MICROS` (default `1000000`) and passes it
  as `p_min_micros` to `payout_batch_reserve` (currently called with `{}` → €25 default). The DB
  default stays €25 as a safe fallback; the fn always overrides. Dry-run (`?dry_run=true`) unchanged.

### Unit 3 — branded notifications (Resend HTML)

- New `supabase/functions/_shared/email.mjs`: `sendEmail({to, subject, html, text})` → POST Resend
  (`RESEND_API_KEY`), `from: "LumaLine <payouts@send.lumaline.dev>"`. Pure template builders
  `paidEmail({handle, amountEur, last4?})` and `connectNudgeEmail({handle, amountEur})` returning
  `{subject, html, text}`. **Best-effort**: every send is wrapped so a failure logs and continues —
  it must NEVER block, reverse, or fail a payout.
- **Branding ("alive", not plaintext):** self-contained HTML, all CSS inline (email-client safe), no
  external image fetches. LumaLine wordmark header, **green accent** (from the brand favicon; confirm
  exact hex from `src/assets` / marketing at build), a single clear CTA button, warm human copy
  (celebratory for paid: "💸 You just got paid"; inviting for nudge: "You've got €X waiting"), and a
  plain-text `text` fallback for every email. Reusable by the monitor later (out of scope to convert now).
- **Paid email**: after each successful `payout_confirm`, resolve the publisher's email and send.
- **Connect-nudge**: after the batch, find publishers with `payable ≥ €1` **and** `stripe_account_id
  IS NULL`, not nudged in ≥6 days; email them; stamp `connect_nudge_at`.
- **New SECDEF, service_role-only RPCs** (migration):
  - `app.publisher_email(p_publisher_id uuid) returns text` — the publisher's `auth.users.email`.
  - `app.payout_nudge_candidates(p_min_micros bigint, p_hold interval)` → rows `{publisher_id, email,
    payable_micros}` for un-onboarded, over-min, `connect_nudge_at IS NULL OR < now()-interval '6 days'`.
  - `app.mark_connect_nudged(p_ids uuid[])` — set `connect_nudge_at = now()`.
  - New column `public.publishers.connect_nudge_at timestamptz` (nullable).

## Data flow (one weekly run)

```
pg_cron (Mon 09:00 UTC)
  → app.run_payout()  [reads Vault lumaline_cron_secret]
    → POST /payout/batch  (Bearer = cron secret; requirePrivileged ✓)
      → payout_batch_reserve(p_hold, p_min=€1)         reserve pending payouts (onboarded + ≥€1)
      → for each: stripe.transfers.create(idem=payoutIdemKey(id))  → payout_confirm  → paid-email
      → payout_nudge_candidates(€1, hold) → connect-nudge-email each → mark_connect_nudged
```

The monitor cron already covers `payout_stuck`/`payout_failed`/recon drift; `/reconcile` unchanged.

## Error handling / money-safety (invariants preserved)

- **No double-pay**: unchanged. `payoutIdemKey(po.id)` + `UNIQUE(stripe_transfer_id)` + the
  one-active-payout index + the ambiguous-error self-heal (never fail after a possibly-successful
  transfer). Idempotent re-runs.
- **Cron down / pg_net absent**: `run_payout` no-ops; next week retries; reserve is idempotent.
- **Email failure ≠ payout failure**: emails are post-confirm and try/caught. A dead Resend key delays
  nobody's money.
- **Auth**: cron secret compared constant-time; the publisher onboard/status routes stay
  publisher-token-scoped; `/payout/batch` still refuses everything that is neither the cron secret nor
  an admin JWT. New RPCs are service_role-only (REVOKE anon/authenticated/public).
- **Least data**: emails carry only handle + amount (+ card last4 on paid, already known to the payer);
  no PII beyond the recipient's own address.

## Testing

- **Unit** (`node --test`, no stack): cron-secret constant-time compare; `min` read from env; nudge
  candidate/dedup selection; email template builders (subject/CTA/amount formatting, plain-text
  fallback present, no external URLs). Pure functions extracted for this.
- **Integration** (local stack, self-skipping): schedule → `reserve(€1)` → transfer (test Stripe or the
  existing harness) → `confirm` → paid-email attempted; seed an un-onboarded over-min publisher →
  nudge fired once, second run deduped. Reuse the proven payout integration harness (the real €30 EEA
  transfer path).
- **Adversarial review** (workflow, money/trust lenses) before deploy — same bar as the charge fix.

## Deploy sequence (owner-gated, per step)

1. Migration (RPCs + `connect_nudge_at` + `run_payout`) applied to prod via the ref-guarded runner + stamp.
2. Set fn env on stripe-connect: `LUMALINE_CRON_SECRET` (= Vault `lumaline_cron_secret`),
   `LUMALINE_PAYOUT_MIN_MICROS=1000000`, confirm `RESEND_API_KEY`.
3. Redeploy `stripe-connect` (cron-auth + €1 min + emails + `_shared/email.mjs`).
4. `select cron.schedule('lumaline-payout-weekly','0 9 * * 1','select app.run_payout()')`.
5. Smoke: manual `POST /payout/batch?dry_run=true` (admin) shows the €1-min plan; verify no transfer.
6. Publish client with `lumaline connect`.

**First real auto-payout** fires when a publisher's matured (7-day-held) payable crosses €1
(currently €0.66, matures ~2026-07-11) — the rail is live and waiting until then.

## Future work (documented now, NOT built)

- **Graphical self-serve portals** — a proper web login + config UI for **publishers** (payout status,
  earnings, connect bank, history) and **advertisers** (create/fund campaigns, upload creatives, set
  bids/budgets, payment method) instead of CLI + admin-booking. Likely the separate Lovable web repo
  (M2-T8/M3-T8), blocked on a UX spec.
- **Owner dashboard** — a graphical operations view (revenue, payouts, fill, fraud, reconciliation)
  over the read-only `scripts/ops/dashboard.mjs` data.
- **On-demand withdraw** (`lumaline withdraw` + `/payout/self`) — publisher-initiated payout.
- Raise the €1 launch minimum toward a steady-state policy as volume grows; convert the monitor's
  plaintext alerts to the shared branded email module.
