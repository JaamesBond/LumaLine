# LumaLine — external security review brief (M5-T7)

**Prepared:** 2026-07-02 · **For:** an independent security reviewer · **Gate:** this is the
hard M5 go-live gate (`docs/ops/go-live-checklist.md` row 10). Real EUR moves only after the
high/critical findings here are closed.

---

## 1. What LumaLine is (30-second model)

A signed, clearly-labeled sponsored line in the Claude Code status bar. Advertisers are
**billed** (CPVA per credited view + CPC per click, EUR); publishers (developers running the
client) are **paid** a 60/40 split. The trust thesis: do transparently, via the official
`statusLine` mechanism only, what invasive tools do by patching. Money correctness and
data-minimization are the product, not features.

- **Backend:** Supabase — Postgres (RLS + SECURITY DEFINER RPCs) + 7 Deno edge functions.
  Project `prmsonskzrubqsazmpwd`.
- **Payments:** Stripe — PaymentIntents (advertiser charges) + Connect transfers (publisher
  payouts). Currently **test mode**; go-live swaps to live keys.
- **Client:** zero-dependency npm package `lumaline` (published `0.1.0`), Node ≥ 18.
- **Ledger:** double-entry, every economic event is a zero-sum group; publishers paid only
  after a 72 h clawback window + a 7-day hold.

## 2. Scope — review THIS

**In scope (money + trust critical):**
- `supabase/migrations/*.sql` — RLS policies, grants, SECURITY DEFINER functions, the ledger
  zero-sum trigger, the sentinel/house never-bills CHECK.
- `supabase/functions/{billing,stripe-connect,admin-booking,auth-device,lumaline-feed,click,monitor}/`
  — every route's authN/authZ, idempotency, webhook signature verification, input handling.
- `supabase/functions/_shared/{jwt.ts,cors.ts,payout-logic.mjs,webhook-secrets.mjs,billing-logic.mjs,monitor-logic.mjs}`.
- `src/statusline.mjs`, `src/config.mjs`, `src/install.mjs` — client trust loop, signature
  verification, data leaving the machine.
- `docs/ops/cloudflare-proxy-worker.js` — the branded-URL proxy.

**Out of scope:** the marketing site (separate repo, waitlist only), `poc/` (dev-only, never
published), `docs/` prose.

**Companion artifact:** `docs/superpowers/t7/t7-review-inventory.md` (internal, gitignored) is
a full machine-generated inventory: every table's RLS + grants, every SECDEF function's
EXECUTE grants + search_path, every route's auth, and the 7 money flows with enforcement
points. Hand it to the reviewer as the map. **Do NOT include `supabase/functions/.env` or the
repo-root `.env` in anything handed over — both hold live secrets.**

## 3. Threat model — what an attacker wants

1. **Get paid without earning** — forge/replay impressions or clicks, inflate a publisher's
   payable balance, or trigger a payout that isn't backed by cleared, matured, un-clawed-back
   earnings.
2. **Avoid being billed** — as an advertiser, serve ads that never produce a chargeable ledger
   entry (or make the sentinel/house path bill nothing while serving real paid demand).
3. **Move money twice or to the wrong place** — double-charge, double-pay, double-refund, or
   redirect a transfer.
4. **Read what they shouldn't** — one publisher reading another's earnings/PII; anon reading
   advertiser billing; anyone reading the admin allow-list or the ledger.
5. **Escalate to admin** — reach an admin-gated mutation without being in `app.admins`.
6. **Break the trust invariants** — make the client display unsigned content, exfiltrate more
   than `{adId, dwellMs, nonce, ts}`, or bill during idle.

## 4. Invariants the reviewer should try to break

Each is a place where "if this fails, money is wrong." The inventory gives exact file:line.

- **Ledger zero-sum**: every `entry_group_id` sums to 0 (deferred constraint trigger). Can it be
  bypassed in a single transaction? (Our own T6 monitor exists because `session_replication_role`
  can bypass it — confirm nothing in the app path can.)
- **Honest billing / sentinel-never-bills**: `is_house=true` and the sentinel advertiser must
  produce `gross=0` and never a chargeable entry. Enforced at 3 layers (feed seeds cpva=cpc=0,
  `check_house_bids` CHECK, billing `is_house` skip, `close_window` zeroing). Do all agree?
- **Charge idempotency**: one cleared group → at most one PaymentIntent (UNIQUE on
  `entry_group_id` + Stripe idempotency key `lumaline_grp_{id}`). Can a retry/race double-charge?
- **Payout safety**: two-phase reserve/confirm; ledger booked at confirm not reserve;
  `payouts_one_active_per_publisher` partial-unique lock; transfer-error classification never
  fails a payout when a transfer may have succeeded (the double-pay bug we already fixed in M3).
  7-day hold > 72 h clawback so no in-window share is ever paid. Can any of these be defeated?
- **Webhook verification**: multi-secret (connected + platform endpoints); signature over the
  RAW body via `constructEventAsync`; dedup on `stripe_webhook_events`. Can a forged or replayed
  event mutate money state?
- **Authorization**: every money-path edge function is `verify_jwt=false` — the Supabase gateway
  does NOT pre-authenticate, so **every route's first act must be its own auth check**
  (`admin_check` forward, webhook signature, or cron secret). One missed gate = internet-exposed.
- **Data minimization**: the client's impression POST body is only `{adId, dwellMs, nonce, ts}`;
  the signed feed is verified ed25519 before display. No code/paths/prompts leave the machine.

## 5. Known items already flagged (start here — verify, don't re-discover)

The internal inventory lists 19 REVIEWER-ATTENTION items — **consistency observations, not
asserted vulnerabilities**. The highest-value ones to adjudicate:

- **`verify_jwt=false` on all money fns** — confirm each route auth-checks before any effect;
  in `stripe-connect`, `/webhook` is deliberately pre-gate — verify no *other* route is.
- **Admin money-RPCs granted to all `authenticated`**, with the admin gate only *inside* the
  function (`approve_clawback`, `reject_clawback`, `resolve_dispute`, `gdpr_delete_publisher`).
  Safety rests on one `IF NOT app.is_admin() THEN RAISE` per function — verify each is present
  and unbypassable. `gdpr_delete_publisher` also writes `auth.*` as definer.
- **`app.admins` has RLS disabled** — the allow-list gating every admin surface relies on schema
  privacy + absent grants only (thinner than `alert_events`, which enables RLS). Confirm it is
  truly unreadable/unwritable via PostgREST.
- **`disputes` RLS keys on a raw `app.jwt_claim('publisher_id')`** while every other
  publisher-scoped policy keys on `app.current_publisher_id()` (auth.uid()-derived) — inconsistent
  identity anchoring; verify neither over- nor under-scopes.
- **`rl_buckets` has no explicit grants**; **`billing_recon_totals`/`uncharged_advertiser_billings`
  were anon-reachable for a few migrations before hardening** — the reviewer should confirm
  against the **live DB** that no default-privilege residue remains (Supabase auto-grants anon
  EXECUTE on new public functions; our `20260629120000` migration is the fix — check nothing
  created between hardening migrations slipped through).
- **Rate limiting is fail-open** on the one public entrypoint (`lumaline-feed`); note nothing
  else throttles anonymous `/window/open` row creation.
- **Refund path** hardcodes `reason='fraudulent'` and amount from `advertiser_charges.amount_cents`
  — confirm an already-refunded/partially-reversed PI can't be over-refunded past the idempotency key.

## 6. How to run it

1. Clone the repo at `main` (tip = merged PR #13). No secrets included; ask for a redacted env
   template if needed.
2. Read `docs/superpowers/t7/t7-review-inventory.md` (the map) + `CLAUDE.md` (trust invariants).
3. Static review of the scope in §2 against the threat model §3 and invariants §4.
4. Optional dynamic: `supabase start` locally + `node --test test/*.mjs` (324 tests) + Stripe
   test-mode keys to exercise the flows.
5. **Deliverable:** a findings report, each finding severity-rated (critical/high/medium/low)
   with a concrete exploit scenario. Acceptance for the M5 gate: **all high/critical closed with
   linked remediation PRs.**

## 7. Where to find a reviewer (owner action)

Realistic options, roughly cheapest → most formal:
- **Independent Supabase/Postgres-RLS specialist** (Upwork/Toptal, or a referral) — best
  fit; the surface is RLS + SECDEF + Stripe, not web-app OWASP. ~€1–3k for a scoped review of
  this size.
- **A boutique appsec firm** doing a fixed-scope "money-path review" — cleaner report, ~€5–15k.
- **Stripe's own partner directory** / a fractional security engineer for a day or two.
- If budget-constrained: a **paid audit from a known Postgres/Supabase consultant** on just the
  migrations + edge-fn auth is the 80/20 — that is where the money risk concentrates.

Give them this brief + the inventory. Scope is small and self-contained; a competent reviewer
turns it around in 2–5 days.

## 8. If you choose to accept the risk instead

The plan treats T7 as a hard gate. If you launch without an external review, that must be an
explicit, recorded owner decision (not a default). To do so, replace this file's gate status in
`docs/ops/go-live-checklist.md` row 10 with a dated, signed risk-acceptance note. Given real
funds and real publisher payouts, an external pass is strongly recommended first.
