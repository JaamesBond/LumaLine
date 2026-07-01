# LumaLine — AS-BUILT Reconciliation & Deferral Ledger

**Status:** Authoritative map of what *is built* vs. what the older design docs *describe*.
**As of:** 2026-07-01 (milestone **M4** DONE — branded domain + CPC money-path (TEST) + **GA npm publish `lumaline@0.1.0` LIVE**; see §5c).
**Branch:** `feat/m4-cpc-and-branded-url` (based on `main` after PR #9). Earlier milestones: M0 `feat/m0-production-rails`.
**Backend project:** Supabase `prmsonskzrubqsazmpwd` (the LumaLine project — **not** the unrelated CRM `kvlfpwzmjxuapjheknnj`).

> Read **this** doc and the **code** for what *is*. Read `docs/` for what's *planned*. Where the two
> disagree, the two entries called out under **§3 Superseded** are the known traps — older docs
> describe an in-memory `src/server/` verification design and "P0–P6" phase names that are **no longer
> the architecture**. This file is the reconciliation between them.

> **M0 owner actions — EXECUTED 2026-06-29** (after this doc's first draft): branch protection on
> `main` is live; `schema_migrations` reconciled to **13** versions (D4 closed); the live `lumaline-feed`
> now **emits `keyid=8720926064dfdf50`** (activated + redeployed, verified); the next private key is in
> Vault as `LUMALINE_ED25519_NEXT_PRIVATE_KEY` with the disk copy shredded (D3 closed); a fresh
> `supabase db reset` reproduced the live object set with **zero drift**. The only M0 item left is the
> owner's merge of PR #3.

---

## 1. The actual production architecture

The trust loop is **not** an in-memory Node server. In production it runs through **server-verified
window RPCs implemented as Postgres `SECURITY DEFINER` functions**, fronted by **Supabase Edge
Functions** (Deno/TypeScript), against the live `prmsonskzrubqsazmpwd` database. The published npm
client (`src/`, `bin/`) talks to those edge functions over HTTPS; it never embeds or assumes a local
server. (The in-memory server still exists — see §3 — but only as a **dev/test reference and the
client's unit-test backend**, never the production path.)

### End-to-end trust loop (production)

1. **Signed feed.** Client polls `lumaline-feed` (Edge Function) → `{ data, sig, keyid }`. The ad
   payload is **Ed25519-signed**; the client refuses anything that fails verification (signed-content-only
   invariant). The signing private key lives **only in Supabase Vault** and never ships.
2. **Server-verified dwell window.** Client opens a window via `window-open` → `window_open` RPC
   (server-issued window id), posts a per-second HMAC-SHA256 **heartbeat hash-chain** via `window-beat` →
   `window_beat` RPC (anti-batch ≥500 ms spacing, bound to a coarse activity bucket), and finalizes via
   `window-close` → `close_window` RPC. Crediting is **idempotent** (`impressions.window_id UNIQUE`) — a
   re-close never double-bills.
3. **Honest billing.** A real impression is recorded only after a full, activity-backed dwell; idle never
   bills. The beta **sentinel** (self-promo) identity is `gross = 0` and is **never billed**.
4. **Click redirect.** `click` Edge Function 302-redirects through a tokenized URL; `click_resolve` RPC
   records the click with `click_token_hash UNIQUE` dedup and a cleared-parent-impression billability gate.
5. **Ledger + clawback.** Cleared revenue posts to a **double-entry, publisher-favored 60/40 ledger**
   (`ledger_entries`), with a **72-hour clawback window** and invalid-traffic scanning feeding `risk_flags`.

### SQL RPCs (`SECURITY DEFINER`)

| RPC | Role |
|---|---|
| `window_open` | Issue a server window (salted-IP-hash rate-limited via `rl_hit`). |
| `window_beat` | Verify + extend the HMAC heartbeat hash-chain; anti-batch timing. |
| `close_window` | Finalize the dwell, idempotently credit one impression. |
| `click_resolve` | Record a click (token-hash dedup, parent-impression gate). |
| `clawback` | Reverse a cleared entry within the 72h window (internal ledger reversal). |
| `scan_ivt` | Invalid-traffic scan → `risk_flags`. |
| `sweep_stale_windows` | Mark abandoned open windows. |
| `clear_events` | Periodic clearing pass. |
| `rl_hit` | Salted-IP-hash rate-limit counter (`rl_buckets`); **fails open** (cost guard, not a security control). |

**`app.*` helpers (private schema):** `app.accrue`, `app.activity_rank`, `app.current_publisher_id`,
`app.is_admin`, `app.jwt_claim`, `app.ledger_group_balances`, `app.set_updated_at`, plus the `app.admins`
table.

### Edge Functions (`supabase/functions/`)

`lumaline-feed` (signed feed + rate-limit guard, emits `keyid`), `click` (302 redirect), `window-open`,
`window-beat`, `window-close`, and `_shared`.

### Schema (the 12 migrations on `main`)

- **16 tables:** `publishers`, `devices`, `device_auth_codes`, `advertisers`, `campaigns`, `line_items`,
  `creatives`, `ad_windows` (**UNLOGGED**), `impressions`, `clicks`, `ledger_entries`, `payouts`,
  `serve_counters`, `line_item_daily_stats`, `risk_flags`, `rl_buckets`.
- **3 views:** `v_publisher_balance`, `v_publisher_window_clearing`, `v_campaign_delivery`.
- **Double-entry 60/40 ledger** with a zero-sum trigger; **72h clawback window**.
- **RLS on all 16 tables**; anon `EXECUTE` revoked on all `SECURITY DEFINER` functions.
- **pg_cron jobs** (registered when `pg_cron` is present; guarded for local): `lumaline-clear-events`
  (hourly, `0 * * * *`), `lumaline-scan-ivt` (every 5 min, `*/5 * * * *`), `lumaline-sweep-windows`
  (every 10 min, `*/10 * * * *`), plus an `rl_buckets` prune job.

---

## 2. Where the published client meets the backend

| Layer | Lives in | Talks to |
|---|---|---|
| Per-tick trust loop | `src/statusline.mjs` | `lumaline-feed`, `window-*` edge fns |
| Pure window state machine | `src/client/window.mjs` | passes the `/window/open` envelope's `keyid` into `cfg.verifyAd` |
| Crypto (Ed25519 verify, HMAC, key fingerprint) | `src/lib/crypto.mjs` | — (Node `node:crypto` only) |
| Rotation-safe trust ring | `src/lib/keyring.mjs` | built from `src/keys/*.pem` + legacy `PUB` |
| Paths + tunables (incl. `KEYS_DIR`) | `src/config.mjs` | — |
| Reversible, consent-only install | `src/install.mjs` / `src/uninstall.mjs` | `~/.claude/settings.json` only |

**Zero runtime dependencies** — Node built-ins only. The `files` allowlist in `package.json` publishes
only `bin`, the four `src/*.mjs` entry files, `src/client`, `src/lib`, `src/keys`, and `README.md`
(never `poc/`, private keys, or `.env`). `package.json` keeps `"private": true` as an intentional guard
against accidental publish during the GitHub beta (removed at GA, M4).

---

## 3. SUPERSEDED — two stale map entries (do not be misled)

These two ideas appear in older docs and **will mislead a future session** if taken as current. They are
explicitly retired here.

### (a) The `verification-protocol-v1` in-memory / `src/server/` design is **NOT the production path**

`docs/superpowers/plans/2026-06-27-verification-protocol-v1.md` describes an in-memory Node verification
server (`src/server/{windows,clicks,server}.mjs`) with `/window/open|beat|close` and `/c/:token`.

- **What it actually is now:** the **dev/test reference implementation** and the **client's unit-test
  backend**. It exercises the exact same window/click *protocol shape* the production RPCs implement, which
  is precisely why the unit tests can prove the verified-window logic without a live database.
- **What runs in production:** the **SQL `SECURITY DEFINER` RPCs + Edge Functions** in §1. The
  authoritative window state, crediting, ledger, and clawback all live in Postgres on
  `prmsonskzrubqsazmpwd`, not in an in-memory server.
- **Net:** treat `src/server/`-style descriptions as the *protocol contract under test*, not the deployed
  system. (Note: there is no shipped `src/server/` in the published client — the production server **is**
  the database + edge functions.)

### (b) The "P0–P6" phase names are **replaced by the M0–M6 milestones**

`docs/superpowers/plans/2026-06-27-production-plan.md` uses "Phase P0–P6" names. The current execution
plan of record is **`docs/superpowers/plans/2026-06-28-production-readiness-handoff.md`**, which
re-sequences the work into **milestones M0–M6** (one milestone per session, legal/money-safety gates
pulled forward, a single explicit test→live cutover at M5). When any doc says "P3" / "Phase 4" etc., map
it to the M-milestones in the handoff plan; the handoff plan wins.

> **Rule of thumb for future sessions:** the **code** (`src/`, `supabase/`) is what *is*; the
> **handoff plan** is what's *planned next*; the older `production-plan.md` and `verification-protocol-v1.md`
> are *historical design context only*.

---

## 4. Proof: the 49 `node --test` tests

`npm test` (`node --test`) is **49/49 green** and is the proof of the verified-window + signed-content
logic (the count grew from 34 → 49 in M0, driven by the `keyid` work + its adversarial-review
hardening). CI runs this gate on every push/PR (M0-T2). Per file:

| Test file | Tests | Proves |
|---|---:|---|
| `test/crypto.test.mjs` | 3 | Ed25519 sign/verify + HMAC primitives. |
| `test/keyring.test.mjs` | 9 | **(new in M0)** keyid selection: present keyid → exact-select, unknown → refuse, wrong-key/tamper → refuse, absent → legacy-default only, next-key trusted, keyid normalization (whitespace/case). |
| `test/keys-bundle.test.mjs` | 4 | **(new in M0)** non-hermetic guard on the SHIPPED `src/keys/` bundle: only public keys; trusts both CURRENT + NEXT keyids; fingerprints match — an incomplete bundle fails CI. |
| `test/windows.test.mjs` | 7 | Server-verified dwell: heartbeat hash-chain, anti-batch spacing, activity gating, min-beats, no-double-bill. |
| `test/clicks.test.mjs` | 6 | Tokenized click redirect + dedup + parent-impression gate. |
| `test/server.test.mjs` | 4 | Signed-feed reference + malformed-input safety (no crash, no oracle). |
| `test/client-window.test.mjs` | 8 | Pure client window state machine, **incl. 2 new keyid-wiring tests** (envelope `keyid` → `verifyAd`). |
| `test/statusline.int.test.mjs` | 1 | First-tick render + audit-log integration. |
| `test/phase1.rpc.integration.mjs` | 7 | Full-window credits one impression; click 302s; re-close does not re-bill. |
| **Total** | **49** | |

---

## 5. M0 as-built deltas (this milestone)

- **M0-T3 — `keyid` multi-key client trust (shipped, rotation-safe).** Signed envelopes now carry a
  `keyid`. `keyFingerprint(pem)` in `src/lib/crypto.mjs` = `sha256(SPKI-DER)[:16]` hex — **content-addressed**,
  insensitive to PEM whitespace, and **not a security control** (the Ed25519 signature is); it only selects
  *which* trusted key verifies. `src/lib/keyring.mjs` `loadKeyring({keysDir, legacyPubPath})` builds a
  `keyid → pem` ring from `src/keys/*.pem` (keyed by **computed** fingerprint — filename is a human hint
  only) plus a legacy/default key. Selection failures are **safe failures**: present-but-unknown keyid →
  refuse; absent keyid → verify against the legacy default only. The feed (`lumaline-feed`) emits
  `keyid = LUMALINE_ED25519_KEY_ID` (undefined ⇒ omitted ⇒ backward compatible). This makes the **first
  Ed25519 rotation non-blackout-safe** before any GA publish.
  - **Bundle today:** `src/keys/public.pem` = **current** key, keyid **`8720926064dfdf50`**;
    `src/keys/next.pem` = **next** key, keyid **`31433cdee001fc81`**. The next key's **private** half is at
    `.secrets/ed25519_next_private.pem` (gitignored) **awaiting Vault custody by the owner** (see Deferral D3).
- **M0-T2 — CI test gate added.** `node --test` runs in GitHub Actions on push/PR (Node 18 + 20); branch
  protection on `main` requires it green. The test count only ever grows.
- **M0-T5 — Provenance release workflow added.** A tag-triggered release workflow builds with
  `--provenance` (OIDC) and runs `prepublishOnly` tests; `npm pack --dry-run` is clean; `"private": true`
  is **retained** (no publish until GA / M4).
- **M0-T1 — `rls_auto_enable` drift captured as a migration.** The only live-vs-migrations object drift was
  one hand-applied object, now captured idempotently in
  `supabase/migrations/20260628000000_capture_rls_auto_enable.sql` (an event trigger `ensure_rls` + function
  `public.rls_auto_enable` that auto-enables RLS on any new `public` table). With this captured, the live
  object set equals the 12 migrations. The stale local `master` branch was deleted.

### Documented OWNER follow-up (non-blocking)

The remote `supabase_migrations.schema_migrations` **history** records only **10 of the 12** versions:
`20260627040000_harden_function_grants` and `20260627041000_rate_limit` were applied out-of-band — their
**objects and grants are live**, but the history rows were never written. A live `INSERT` to reconcile the
history was **correctly blocked by the auto-mode production-write guard**, so it is recorded here as an
**owner action**, not silently dropped:

```
supabase migration repair --status applied 20260627040000 20260627041000 20260628000000
```

All three migrations are **idempotent**, so a future `supabase db push` replaying them is harmless; the
repair only reconciles the *history table*, and nothing is blocked in the meantime.

---

## 5a. M1 as-built deltas (publisher login — code complete, owner-gated for live)

Built local-only (no live writes this session) on `feat/m1-publisher-login`; PR open. Sentinel stays
`gross=0`. New migration `20260629010000_device_code_flow.sql`, new edge fn `auth-device`.

- **M1-T1 — `auth-device` edge fn + the device-code SQL.** RFC 8628: `POST /device/code|token|refresh|logout`,
  `POST /earnings`, `GET /activate`. The **only** minter of a *real* per-publisher device JWT (HS256 over
  `LUMALINE_JWT_SECRET`, the same secret PostgREST verifies; claims `role/aud:authenticated`,
  `sub`=`publishers.auth_user_id`, `publisher_id`, `device_id`; TTL **900s**). Backing RPCs (all
  `SECURITY DEFINER`, `search_path=''`): `device_code_start/redeem/refresh` (**service_role only**),
  `device_code_approve`/`device_revoke`/`ensure_publisher` (**authenticated**, anon/public **REVOKED** —
  Supabase default-priv auto-grant stripped, per [[lumaline-secdef-grant-hardening]]). Only **hashes** of the
  device_code + refresh token are stored.
- **M1-T4 — attribution without touching the trust-critical RPCs.** `lumaline-feed` now `chooseAuth()`s: a
  valid caller device token is forwarded (credit binds to the real `publisher_id`); else the sentinel JWT is
  minted (`gross=0`). On a real-token `window_open` failure (revoked/expired) it retries under the sentinel so
  the user still sees a `gross=0` ad. `window_open/beat/close` already re-check `devices.revoked_at` every
  call — unchanged. The client threads the token as `Authorization: Bearer` only (no new body field; token
  never logged) — data-minimization preserved.
- **M1-T3 — zero-dep client login.** `src/client/auth.mjs`: device-code login, **atomic** 0600 token store
  (temp+rename), silent near-expiry refresh (rotating refresh token), logout (best-effort server revoke +
  local clear). `bin/lumaline.mjs` gains `login`/`logout`/`earnings`; statusline attaches the token; doctor
  shows login state. **At-rest store = a 0600 file, not the OS keychain** — deliberate: the statusline runs a
  fresh process every ~1s and cannot spawn a keychain helper per tick. The token is short-lived + instantly
  revocable on the billing path. **OWNER follow-up (non-blocking):** OS-keychain hardening that keeps the
  hot-path read cheap.
- **M1-T5 — earnings read.** `/earnings` proxies the RLS-scoped `v_publisher_balance` +
  `v_publisher_window_clearing` with the caller's bearer (anon key stays server-side; no key ships in the
  client). `lumaline earnings` renders USD + the "payouts begin at go-live" disclosure.
- **M1-T6 — legal (v1.0, IN FORCE).** `docs/legal/privacy-policy.md` + `publisher-tos.md`, matched to actual
  data flow (UUID-only token, salted IP hash, coarse activity bucket; the `asn` column is **reserved, not
  collected**). **Owner-approved 2026-06-29** (Aivora SRL, Romania); all placeholders resolved — 60/40 split,
  72h clawback, $25 payout min, $100 liability cap, 5-day dispute SLA, 5min/90d/7y retention, EU-rep not
  required, sub-processors Supabase/Stripe/Resend + an SCC international-transfer clause. *(Owner-approved; not
  separately attorney-reviewed.)*

**Verified:** `node --test` **73/0**; the device-code flow + attribution + revocation + refresh + earnings-RLS
proven against a **local Supabase stack** (real Deno runtime + Postgres). Adversarial review: 10 confirmed
findings, all low/medium, 0 critical/high; 7 fixed, 3 deferred to the ledger (D8–D10).

### Owner gate to take M1 LIVE
Legal ✅ done (v1.0 in force). Remaining: enable **Resend** as the Supabase Auth email sender (for
`/activate`) + sign its DPA; apply the migration + deploy `auth-device` (`--use-api`) + redeploy
`lumaline-feed`; merge the PR. See `MILESTONE_STATUS.md` for the list.

---

## 5b. M3 as-built deltas (publisher payout rails — code complete, owner-gated for live)

Branch `feat/m3-payout-rails` (PR #7). Built + verified against a local Supabase stack (real Deno edge
runtime + Postgres); `supabase db reset` applies every migration in-sequence with zero drift.
`node --test` **225 pass / 7 skip / 0 fail**.

**Currency: EUR.** The live e2e found the product was coded in USD while the platform Stripe account
(Aivora SRL) is **RO / EUR / RON, with no USD balance** — so US onboarding/transfers errored. Resolved
(owner decision) by operating in **EUR** end-to-end: payout + billing currency `eur`,
`SUPPORTED_COUNTRIES` = the **EEA** (EU-27 + IS/LI/NO), client/legal/docs in € (€25 min). The micros
model is currency-agnostic (1 EUR = 1,000,000 micros = 100 cents), so no ledger math changed.

**New edge function `stripe-connect`** (`verify_jwt=false`, per-route auth):
- `POST /connect/onboard`, `GET /connect/status` — Express account get-or-create + **Stripe-hosted**
  onboarding link; `/status` reports eligibility. Caller resolved to their OWN publisher via RLS.
- `POST /webhook` — the only unauthenticated route; authenticated by the **Stripe signature**
  (`constructEventAsync` over the RAW body). Dedups on `event.id` (**check-first/record-after-success**,
  5xx on infra failure so Stripe retries), handles `account.updated` (eligibility + country gating) and
  `transfer.reversed` (amount-aware reversal).
- `POST /payout/batch[?dry_run]` — admin: `payout_batch_reserve` → transfer **every** db-pending payout
  (crash-recovery, not just this run) → `payout_confirm`. Idempotency key `lumaline_payout_<id>` + a
  `metadata.payout_id` pre-check (survives Stripe's 24h key expiry). **Never `payout_fail` once a transfer
  may exist** (the critical double-pay fix) — ambiguous errors leave the payout `pending` to self-heal.
- `GET /reconcile?from&to` — admin: DB paid-payout debits vs Stripe transfers **net of reversals**.
- Pure money-decision helpers in `_shared/payout-logic.mjs` (`.mjs` so `node --test` imports them):
  `classifyTransferError`, `sumLumalineTransfersMicros`, `reversedMicrosFromTransfer`.

**New migrations:**
- `20260629080000_resolve_dispute.sql` — admin dispute resolution (M2 carry-forward).
- `20260629090000_gdpr_deletion.sql` — `gdpr_delete_publisher()`: anonymize-in-place, ledger preserved +
  still zero-sum, refuses while a payout is in flight.
- `20260629100000_payout_rails.sql` — `payout_batch_reserve` (one-active-per-publisher unique index =
  reservation lock; **ledger booked at confirm, not reserve**), `payout_confirm`/`payout_fail`/
  `payout_reverse`, `app.publisher_payable_micros` (matured CPVA − already-paid, **loud CPC guard** until
  M4), `payout_recon_totals`, `set_publisher_payout_eligibility`, `stripe_webhook_events` dedup table.
  All money RPCs `service_role`-only.
- `20260629110000_payout_rails_hardening.sql` — adversarial-review fixes: per-row CPC-guard isolation
  (one publisher can't freeze the batch), **floor payable to whole cents** (carry the remainder), and
  **amount-aware `payout_reverse`** (cumulative reversed, idempotent; partial keeps `paid`).

**Ledger convention (payout):** `publisher_earnings` **+amount** / `platform_cash` **−amount** at confirm
(reduces what is owed); the mirror at reverse. `payable = matured cpva earnings − already-paid`.

**Money-safety:** the 7-day payout hold is strictly greater than the 72h clawback window, so cleared
earnings are only ever paid after they can no longer be clawed back.

**Internal adversarial review (2026-06-30):** 6 dimensions × 3-lens refutation; **11 confirmed, all
fixed** (1 critical double-pay, 2 high, 3 medium — see `MILESTONE_STATUS.md`). This is NOT a substitute
for the **external** money-path security review (M3-T7, owner-gated, hard gate for M5).

**Real-Stripe (test) e2e (2026-06-30)** — local stack + real Stripe test API + `stripe listen`:
- ✅ T1 onboarding: real Express account + hosted onboarding link created (EUR/EEA).
- ✅ T1 webhook: a real Stripe-signed `account.updated` delivered over live HTTP → signature verified → 200.
- ✅ T2 transfer call: real `transfers.create`, EUR accepted; **both double-pay-safe branches exercised
  against live Stripe errors** — ambiguous → payout left `pending` (no ledger); definitive capability
  error → `payout_fail` (no ledger, payable restored). Reservation lock + per-publisher CPC skip +
  cent-floored reserve confirmed live. (Found + fixed a classifier gap: the Deno esm.sh Stripe build
  surfaces `err.rawType` (snake-case), so `classifyTransferError` now treats `invalid_request_error` as
  definitive too.)
- ⏳ NOT proven (owner step): a fully-COMPLETED money-landing transfer + recon — the destination needs the
  `transfers` capability **active**, which needs the Connect **platform profile** configured (Custom
  accounts) OR one **browser** Express onboarding.

**⚠️ Remote state:** the project `prmsonskzrubqsazmpwd` is at **M1** — M2 was merged to `main` but **never
deployed** there (no `disputes`/`advertiser_charges`/`billing`/`admin-booking`), and M1's `device_code_flow`
is re-stamped `20260629114856` (drift). So the remote deploy must reconcile the drift and ship **M2 then M3**.

### Owner gate to take M3 LIVE
Authorize the production deploy of **M2 (migns `020000..070000` + `billing` + `admin-booking`) then M3**
(`stripe-connect` + migns `080000..110000`) to `prmsonskzrubqsazmpwd`, reconciling the M1 drift; cc creates
the Connect webhook endpoint via the Stripe API → `STRIPE_WEBHOOK_SECRET` in Vault; configure the Connect
platform profile (or do one browser Express onboarding) for the completed-transfer verify; then live
test-mode verify (onboarding + a real completed EUR transfer + recon). Sign `publisher-tos.md §7` (EUR).
T6 monitoring, T7 external review, T8 publisher dashboard remain owner-supplied.

### ✅ M3 REMOTE DEPLOY — DONE (2026-07-01, `prmsonskzrubqsazmpwd`, Stripe TEST/sandbox)

Path B executed against the production project (owner-authorized). All writes via the ref-guarded PAT
runner (asserts ref before every query) + the Supabase CLI (`--use-api`); never the Supabase MCP.

- **Drift reconciled** — the M1 `device_code_flow` ledger row was re-stamped `20260629114856 → 20260629010000`
  (version-only `UPDATE`, name/statements preserved). Pending set then = exactly the 11 M2+M3 migrations.
- **Migrations applied in order (atomic DDL + ledger row each)** — M2 `020000..070000`, M3 `080000..110000`.
  Remote `schema_migrations` == the 26 local files, 0 orphans. Object set == migrations (all M2/M3 tables,
  RPCs, views present).
- **Edge fns deployed** (`--use-api`, `_shared/{cors,jwt}.ts` + `payout-logic.mjs` bundled) — `billing`,
  `admin-booking`, `stripe-connect`; all `verify_jwt=false`, ACTIVE. (Full set live: `lumaline-feed`,
  `auth-device`, `click`, `billing`, `admin-booking`, `stripe-connect`.)
- **🔒 Security fix surfaced by `get_advisors`** — deploying M2 (never advisor-checked on remote) exposed a
  **publicly-reachable `SECURITY DEFINER` view** `public.uncharged_advertiser_billings` granted to `anon`
  (advertiser billing data readable with the anon key, bypassing RLS — 1 ERROR) plus two anon-executable
  SECDEF fns (`billing_recon_totals`, `check_house_bids` — 2 WARN). Root cause = the Supabase default-priv
  grant gotcha (migrations granted `service_role` but never revoked the auto-granted anon/authenticated).
  Fixed forward in **`20260629120000_secdef_grant_hardening.sql`** (revoke anon/authenticated + `security_invoker=on`).
  Post-fix advisors: **0 ERROR/CRITICAL** (remaining 15 WARN = accepted-by-design self-scoping RPCs + email-OTP).
  `supabase db reset` applies all 26 clean; `node --test` **225 tests / 218 pass / 7 skip / 0 fail**.
- **Webhook wired** — a Connect endpoint (`account.updated`) created via the Stripe API against
  `…/functions/v1/stripe-connect/webhook`; its `whsec` stored in Vault as `STRIPE_WEBHOOK_SECRET` (never
  logged); `stripe-connect` redeployed. Verified: missing-sig → **400**, bad-sig → **400** (secret loaded).

**✅ Live test-mode e2e on the remote (2026-07-01) — the completed transfer, previously owner-blocked, is now proven:**
- Onboarding: a **headless Custom** connected account (after the owner acknowledged the Connect platform
  profile) filled entirely via API (identity + address + DOB + ToS + RO test IBAN) → `transfers: active`,
  `payouts_enabled: true`.
- **Live webhook** on the remote: a real Stripe-signed `account.updated` → verified vs `STRIPE_WEBHOOK_SECRET`
  → deduped → `set_publisher_payout_eligibility` → publisher `verified`.
- **Completed EUR transfer**: platform EUR balance funded (`pm_card_bypassPending`); `/payout/batch` (admin) →
  reserve → real `transfers.create` **€30.00 EUR** (`tr_…`) → `payout_confirm` booked the balanced ledger
  group (`publisher_earnings +30M / platform_cash −30M`, sum 0); payable → 0.
- **Reconcile**: `/reconcile` **green** (DB 30,000,000 == Stripe 30,000,000, discrepancy 0). After a real full
  transfer reversal it correctly flips to **`ok:false` (DB 30M vs Stripe 0)** — the reversal-detection backstop.
- **`transfer.reversed` → `payout_reverse`** proven live: the real event delivered to the deployed fn →
  inverse ledger booked (group nets 0), `reversed_micros=30M`, payout `failed`, payable **restored** to €30.
- All e2e test data cleaned up (DB rows + Stripe test accounts deleted); ledger back to 0 legs, `app.admins` empty.

**Production note (webhook delivery gap, M4 follow-up):** the registered endpoint is `connect=true`, so it
receives connected-account `account.updated` but **not** platform-owned `transfer.reversed` (which routes to
platform endpoints). The single-secret function can't verify two endpoints, so auto-reversal handling is
deferred: today `/reconcile` **detects** reversals (proven above) and `payout_reverse` is applied by resend/operator;
M4 adds a platform endpoint + multi-secret verification. Also `LUMALINE_APP_URL` is unset → the onboarding
return/refresh default to `localhost:3000`; set it to the real payouts-return page at M4.

**Still owner-gated after the deploy:** app.admins seeding of the real admin UUID for production ops; sign
`publisher-tos.md §7` (EUR); **T6** money-path monitoring; **T7** external security review (hard M5 gate);
**T8** publisher dashboard; the **M5** test→live key swap (never done here — TEST only). Merge PR #7.

---

## 5c. M4 as-built deltas (branded domain + CPC money-path + GA-publish prep — TEST mode)

Branch `feat/m4-cpc-and-branded-url` (13 commits, base `main` after PR #9). Spec/plan:
`docs/superpowers/specs/2026-07-01-m4-cpc-money-path-and-url-plumbing-design.md` +
`docs/superpowers/plans/2026-07-01-m4-implementation.md`. Executed subagent-driven; ops steps (remote
apply, Cloudflare, Stripe, deploys) driven by the ref-guarded PAT runner + Supabase CLI, never the MCP.
Stays **TEST mode** — the live-key swap is still M5.

- **D1 — CPC folded into the money-path (1 migration).** `20260701090000_cpc_billing.sql` extends
  `public.uncharged_advertiser_billings` with a **UNION branch that joins `public.clicks`**: CPC ledger
  legs carry `source_type='click'`, `source_id=clicks.id`, `impression_id IS NULL`, so the advertiser is
  resolved `clicks → line_items → campaigns → advertisers` (not the CPVA `impressions` path). `billing_recon_totals`
  and `app.v_billing_recon` now filter `event_type IN ('cpva_accrual','cpc_accrual')`. `app.publisher_payable_micros`
  **drops the loud CPC RAISE guard** and adds a clicks-joined CPC-earned term (`RETURN v_earned_cpva +
  v_earned_cpc - v_paid`). The migration re-asserts `security_invoker=on` + REVOKE anon/authenticated +
  GRANT service_role on both views. `/billing/charge` is **view-driven → no edge-fn change**. Applied to
  remote (**27 migrations**, advisors **0 ERROR/CRITICAL**). **Acceptance #2 proven on remote**: a seeded
  cleared CPC group resolves through the clicks branch → `/billing/charge?dry_run` lists it (`would_charge=1`).
- **D4 — client defaults flipped to the branded domain.** `src/config.mjs`: `FEED_BASE` default →
  `https://feed.lumaline.dev/lumaline-feed`; **new `CLICK_BASE`** = `LUMALINE_CLICK || https://c.lumaline.dev`;
  `AUTH_BASE` derives to `https://feed.lumaline.dev/auth-device`. Env overrides preserved. `test/config-urls.test.mjs`
  (3 tests) pins the branded defaults + override behaviour.
- **T1b — Cloudflare reverse-proxy (domain live in Cloudflare).** Worker `lumaline-proxy` + Custom Domains
  `feed.lumaline.dev` and `c.lumaline.dev` (auto DNS + TLS), zone `28a0e8867b12d3b35abf869c6a577399`. It host+path
  rewrites `feed.lumaline.dev/<fn>/*` → `…/functions/v1/<fn>/*` and `c.lumaline.dev/*` → `…/functions/v1/click/*`
  (drops the inbound `host`). **The Ed25519-signed feed still verifies through the branded host** (keyid
  `8720926064dfdf50` — signing is domain-agnostic, so the trust thesis holds across the proxy). As-built:
  `docs/ops/cloudflare-proxy-worker.js`.
- **D2 — feed emits a branded tokenized click redirect.** `lumaline-feed` emits
  `clickUrl = token ? ${CLICK_BASE}/c/${token} : dest` (`LUMALINE_CLICK_BASE` set on remote); the `click` fn's
  `extractToken` now **skips a leading `/c/` segment** (bug found during verify: it had returned the literal
  `'c'` as the token). Redeployed. **Verified e2e**: feed → `c.lumaline.dev/c/<token>` → **302** → destination.
- **D3 — multi-secret webhook verify + platform endpoint (closes the M3 §5b delivery gap).** New
  `_shared/webhook-secrets.mjs` `parseWebhookSecrets()` (comma-split); `stripe-connect` verifies an event
  against **each** configured secret (raw body read once, try each, 400 if none, 503 if zero configured).
  A **platform endpoint** `we_1ToQ5kCChUMF5SBOkkIbkaXO` (`transfer.reversed` + `transfer.canceled`,
  `connect=account`) was created; Vault `STRIPE_WEBHOOK_SECRET` is now the **comma-split pair**
  `<we_1To11 connect secret>,<platform secret>`; `stripe-connect` redeployed. **Verified on remote**:
  platform-signed `transfer.reversed` → **200**, `we_1To11`-signed `account.updated` → **200** (backward-compat
  holds), bogus secret → **400**. The stale `we_1To11` Connect endpoint is **kept** (owner revealed its secret;
  nothing deleted). Auto `transfer.reversed` is now handled inline — defense-in-depth over the `/reconcile` backstop.
- **D5 — `LUMALINE_APP_URL=https://lumaline.dev`** set in Vault (onboarding return/refresh no longer default
  to `localhost:3000`); `stripe-connect` redeployed.
- **D6 (README) — OSC-8 scoping + per-release re-test checklist.** README documents CPC status-bar clicks as
  **IDE-terminals-only today** (upstream regression #26356, last-good v2.1.2) and adds a per-release re-test
  checklist so the standalone-terminal fix is picked up when it lands. No client-side fix exists.
- **Tests.** Unit `node --test` grew to **147 pass / 0 fail** (new hermetic guards `cpc-billing.test.mjs`,
  `webhook-multi-secret.test.mjs`, `config-urls.test.mjs`). New integration files (`cpc-billing.integration.mjs`,
  W8–W11 in `stripe-connect-webhook.integration.mjs`, P17 in `payout-rails.integration.mjs`) **self-skip cleanly**
  without the local Supabase stack; full-suite count only grows from 225 (runs green in CI/local-stack).

**✅ T4 GA npm publish — DONE 2026-07-01. `lumaline@0.1.0` is LIVE on npm** with SLSA v1 provenance
(`dist-tags.latest=0.1.0`; registry `[0.0.1, 0.1.0]` — supersedes the 0.0.1 reservation stub). Path: removed
`"private": true` → owner merged PR #10 (then a follow-up merge #11 landed the flip on `main`, tip `88d38a7`) → tag
`v0.1.0` → `.github/workflows/release.yml` ran the fail-closed tarball audit (15 files; public verify keys
`public.pem`+`next.pem` only; no `poc/`/`.env`/private key) + `node --test` gate + `npm publish --provenance`. Auth
required an npm **Automation** token (a classic *Publish* token hit `EOTP` — 2FA can't be satisfied non-interactively
in CI); the token is now the repo secret `NPM_TOKEN`. Both a final `/security-review` (0 findings) and a code review
were clean before publish. Future GA bumps: version bump → merge to `main` → push a `v*` tag.

---

## 6. Deferral ledger

Genuine deferrals, recorded so none is silently lost. Each names the **reason** and the **milestone/owner**
that closes it.

| ID | Deferred item | Reason it's safe to defer | Closes at |
|---|---|---|---|
| **D1** | **Public transparency / clearing report** (aggregate fill, credited views, clearing prices, publisher-share %, clawback rate). | **This is the product thesis** — transparency is the whole pitch vs. invasive monetizers — so it is **explicitly tracked, never dropped**. It needs real cleared traffic to report on, which only exists after paid demand (M2) and go-live (M5). Figures must reconcile to the ledger and stay non-PII (data-minimization invariant). | **M6** (M6-T5) |
| **D2** | **Second-price auction.** | With a **single advertiser**, a full second-price auction is dead code. **First-price / reserve-floor clears today.** The schema **retains the clearing-price column** so the second-price upgrade is **non-breaking** when multiple advertisers exist. | **Post-multi-advertiser** (designed into M2-T1 serving) |
| **D3** | **Next-key private custody in Vault.** | The `keyid` mechanism + the **public** next key (`31433cdee001fc81`) ship now so clients trust it *before* the feed flips. | ✅ **DONE 2026-06-29** — next private stored in Vault as `LUMALINE_ED25519_NEXT_PRIVATE_KEY` (byte-verified vs the local PEM), disk copy shredded. |
| **D4** | **`schema_migrations` history repair** (the 2 out-of-band versions + the drift-capture row). | Objects/grants were already live and the migrations are idempotent; the gap was the **history table** only. | ✅ **DONE 2026-06-29** — history reconciled to **13** versions; future `db push` is clean. |
| **D5** | **Per-publisher earnings / payouts** (device-code `lumaline login`, attribution off the sentinel, Stripe charging + Connect payouts, money-safety gates, independent security review). | The beta is intentionally **sentinel-only, `gross = 0`, never billed** — *see it live today, not get paid today*. The full money machine is built + proven in **Stripe test mode** before a single real dollar moves, behind legal and security gates. | **M1–M3** (test mode), **M5** (live go-live) |
| **D6** | **Branded domain + CPC measurement + GA npm publish.** | Installed clients don't self-update, so GA must ship on the **stable branded URL** and **rotation-safe** (the M0 `keyid` work is its hard prerequisite). Until then the beta installs via `npm i -g github:JaamesBond/LumaLine`. CPC is also gated by upstream OSC-8 bug #26356 (clicks in IDE terminals only today). | **M4 — ✅ DONE 2026-07-01** (§5c): branded domain + CPC money-path + **GA npm publish `lumaline@0.1.0` LIVE** (SLSA provenance). |
| **D7** | **Scale / ops deferrals:** load-test validation of the ~15k writes/s ceiling, richer IVT heuristics (data-min-safe), advertiser API keys, full dashboards/on-call runbook, DR-at-scale. | Not on the money-honesty critical path; the money-critical alerts (ledger-imbalance, payout-failure, reconciliation) land earlier at M3-T6. | **M6** |
| **D8** | **M1 — orphaned `open` window** when a revoked device's `window_open` is retried under the sentinel (the client keeps sending its real token, so the sentinel window's beats/close 401 and it never closes). | **Harmless:** `gross=0`, never credits, no double-bill, no crash; the access token expires in ≤15 min and the existing Phase-4 `sweep_stale_windows` cron abandons stale-open rows. | **M4/M6** (optional: signal client demotion in the open reply) |
| **D9** | **M1 — refresh token has no absolute lifetime + no reuse-detection** (OAuth refresh-rotation BCP). | Bounded by the short **900s** access TTL, 0600 at-rest storage, **manual `device_revoke`**, and the per-window `revoked_at` re-check on the billing path. No payouts until M5. | **M3** (security review): add `devices.refresh_expires_at` + superseded-hash reuse detection → auto-revoke device family |
| **D10** | **M1 — `/earnings` does not re-check `devices.revoked_at`** (a token minted just before logout can read its *own* earnings until exp ≤15 min). | **Self-data only**, RLS-scoped to the caller; zero billing/cross-publisher impact; time-bounded by the short TTL. | **M3** (add a server-side `revoked_at` check on the `/earnings` handler) |
| **D11** | **M4 — CPC advertiser charges have no automated Stripe refund path.** The refund handler (`billing/index.ts`) looks up `advertiser_charges` by `impression_id`, but CPC charges carry `impression_id = NULL`, so a CPC charge can only be **manually** refunded via Stripe today. | **Internal ledger stays correct**: `public.clawback` reverses *both* the impression and click ledger groups for the window, so this is missing Stripe-side *automation* only, not ledger corruption. M4's scope was "wire CPC into the money path"; M4 creates the precondition, so the refund automation is a tracked follow-up. Manual refund remains available. | **M5/M6** (add a click-keyed branch to the refund handler + `clawback_reviews`) |
| **D12** | **M4 — webhook integration tests W8/W9/W11 hard-fail (don't skip) on a partially-configured stack.** They assert `200` for platform/connect-signed events, so a `supabase functions serve` running with only the local dev secret yields `400` → red instead of skip. | Cosmetic test-hygiene gap: the whole integration suite already requires a manually-configured stack + `.env` (the header documents the two-secret precondition); a correctly-configured stack passes. W10 (asserts `400`) is robust regardless. No production impact. | **M6** (gate W8/W9/W11 on served-secret presence) |

---

## 7. Trust invariants (binding on every change)

1. **Official `statusLine` only** — no bundle patching, CSP changes, or DOM injection.
2. **Signed content only** — refuse any ad that fails Ed25519 verification, **including an unknown `keyid`**.
3. **No install side-effects** — no `postinstall`, no self-update; wiring only via explicit `lumaline install`,
   fully reversible by `uninstall`.
4. **Honest billing** — credit only after a full server-verified dwell; never on idle; the **sentinel
   (`gross = 0`) is never billed** (to become a DB CHECK at M2-T2).
5. **Data minimization** — only `{ windowId, seq, hmac, activity-bucket, ts }` (+ salted, non-reversible IP
   hash) leaves the machine; everything mirrored to the local audit log.
6. **Zero runtime dependencies** — Node built-ins only.
7. **Secrets never committed** — Ed25519 private key + device-JWT secret live only in Supabase Vault.

---

## 8. Pointers

- **What IS (code):** `src/statusline.mjs`, `src/client/window.mjs`, `src/lib/crypto.mjs`,
  `src/lib/keyring.mjs`, `src/config.mjs`; `supabase/migrations/` (12 + the drift-capture migration);
  `supabase/functions/` (`lumaline-feed`, `click`, `window-open|beat|close`, `_shared`); `test/` (49 tests).
- **What's PLANNED (docs):** `docs/superpowers/plans/2026-06-28-production-readiness-handoff.md`
  (**plan of record**, M0–M6); `docs/superpowers/specs/2026-06-27-verification-and-economics-design.md`
  (money + threat model).
- **Historical / superseded context only:** `docs/superpowers/plans/2026-06-27-verification-protocol-v1.md`
  (in-memory design → now the dev/test reference, §3a),
  `docs/superpowers/plans/2026-06-27-production-plan.md` (P0–P6 → replaced by M0–M6, §3b).
