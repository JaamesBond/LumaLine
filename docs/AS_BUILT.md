# LumaLine — AS-BUILT Reconciliation & Deferral Ledger

**Status:** Authoritative map of what *is built* vs. what the older design docs *describe*.
**As of:** 2026-07-26. **M0–M9 DONE + merged + DEPLOYED.** First real advertiser charge **€1.10
settled + reconciled 2026-07-04** (§5d). All three self-serve dashboards **live on lumaline.dev**
(M7 publisher `/app`, M8 admin, M9 advertiser — §5f); **advertiser deposits LIVE 2026-07-23**
(prepaid non-refundable ad credit, ToS v2.0 in force). Security-audit hardening **deployed
2026-07-22** (§5g). Payouts reach **34 countries** (EEA + US/GB/CA/CH, §5h). Client `lumaline@0.1.7`
= npm latest. **GDPR account-lifecycle Phases 1–3 merged AND fully deployed 2026-07-26** — `main`
and prod are both at 75 migrations (§5i). **Open:** first REAL publisher payout (§5h note on RO
law), issue #45 (integration suite vs the concurrent-open cap). GDPR Phase 3 is **fully
operational**: `auth-device` v21 deployed and the completion cron `lumaline-gdpr-complete-pending`
scheduled hourly at `:23` (§5i).
**Backend project:** Supabase `prmsonskzrubqsazmpwd` (the LumaLine project — **not** the unrelated CRM `kvlfpwzmjxuapjheknnj`).

> **Security-audit hardening (2026-07-22, PR #39 — MERGED + DEPLOYED):**
> a two-pass internal adversarial audit closed a set of farming / DoS / self-click / Sybil / chargeback
> residuals on the LIVE surface — see **§5g** and deferral **D13–D15**. All 20 migrations applied to
> prod + 7 edge fns redeployed 2026-07-22. No client change; wire-compatible.

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
   The heartbeat hash-chain **sequences** beats and is third-party tamper-evident; it is **not** an
   attention proof against the publisher (the per-window challenge is the shared HMAC key). Farming is
   gated server-side: **in-DB per-device velocity + concurrency caps in `window_open`** (concurrency ≤6
   open/device, ≤30 opens/min/device, ≤120/min/publisher; sentinel exempt), **per-device/IP `scan_ivt`**,
   and the 72h clawback.
3. **Honest billing.** A real impression is recorded only after a full, activity-backed dwell; idle never
   bills. The beta **sentinel** (self-promo) identity is `gross = 0` and is **never billed**.
4. **Click redirect.** `click` Edge Function 302-redirects through a tokenized URL. The single-use
   token is **minted by `lumaline-feed` and embedded only inside the Ed25519-signed `adData.clickUrl`**
   (`window_open` stores only its hash and no longer returns the raw token to any caller); `click_resolve`
   RPC records the click with `click_token_hash UNIQUE` dedup and a cleared-parent-impression billability gate.
   **Self-click is neutralized (pass-2, §5g):** `click_resolve` is now **`service_role`-only** (the direct
   `/rest/v1/rpc/click_resolve` path is revoked) and **voids same-IP clicks** — a click whose salted clicker-IP
   hash equals the serving window's `ad_windows.ip_hash` is the serving machine (the honest single-user
   terminal case) and is recorded `void`, never billed; `scan_click_ivt` velocity-flags cross-IP click farms.
5. **Ledger + clawback.** Cleared revenue posts to a **double-entry, publisher-favored 60/40 ledger**
   (`ledger_entries`), with a **72-hour clawback window** and invalid-traffic scanning feeding `risk_flags`.

### SQL RPCs (`SECURITY DEFINER`)

| RPC | Role |
|---|---|
| `window_open` | Issue a server window; **in-DB per-device velocity + concurrency caps (the real fraud gate; edge RL is bypassable)**; stamps a salted IP hash for IVT. No longer returns a click token. **Serve path excludes dispute-held advertisers** (`dispute_hold_at`) and self-deal advertiser-users (pass-2). |
| `window_beat` | **Sequence** the heartbeat hash-chain (third-party tamper-evident; anti-batch timing). Not an attention proof vs the publisher. |
| `close_window` | Finalize the dwell, idempotently credit one impression. |
| `click_resolve` | Record a click (token-hash dedup, parent-impression gate); **`service_role`-only + same-IP self-click void** (pass-2, §5g). |
| `clawback` | Reverse a cleared entry within the 72h window (internal ledger reversal). |
| `scan_ivt` | Invalid-traffic scan → `risk_flags`, **per publisher + per device + per IP-hash**; every 2 min (faster than clearing). |
| `sweep_stale_windows` | Mark abandoned open windows. |
| `clear_events` | Periodic clearing pass. |
| `rl_hit` | Salted-IP-hash DB rate-limit counter (`rl_buckets`); paired with a **per-isolate in-memory fallback** in the edge so the no-salt/no-DB path is no longer silently fail-open. |
| `scan_click_ivt` | Click-side IVT scan: per serving-device / publisher / serving-IP velocity → `risk_flags` (`ivt:click:*`) + pending `clawback_reviews`; every 2 min (pass-2). |
| `scan_publisher_sybil` (`app.*`) | Flags ≥3 distinct publishers sharing one salted `ad_windows.ip_hash` → payout **hold** (`sybil:shared_ip`, `verified→pending`); **never auto-clawback**; daily (pass-2). |
| `monitor_fleet_velocity` | READ-ONLY fleet counters (provisional impressions, new publishers/devices, distinct IP-hashes) for the `monitor` `fleet_velocity` HIGH check (pass-2). |
| `signup_throttle_hit` | Durable fixed-window signup/device-code counter (fail-**closed** on empty scope); `service_role`-only (pass-2). |
| `admin_clear_advertiser_dispute_hold` | Clears `advertisers.dispute_hold_at`; gated on the aal2 `app.money_admins` tier (same as `admin_open_clawback`); pass-2 A9. |

**`app.*` helpers (private schema):** `app.accrue`, `app.activity_rank`, `app.current_publisher_id`,
`app.is_admin`, `app.jwt_claim`, `app.ledger_group_balances`, `app.set_updated_at`, plus the `app.admins`
table.

### Edge Functions (`supabase/functions/`)

`lumaline-feed` (signed feed + rate-limit guard, emits `keyid`), `click` (302 redirect), `window-open`,
`window-beat`, `window-close`, and `_shared`. **(pass-2, §5g)** `_shared` gains a single
**trusted-client-IP + salted-hash derivation** consumed by `lumaline-feed`, `click`, and `auth-device`,
so the serving-window hash and the clicker / signup hash are byte-identical (standard-base64
`sha256(LUMALINE_RL_SALT || ip)`); the `monitor` fn gains the `fleet_velocity` + `postpay_chargeback` checks.

### Schema (the 12 migrations on `main`)

- **16 tables:** `publishers`, `devices`, `device_auth_codes`, `advertisers`, `campaigns`, `line_items`,
  `creatives`, `ad_windows` (**UNLOGGED**), `impressions`, `clicks`, `ledger_entries`, `payouts`,
  `serve_counters`, `line_item_daily_stats`, `risk_flags`, `rl_buckets`.
- **3 views:** `v_publisher_balance`, `v_publisher_window_clearing`, `v_campaign_delivery`.
- **Double-entry 60/40 ledger** with a zero-sum trigger; **72h clawback window**.
- **RLS on all 16 tables**; anon `EXECUTE` revoked on all `SECURITY DEFINER` functions.
- **pg_cron jobs** (registered when `pg_cron` is present; guarded for local): `lumaline-clear-events`
  (hourly, `0 * * * *`), `lumaline-scan-ivt` (every 2 min, `*/2 * * * *`), `lumaline-sweep-windows`
  (every 10 min, `*/10 * * * *`), plus an `rl_buckets` prune job — plus (pass-2, §5g)
  `lumaline-scan-click-ivt` (every 2 min), `lumaline-sybil-fleet-scan` (daily `41 3 * * *`), and a
  `signup_throttle_buckets` prune (every 5 min).

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

## 5d. M5 as-built deltas (production money GO-LIVE — test→live cutover, REAL money)

M5 is the single, fully-gated test→live cutover. It is **effectively live**: real charges settle on
`sk_live`. See memory `[[lumaline-production-handoff-plan]]` for the blow-by-blow.

- **M5-T3 — FIRST REAL CHARGE ✅ 2026-07-04.** **€1.10 collected on a real live card** (PI
  `pi_3TpUM5CChUMF5SBO015yREeI`, batch `6b09f5ad…`), **22 CPVA impressions aggregated into ONE
  PaymentIntent**, `/reconcile` **GREEN** (discrepancy 0), owner received the Stripe email. The charge
  blocker was fixed first: per-advertiser aggregation via a stable `charge_batch_id` + single-flight
  lock — migration **`20260704140000_billing_aggregate_batch.sql`** (on prod, billing fn redeployed,
  PR #31 `fix/billing-aggregation`). Adversarial review found + closed F1 double-charge / F2 no-lock /
  F3 stranded batch / F5 house before the GO.
- **Related prod fixes:** the **refresh-token crash-mid-rotation** grace window
  `20260704120000_refresh_token_grace_window.sql` (Auth0-style reuse-interval, PR #30); the
  **dwell-latency under-credit** ("dwell too short" at edge latency) — client **0.1.2** +
  `20260703010000_close_window_dwell_tolerance.sql` (2026-07-03); auth email via **Resend SMTP** on
  `send.lumaline.dev` + the `/activate` page consuming the magic link + auto-approving (2026-07-03).
- **M5-T4 — first REAL payout: rails MERGED (PR #32 `feat/m5-t4-auto-payout`), first payout PENDING.**
  Migration **`20260704150000_auto_payout.sql`** — weekly `run_payout` pg_cron target, `connect_nudge_at`
  + publisher-contact/nudge-candidate RPCs; branded **paid / connect-nudge emails** (`_shared/email.mjs`).
  The first real payout was blocked on accrual (publisher 60% = €0.66 < the €25 default min) → needs more
  accrual or a lower `LUMALINE_PAYOUT_MIN_MICROS` (the edge default is €1). **Prod deploy of the
  auto-payout migration is owner-gated (M5-T4 runbook, commit `0e55541`) — verify current prod state at
  session start.**
- **M5-T6 — money-path monitoring ✅.** `monitor` edge fn + `app.alert_events` (migration
  `20260702010000_money_monitoring.sql`): ledger zero-sum, stuck/failed payouts, failed charges,
  billing+payout recon-drift; alert emails on state change; `app.run_monitor` cron.
- **M5-T7 — independent external security review:** owner-gated; **status unverified in-repo** — confirm.

## 5e. M6 as-built deltas (scale / ops / observability + transparency)

The safe (non-money-path) slice of M6 is merged; the money-touching parts are deferred behind M5
validation.

- **M6-T1 — dashboards + on-call runbook ✅ (PR #28).** Read-only ops tooling `scripts/ops/*`
  (`dashboard.mjs`, `watch-billing.mjs`, `sql.mjs`) + the on-call runbook (`docs/ops/oncall-runbook.md`).
- **M6-T5 — public transparency / clearing report ✅ (PR #28).** `scripts/ops/transparency-report.mjs`
  → `docs/transparency-report.{json,md}`, reconciles to the ledger, non-PII (closes deferral **D1**).
- **M6-T2 — window-protocol load harness ✅ built + merged (PR #29 `m6/t2-load-harness`).**
  `scripts/load/harness.mjs` + libs; guarded "build local, DO NOT run vs prod" — the **run against prod
  is owner-gated**.
- **M6-T3 — richer IVT + activity-delta envelope: DEFERRED** (`DEPENDS-ON: M5` — edits the live
  clearing/clawback path; unblock only after M5 charge/payout validated).
- **M6-T4 — advertiser API keys: DEFERRED** (avoid a new prod migration during money validation).

## 5f. M7–M9 as-built deltas (self-serve dashboards — ALL THREE MERGED + DEPLOYED)

> **Outcome (2026-07-18→21):** M7 publisher portal (PR #33), M8 owner/admin dashboard (PR #34,
> aal2 `money_admins` tier), M9 advertiser portal (PR #35, prepaid ad-credit + DB-as-boundary RLS)
> all merged to `main` and deployed; dashboards live on lumaline.dev 2026-07-21. **Advertiser
> deposits went LIVE 2026-07-23** (webhook + secret wired, ToS v2.0 in force, kill-switch lifted).
> The section below is the M7 design record as written pre-merge.

**M7 = go-wide self-serve dashboards** (publisher → owner → advertiser). Three sub-projects, each its
own brainstorm→spec→plan→build. Plan: `~/.claude/plans/look-at-m7-and-harmonic-wreath.md`. Scope doc:
`docs/superpowers/2026-07-05-dashboards-planning-handoff.md`. Memory: `[[m7-publisher-portal]]`.

**Publisher portal — BUILT + e2e-verified 2026-07-05; NOT committed/deployed.** Backend work is
uncommitted on branch **`feat/m7-publisher-portal`**; frontend lives in the separate marketing repo
`~/projects/luma-line-edf7d51e` working tree. Locked decisions: portal lives as authed `/app/*` routes
**inside the Lovable marketing repo** (TanStack Start + shadcn); web auth = a **direct Supabase Auth
session** (magic-link) → `auth.uid()` RLS ("Scheme A"), NOT the CLI device JWT; advertiser prepay +
CPVA-only were chosen for the later advertiser portal.

- **Backend (3 migrations + 2 test suites, `node --test` 18/18 green after local `db reset`):**
  - `20260705120000_gdpr_self_delete.sql` — self-serve erasure. Extracts the shared erasure body into
    `app.gdpr_erase_publisher(uuid)`; admin `gdpr_delete_publisher(uuid)` now delegates; new
    `public.gdpr_self_delete()` takes **no arg**, self-derives from `app.current_publisher_id()` (can't
    target another publisher), keeps the payout-in-flight guard + anonymize-in-place. Granted `authenticated`.
  - `20260705130000_publisher_earnings_summary.sql` — SECURITY DEFINER STABLE, self-scoped; returns
    `{matured,held,lifetime,paid,balance}_micros`. `matured` reuses `app.publisher_payable_micros(pid,'7 days')`
    so the number shown agrees with what a payout actually pays; `held = balance − matured`.
  - `20260705140000_v_publisher_devices.sql` — view omitting `refresh_token_hash` (`security_invoker=on`),
    so the exclusion is DB-enforced, not client discipline.
  - Tests: `test/gdpr-self-delete.integration.mjs` (S1–S8), `test/publisher-earnings-summary.integration.mjs`
    (E1–E4). Existing `gdpr-deletion.integration.mjs` stays green (refactor-safe).
- **Frontend (Lovable-safe: all new code under `src/routes/app/*`, `src/routes/{login,payouts/onboard}.tsx`,
  and `src/features/app/*`; never touches `src/integrations/supabase/*`; uses the isolated `lumaline`
  client only).** Pages: Overview, Earnings, Payouts + bank-connect (3-state onboard badge +
  `/payouts/onboard` return route), Setup, Account (devices revoke + delete danger flow). `ssr:false` +
  a client-aware tri-state auth gate. `npm run build` passes.
- **e2e-verified via Playwright against the local stack** (a demo publisher seeded with earnings): unauth
  `/app`→`/login`; authed pages render correct RLS data via the web session (earnings summary, window
  clearing, devices view, payouts, connect status); the delete flow proved **both** the payout-in-flight
  refusal AND success (DB anonymized, devices gone, ledger preserved, email tombstoned); open-redirect
  ignored; no `refresh_token_hash` leak; 0 console errors; no secrets in the client bundle.
- **Owner-gated to ship:** commit the branch + PR; deploy the 3 migrations to `prmsonskzrubqsazmpwd`;
  set `LUMALINE_APP_URL` = the portal origin; pin the Supabase Auth redirect allow-list to
  `<origin>/{app,activate,payouts/onboard}` (**no wildcard**); confirm `LUMALINE_PAYOUT_MIN_MICROS`;
  then push the marketing repo → Lovable deploys (owner merges — self-PR is auto-denied). Brand = the
  teal→emerald gradient (`--accent-to` ≈ #10B981), **not** the flat #16A34A the scope doc named.
- **Still to build (own sub-projects):** the **owner dashboard** (admin-gated read views over
  recon/ledger/monitor + audited clawback/dispute RPCs — medium) and the **advertiser portal** (NEW
  identity `advertiser_users` + RLS isolation, prepay balance, re-scoped `admin-booking` RPCs, CPVA-only,
  guard rails against house/sentinel — largest, most review).

## 5g. Security-audit hardening (PR #39 — MERGED + DEPLOYED 2026-07-22)

A two-pass internal adversarial audit of the LIVE money + farming surface. **Working-tree only** — no
commit, no deploy; owner-gated to ship. Discipline held throughout: **one coherent recreate per
`SECURITY DEFINER` function** across both passes; every recreated money/PII RPC re-applies
`REVOKE ALL FROM public, anon` + explicit `GRANT`s and ends with a migration-tail `DO` block that FAILS
if `anon` retains `EXECUTE`; **no client change, no new client→server envelope field, wire-compatible**
(the shipped v0.1.x client — edge proxy AND direct PostgREST RPC — keeps working; direct authenticated
`EXECUTE` on `window_open`/`window_beat`/`close_window` is deliberately preserved so live clients don't break).

- **Pass-1** — migrations `20260722010000`–`130000` (applied to the local stack; `node --test`
  **653 pass / 0 fail**). Closed the billing / payout / self-deal / rate-limit / GDPR-aal2 residuals;
  already folded into §1 (window_open in-DB velocity + concurrency caps, `scan_ivt` per device/IP every
  2 min, `rl_hit` + per-isolate memory fallback, single-use click token minted feed-side, sentinel-exempt).
- **Pass-2** — migrations `20260722140000`+ (this section). Closes the remaining **self-click**,
  **IP-trust / DoS**, **Sybil**, and **A9 chargeback** residuals. New pure `node --test` suites
  (`sec-client-ip`, `sec-selfclick-cpc`, `sec-fleet-velocity`) fail-before / pass-after; the suite count only grows.

> **Coordination note:** the pass-2 clusters (P1 IP-trust, P2 self-click, P3 Sybil/A9) were specced in
> parallel and draw from the shared `>= 20260722140000` timestamp pool; on merge the migrations take
> **disjoint, strictly-ascending** slots and the single `window_open` / `close_window` / `click_resolve` /
> `ensure_publisher` recreate is the latest-timestamped one for that function (no function recreated twice).
> The **trusted-client-IP + salted-hash derivation** lives in ONE `_shared/` module so the serving-window
> hash and the clicker / signup hash compare equal.

### P1 — Trusted client-IP resolution + edge DoS keying (IP-TRUST)

`rawClientIp`/`clientIpHash` (and `auth-device`'s `deviceRateOk`) read the **leftmost** `X-Forwarded-For`
hop — 100% caller-controlled — so the memory limiter, the durable `rl_hit` bucket, and the
`ad_windows.ip_hash` that feeds `scan_ivt` were all keyed on an attacker-chosen value. Fixed by a shared
resolver with precedence **worker-vouched (`x-lumaline-client-ip` + a constant-time `x-lumaline-edge-proof`
shared-secret check) → `cf-connecting-ip` → leftmost XFF → `x-real-ip`**. (The two-hop
`client → Cloudflare → Supabase edge` topology means the *rightmost* XFF at the edge is Cloudflare's shared
egress IP and would collapse every client into one bucket — so it is deliberately NOT used.) `close_window`
additionally persists the window's salted `ip_hash` onto the durable `impressions` row so self-click / IVT
forensics survive the UNLOGGED `ad_windows`.

### P2 — Publisher self-click CPC farming (SELF-CLICK)

The raw click token is embedded in the Ed25519-signed `adData.clickUrl`, so a serving publisher could
extract it and self-click via `/click` or directly via `/rest/v1/rpc/click_resolve`. Closed by: (a)
**revoking `authenticated` EXECUTE on `click_resolve`, granting `service_role` only** — the shipped client
never calls it; only the `click` edge fn does, and it always derives the trusted clicker IP (kills the
direct-RPC path outright); (b) a **same-IP void** — a click whose salted clicker-IP hash equals the serving
window's `ad_windows.ip_hash` is the serving machine and is recorded `void`, never billed
(`self_click_same_ip`); (c) **`scan_click_ivt`** (every 2 min) velocity-flags per serving-device /
publisher / serving-IP click farms into `risk_flags` (`ivt:click:*`) + a pending `clawback_reviews` row,
which the existing `clear_events` predicate withholds until an admin resolves (reject releases a false
positive). **Honest-model tradeoff, documented loudly:** in a single-user terminal the publisher *is* the
end user, so a genuine click is same-machine — treating same-IP clicks as owner self-views forfeits nearly
all CPC revenue, which is acceptable because CPC is already marginal (OSC-8 status-bar clicks fire only in
IDE terminals, upstream #26356; CPVA/views is the dependable model everywhere).

### P3 — Sybil throttles + fleet anomaly monitor + A9 chargeback suspension

- **Signup / device-code throttle** — `signup_throttle_hit` durable fixed-window counter (fail-**closed**
  on empty scope) on `auth-device /device/code` (global + per-trusted-IP scopes), layered over the existing
  per-isolate limiter; plus a **global new-publisher-per-minute cap inside `ensure_publisher`** on the
  CREATE path only (returning users are never throttled; the browser calls PostgREST directly so no client
  IP is available there — the per-IP dimension lives at the device-code edge).
- **Fleet Sybil scan** — `app.scan_publisher_sybil` (daily) flags ≥ `p_min_pub` (default 3) distinct real
  publishers serving from ONE salted `ad_windows.ip_hash` as a cluster → **payout HOLD**
  (`publisher_payout_holds` reason `sybil:shared_ip` + `payout_status verified→pending`), **hold-only,
  never auto-clawback** (human review). **No free-email whitelist** (a pure-Sybil farm uses gmail — the gap
  `scan_selfdeal_risk` deliberately left). `publishers.stripe_account_id` is UNIQUE, so a literal
  shared-payout-account Sybil is structurally impossible; payout-account clustering is intentionally omitted.
- **Fleet-velocity monitor** — READ-ONLY `monitor_fleet_velocity` counters wired into the `monitor` edge fn
  as a new `fleet_velocity` HIGH check (surfaces distributed low-and-slow Sybil the per-entity `scan_ivt`
  cannot see; alerts a human, never blocks). Also wires pass-1's shipped-but-unwired `evalPostpayChargebacks`
  as the live `postpay_chargeback` check.
- **A9 — advertiser dispute hold** — a postpay chargeback previously only paused `line_items`, which the M9
  advertiser self-serve RPCs (`advertiser_set_line_item_status` / `advertiser_set_campaign_status`) could
  flip straight back to `active`, and `window_open`'s serve path checked only `a.status='active'`. New
  advertiser-level `advertisers.dispute_hold_at` (a protected column; service_role/admin-only via
  `advertisers_protect_cols`), **set by `book_postpay_chargeback`**, **gates `window_open`'s real-publisher
  serve path** (`and a.dispute_hold_at is null`), and **blocks self-serve resume** in both status RPCs.
  Cleared only by `admin_clear_advertiser_dispute_hold`, gated on the **M8 aal2 `app.money_admins` tier**
  (same gate as `admin_open_clawback`).

### Bounded residuals (honest — NOT code-eliminable)

1. **Direct-RPC / Cloudflare-bypass IP spoofing → IP is advisory.** A caller that bypasses Cloudflare and
   hits `*.supabase.co` (or calls `/rest/v1/rpc/window_open` directly) can still send an arbitrary
   `cf-connecting-ip` / XFF / `x-lumaline-client-ip` with no valid edge-proof → the resolver marks it
   `trusted:false` and the IP is **best-effort / advisory**; the per-IP dimension of `scan_ivt` /
   `scan_publisher_sybil` is inert against them. The **hard bound is the IP-independent in-DB per-device /
   per-publisher velocity + concurrency caps** in `window_open` (unchanged). Real fix = ops (D14).
2. **Cross-IP low-and-slow self-click.** Clicking one's own served ads from a *different* network
   (VPN / phone) escapes the same-IP void. Bounded by `scan_click_ivt` on the **serving**
   device / publisher / IP (the farm still generates every window on one machine), P1's `window_open`
   open-velocity caps, the parent impression having to independently clear under `scan_ivt`, and CPC firing
   only in IDE terminals (#26356). Net CPC yield per farm machine is tightly capped and self-defeating.
3. **Cross-identity low-and-slow Sybil.** N accounts across N distinct KYC identities / emails / trusted IPs,
   each under every per-entity cap and below the shared-IP cluster threshold. **Operational, not a query:**
   Stripe **KYC** at payout onboarding + the **7-day payout hold > 72h clawback** (unpaid Sybil earnings sit
   held and reviewable; paid earnings can't be clawed but require passing KYC first) + the **payout-hold
   review queue** (fed by `scan_publisher_sybil`) + the **fleet-velocity monitor**. Recorded as **D15**.
4. **Same human, many Stripe Connect accounts.** `stripe_account_id` UNIQUE blocks the literal shared-account
   Sybil; distinct Connect accounts backed by one human/bank are Stripe KYC's job.
5. **Per-IP throttle vs CGNAT / shared-office IP.** A per-IP signup / cluster cap can false-positive legit
   users behind one NAT, so per-IP is a *moderate* cap; the always-on GLOBAL cap + the monitor are the real
   bound, and `scan_publisher_sybil` is **hold-only** (a false cluster costs a review, never a wrong reversal).

### Ops-layer recommendations (NOT code — owner / infra)

- **Cloudflare WAF / rate-limit** on `feed.lumaline.dev` + `c.lumaline.dev` / `auth-device` keyed on
  `cf-connecting-ip` (unspoofable at the CF edge) — the durable DoS control; the edge limiter stays a cheap
  secondary floor. Optionally **restrict direct `*.supabase.co` origin access** (Authenticated Origin Pulls,
  or require `x-lumaline-edge-proof` at the edge and 401 without it) to remove the bypass path — a policy
  decision that **would break the documented direct-PostgREST-RPC wire-compat**, so it stays a recommendation
  (both tracked as **D14**).
- Set the new secret **`LUMALINE_EDGE_PROOF`** in Supabase Vault + the Cloudflare Worker env (unset ⇒ proof
  path disabled ⇒ resolver falls back to `cf-connecting-ip`, still strictly better than leftmost-XFF).
- **Schedule** the new crons (`scan_click_ivt`, `scan_publisher_sybil`, the `fleet_velocity` +
  `postpay_chargeback` monitor checks, the `signup_throttle_buckets` prune) and **calibrate** thresholds
  (`FLEET_VELOCITY_BASELINES`, `p_min_pub`, `MAX_NEW_PUB_PER_MIN`, `LUMALINE_DEVCODE_*`) against real launch
  traffic before tightening.
- Ensure the owner is in **`app.money_admins` with a verified aal2 session** BEFORE relying on
  `admin_clear_advertiser_dispute_hold` (M8 self-lockout hazard: an all-aal1 admin base cannot clear a hold).
- Consider **disabling CPC** (`cpc_bid_micros = 0`, unambiguously CPVA-only) since the same-IP void makes CPC
  near-non-earning in the current single-user product, or keep it live for the rare cross-IP IDE case and
  monitor `ivt:click:*` volume. Document the same-IP-void policy in the publisher terms / transparency report.
- Build a lightweight admin view over open `publisher_payout_holds` (`sybil:shared_ip` / `selfdeal:shared_email`)
  + `advertiser_postpay_chargebacks` so the review queue is actioned.

## 5h. Post-M9 deltas (2026-07-22→25: deposits live, legal v2, payout countries, 0.1.7)

- **Advertiser deposits LIVE (2026-07-23).** Found + closed a live hazard: the deposit checkout
  worked with the live Stripe key while `ADVERTISER_STRIPE_WEBHOOK_SECRET` was unset — money could
  be captured with the credit never landing. Fixed: kill-switch (`ADVERTISER_MAX_DEPOSIT_MICROS=0`)
  while **Advertiser ToS v2.0** (PR #42: prepaid **non-refundable** spend-only credit, **B2B-only**
  eligibility, VAT section, deposit-chargeback = breach) was merged in force; Stripe webhook
  endpoint created + secret set (digest-verified); kill-switch lifted (max €5000).
- **Publisher ToS v1.2** (PR #46): stale test-mode notices removed; §7.7 payout countries extended.
- **Payout reach: 34 countries** — EEA + **US/GB/CA/CH** via Stripe cross-border (PR #46;
  the old "RO platform cannot pay US" comment was wrong per Stripe docs). Country handling
  rebuilt: nothing ever set `publishers.country`, and onboard defaulted NULL→"US" → **bank
  connect had been broken for 100% of publishers** (PR #44: resolve body→stored→`cf-ipcountry`,
  never default, `country_required` 422 without stamping); mis-picked country **redoable until
  Stripe verification** (PR #48: delete+recreate un-onboarded accounts, 409 past that);
  dashboard country picker (marketing repo PRs #1/#2). `stripe-connect` fn at **v24**.
  **Rest-of-world (AU, IN, BR…) is NOT reachable self-serve** from an EEA platform — Stripe
  Global Payouts is sales-gated; Wise Platform is the researched complement (see memory
  `payout-provider-research`).
- **Client `0.1.7`** (PR #47): README truth-pass + "Getting paid" section (PR #43), `lumaline
  connect --country=XX`. README + CLI commit to a **€1 payout minimum** — the prod
  `LUMALINE_PAYOUT_MIN_MICROS` secret must be `1000000` to match (temporarily `500000` during the
  first-payout exercise).
- **First REAL publisher payout: still pending.** Blocked on recipient-side KYC: Stripe RO offers
  **no "individual" business type** (Romanian law — recurring income needs a PFA/ÎI/SRL), so the
  RO friend-publisher (~€0.90 payable) cannot onboard as a person; owner onboarded an NL account
  2026-07-24 (verification unconfirmed). Rails themselves proven test-mode end-to-end (M3).
- **Known-broken:** `test/serving.integration.mjs` fails on a clean local stack on `main`
  (per-device concurrent-open cap from §5g; CI blind — integration suites self-skip). Issue #45.
- **Docs housekeeping (2026-07-25):** deleted dead one-shot docs (`BLOCKED.md`, `RUN_LOG.md`,
  `LAUNCH_RUN_PROMPT.md`, `REVIEW_TODO.md` — the one live nit became issue #49); `ops/HANDOFF.md`
  reduced to a pointer; onboarding runbooks + `CLAUDE.md` + `MILESTONE_STATUS.md` refreshed.

## 5i. GDPR account-lifecycle phases 1–3 (2026-07-25→26)

Spec: `docs/superpowers/specs/2026-07-25-gdpr-lifecycle-design.md`. Five deliverables that share the
lifecycle but almost no code, shipped **one phase per branch+PR** on owner directive. Phases 1–3 are
**merged**; 4 and 5 are not started.

**✅ SCHEMA FULLY DEPLOYED 2026-07-26.** `main` and `prmsonskzrubqsazmpwd` are at the same 75
migrations. All five GDPR migrations are live:

| Migration | PR | On `main` | On prod |
|---|---|---|---|
| `20260725100000_retention_sweep` | #51 | ✅ | ✅ deployed + cron scheduled + ran clean |
| `20260726100000_advertiser_erasure_split` | #52 | ✅ | ✅ deployed |
| `20260726110000_erasure_terminal_and_ledger_health` | #53 | ✅ | ✅ deployed |
| `20260726120000_erased_advertiser_surface` | #53 | ✅ | ✅ **deployed 2026-07-26** |
| `20260727100000_gdpr_pending_deletion` | #54 | ✅ | ✅ **deployed 2026-07-26** |

**Deploy evidence (2026-07-26).** `supabase db push --linked` after a dry run that confirmed exactly
those two files. Pre-flight: 4 publishers / 2 advertisers (so the non-`CONCURRENTLY` index build is
microseconds), every `deletion_disposition` NULL (so the widened CHECK rejects nothing), **zero
dependents** on the 0-arg `advertiser_gdpr_self_delete()` being dropped, one `money_admin` present
(spec §9.3 hazard 2), and a money snapshot of `ledger_sum=0 / 90 rows / 0 payouts in flight / 0
balances`. Post-deploy: **that money snapshot is byte-identical**; 75 migrations; both watermark
columns + both partial indexes + the widened CHECK present; the 0-arg overload gone and the
`(text)` form present; `anon` has EXECUTE on **none** of the new functions and `authenticated` on
neither `app.gdpr_complete_pending` nor `device_code_redeem`; **zero** rows pending and **zero**
devices revoked by the deploy (the one revoked device dates from 2026-06-29). Security advisors:
**0 ERROR before, 0 ERROR after** — the 3 new WARNs are all
`authenticated_security_definer_function_executable`, the same class already firing on every
sibling self-serve SECDEF RPC. A PostgREST `notify pgrst, 'reload schema'` was issued and the new
signatures were smoke-tested **as `anon`** (which holds no EXECUTE, so no body could run): all
returned `42501 permission denied` rather than `PGRST202 not found`, proving both that the schema
cache refreshed and that a `{}` body resolves unambiguously to the defaulted-parameter form.
Runbook STEP 1 returned all zeroes with `skipped: []`.

**✅ FULLY OPERATIONAL 2026-07-26.** Both follow-ups are done:

1. **`auth-device` redeployed, v20 → v21** (ACTIVE). It now maps the RPC's `deletion_pending` status
   to a `403 deletion_pending` instead of letting it fall through to the generic `invalid_grant`.
   Smoke-tested live: `POST /device/code` still returns 200 with a real `device_code`/`user_code`.
2. **Completion cron scheduled** — `lumaline-gdpr-complete-pending`, `23 * * * *`, active.

**STEP 2 rehearsal (run against production, rolled back).** The runbook's STEP 1 returns all zeroes
on an empty table, which is indistinguishable from a no-op, so the pass was proven properly inside a
transaction ending in `ROLLBACK`. It deviated from the runbook's literal text in one safe direction:
instead of backdating a *real* advertiser, it created two **synthetic** ones, which proves the same
thing about prod's schema/triggers/grants while making it impossible to erase a live customer even
if the rollback had somehow been skipped. Both branches were exercised in a single pass —

| Fixture | Setup | Result |
|---|---|---|
| REH-A | no blocker, requested 26 days ago | **erased**, name anonymized to `deleted-…`, watermark cleared, `deletion_disposition` preserved, campaign paused, **no alert** (correct — it stopped being pending before alerts are computed) |
| REH-B | pending topup, requested 26 days ago | **stayed pending**, Art. 12(3) alert **raised** at severity `high` |

Pass returned `advertisers_erased: 1, still_pending: 1, alerts_raised: 1, skipped: []`. Global
`ledger_sum` was 0 before and after; **zero real advertisers erased and zero real rows left
pending**. Post-rollback the database was verified pristine: no rehearsal rows, no intents, no
alerts, no erased advertiser, ledger 0, both real campaigns still active.

**Operational note.** The window between deploying the schema and scheduling the cron was not
neutral, and is worth remembering for the next phase: once Phase 3 is deployed, a blocked erasure
request **freezes** the account (revokes devices / pauses campaigns), and with no cron running
nothing lifts that freeze except the user's own cancel. Deploy and schedule together.

### Phase 1 — retention sweep (PR #51, DEPLOYED + LIVE)

`app.retention_sweep()` enforces privacy-policy §8. **Column-level scrubbing, not deletion**:
`impressions.ip_hash/asn` past 90d, `ad_windows.ip_hash` past 7d, `clicks.click_token_hash` past 90d
(to a per-row sentinel); only `device_auth_codes` are deleted (past 24h). No row that anchors money
is ever removed — `impressions` anchor `ledger_entries`, and `app.advertiser_expected_reserved` sums
`ad_windows.reserve_micros` with **no time bound** as the RHS of money invariant (C) RESERVED.
`risk_flags` is deliberately **not** swept (`clawback_reviews` references it NO ACTION, and a
pending review is what blocks clearing fraud-flagged revenue).

**Live on prod:** cron `lumaline-retention-sweep` at `53 3 * * *`, active; first run
2026-07-26 03:53 UTC **succeeded**. (Supersedes any earlier note saying Phase 1 was merged but not
enabled.) Test-strength deferrals from this phase: **D16–D18**; the unbounded-growth residual is
**D19**.

### Phase 2 — split personal-data erasure from commercial closure (PR #52, DEPLOYED)

Removed the advertiser **idle-balance gate** from `app.advertiser_gdpr_erase`. Deposits are
non-refundable and there is no withdrawal RPC, so gating erasure on `balance_micros > 0` made Art. 17
erasure permanently unreachable for anyone holding credit — not "later", *never*. One check was
gating two different things: erasure of a **natural person's** data and settlement of a **legal
entity's** money.

**Kept:** `house_advertiser`, `already_deleted`, and the three in-flight-**transaction** guards
(`topup_pending`, `charge_pending`, `uncharged_postpay_billings`). By default the residual balance is
left **on the books** as an unrecognized liability — erasure never sweeps it. Added the opt-in
counterpart `public.advertiser_writeoff_credit()` (self-scoped, refuses while `reserved_micros > 0`,
books a zero-sum `advertiser_funds`/`platform_revenue` pair — **no `platform_cash` leg**, because no
cash moves) and the `deletion_disposition` column (`dormant`|`writeoff`; `spend_down` deliberately
withheld until Phase 3 shipped the cron to honour it).

### Erased-advertiser surface audit (PR #53, DEPLOYED)

Erasure keeps the `advertiser_users` mappings (that is what makes a repeat erasure idempotent and
keeps the data export reachable), so `app.current_advertiser_id()` still resolves for an erased org
and every self-serve RPC stayed **callable**. `20260726110000` closed the spending path
(`window_open` gained `a.deleted_at is null`; the two resume RPCs refuse with `account_deleted`);
`20260726120000` classified the rest — six creation/edit RPCs and the deposit resolver **refuse**,
while `advertiser_data_export` and `advertiser_writeoff_credit` deliberately **stay open** (Art.
15/20 does not lapse because Art. 17 was exercised, and gating the write-off would trap the residual
credit forever).

### Phase 3 — pending-deletion state machine (PR #54, DEPLOYED + OPERATIONAL 2026-07-26)

`20260727100000_gdpr_pending_deletion.sql` + `scripts/ops/pending-deletion-enable.sql`. The request
path becomes **erase-or-enter-pending**; the money gate is byte-identical and both erasure bodies are
**called, never copied**.

- **`deletion_requested_at`** on `publishers` + `advertisers` (partial indexes on the cron's
  predicate). Neither is protected by `app.advertisers_protect_cols`. `spend_down` joins the
  disposition CHECK.
- **`app.gdpr_deferrable_reason(text)`** — an **allow-list** classifying refusals as deferrals
  (`payout_in_flight`, `topup_pending`, `charge_pending`, `uncharged_postpay_billings`) vs terminal
  (`already_deleted`, `house_advertiser`). Allow-list so a future reason defaults to terminal:
  wrongly deferring freezes an account for a deletion that can never complete, and scheduling the
  house advertiser would freeze the beta sentinel permanently.
- **Freeze.** Publisher = **device revocation**, which stops serving through `window_open`'s existing
  `d.revoked_at is null` check with **no hot-path change**; `publishers.status` deliberately stays
  `'active'` because Phase 4's `payout_batch_reserve` predicate requires it. Advertiser = pause
  campaigns/line_items, **except under `spend_down`**, where credit must stay spendable.
- **The freeze is enforced, not advisory.** `device_code_redeem` (the sole device-mint point) returns
  `deletion_pending` without consuming the grant; the two resume RPCs refuse while pending
  (`spend_down` exempt). Without these, `lumaline login` or one Resume click undid the freeze — the
  same defect class #53 closed one state later. `window_open` is **untouched**; the residual (a
  pending advertiser forced back to `active` behind the RPCs still serves) is the pre-existing
  terminal-erasure boundary and closes within the hour.
- **`public.advertiser_gdpr_self_delete(p_disposition text default 'dormant')`** — the no-arg form is
  **DROPPED** (`CREATE OR REPLACE` cannot change an argument list; leaving it makes the portal's
  zero-arg call ambiguous). The default preserves that call over SQL and over a PostgREST `{}` body.
  `'writeoff'` is **refused** here: this function moves no money, so recording it would be exactly
  the silent broken promise Phase 2 avoided.
- **`app.gdpr_complete_pending(p_overdue, p_limit)`** — hourly, service_role only. Each row is
  isolated in its own subtransaction so one stuck account cannot strand every other data subject;
  failures are **reported** in `skipped`, never swallowed. Each row is re-read **`FOR UPDATE`** and
  re-verified before erasing — without that, a cancel landing mid-pass was still erased,
  irreversibly (proven with two concurrent sessions; the cancelled row survived while a control in
  the same pass was erased). `spend_down` additionally requires `balance_micros` **and**
  `reserved_micros` to be zero (a reserve is a hold *within* the balance; erasing over one strands a
  hold that `advertiser_reconcile_reserved` could later "self-heal").
- **Art. 12(3) alert** — `app.alert_events` `gdpr_pending_overdue` at 25 days, five days of margin.
  Raises **and resolves**, mirroring `monitor_sync_alerts`' `ON CONFLICT` against the partial unique
  index on open `(check_name, dedup_key)`.
- **Cancel** — `gdpr_cancel_deletion()` / `advertiser_gdpr_cancel_deletion()`, self-scoped, refused
  with `already_deleted` after erasure. Advertiser cancel restores **exactly** what the freeze paused
  (ids recorded in the `gdpr_pending` action-log payload) — a blanket unpause would resurrect
  campaigns the advertiser had deliberately stopped and resume spending their money. Publisher cancel
  does **not** un-revoke devices; the payload reports `devices_still_revoked` + a `next_step`.
- **Cron not scheduled by the migration** (deliberate); enabled separately via
  `scripts/ops/pending-deletion-enable.sql` and now **live on prod** as
  `lumaline-gdpr-complete-pending`, hourly at **`23 * * * *`** — free by construction against prod's jobs (`:00` clear-events, `:07`
  monitor-hourly, `03:17`/`03:41`/`03:53` selfdeal/sybil/retention, plus the `*/2`, `*/5`, `*/10`
  jobs; 23 is odd and not a multiple of 5 or 10). Its STEP 2 is a **rehearsal inside a rolled-back
  transaction**, because on a fresh deploy STEP 1 returns all zeroes and an all-zero result on an
  empty table is indistinguishable from a no-op.

**Tests:** `gdpr-self-delete.integration.mjs` S1–S12 (12/12, 0 skips);
`advertiser-gdpr.integration.mjs` G1–G27 (25/27, 0 skips — the 2 are the documented G6/G8 aal2
`is_money_admin()` baselines a local stack cannot satisfy). Zero regressions established two ways:
isolated runs off a clean reset give `main` and the branch byte-identical failing-name sets; and on
full parallel runs `main` itself yields 14 failures one run and 17 the next, its 17-run matching the
branch exactly (`serving.integration` T3/T4/T5 are that pre-existing flake — in isolation that suite
fails only its documented B1). **This is why the gate is the failing FILE list plus zero skips,
never a count.**

### Phases 4–5 — NOT STARTED

- **Phase 4 (spec §4) — final payout on close.** One additive predicate inside
  `payout_batch_reserve`'s existing loop so a *closing* publisher qualifies below the payout minimum:
  `if v_payable < p_min_micros and rec.deletion_requested_at is null then continue`. It is the
  **fifth** `CREATE OR REPLACE` of a money-path function — the body must be copied **verbatim** from
  the live definer with only that predicate changed, following the precedent `20260722060000` set.
  Transfer/confirm and the reservation lock are **not** touched. Depends on Phase 3's column.
- **Phase 5 (spec §7) — portal surfaces.** Ships **last**, so the UI only ever exposes a working
  flow. Separate Lovable repo (`~/projects/luma-line-edf7d51e`).

## 6. Deferral ledger

Genuine deferrals, recorded so none is silently lost. Each names the **reason** and the **milestone/owner**
that closes it.

| ID | Deferred item | Reason it's safe to defer | Closes at |
|---|---|---|---|
| **D1** | **Public transparency / clearing report** (aggregate fill, credited views, clearing prices, publisher-share %, clawback rate). | **This is the product thesis** — transparency is the whole pitch vs. invasive monetizers — so it is **explicitly tracked, never dropped**. It needs real cleared traffic to report on, which only exists after paid demand (M2) and go-live (M5). Figures must reconcile to the ledger and stay non-PII (data-minimization invariant). | ✅ **DONE — M6-T5** (PR #28): `scripts/ops/transparency-report.mjs` → `docs/transparency-report.{json,md}`, reconciles to the ledger. |
| **D2** | **Second-price auction.** | With a **single advertiser**, a full second-price auction is dead code. **First-price / reserve-floor clears today.** The schema **retains the clearing-price column** so the second-price upgrade is **non-breaking** when multiple advertisers exist. | **Post-multi-advertiser** (designed into M2-T1 serving) |
| **D3** | **Next-key private custody in Vault.** | The `keyid` mechanism + the **public** next key (`31433cdee001fc81`) ship now so clients trust it *before* the feed flips. | ✅ **DONE 2026-06-29** — next private stored in Vault as `LUMALINE_ED25519_NEXT_PRIVATE_KEY` (byte-verified vs the local PEM), disk copy shredded. |
| **D4** | **`schema_migrations` history repair** (the 2 out-of-band versions + the drift-capture row). | Objects/grants were already live and the migrations are idempotent; the gap was the **history table** only. | ✅ **DONE 2026-06-29** — history reconciled to **13** versions; future `db push` is clean. |
| **D5** | **Per-publisher earnings / payouts** (device-code `lumaline login`, attribution off the sentinel, Stripe charging + Connect payouts, money-safety gates, independent security review). | The beta is intentionally **sentinel-only, `gross = 0`, never billed** — *see it live today, not get paid today*. The full money machine is built + proven in **Stripe test mode** before a single real dollar moves, behind legal and security gates. | **M1–M3** (test mode), **M5** (live go-live) |
| **D6** | **Branded domain + CPC measurement + GA npm publish.** | Installed clients don't self-update, so GA must ship on the **stable branded URL** and **rotation-safe** (the M0 `keyid` work is its hard prerequisite). Until then the beta installs via `npm i -g github:JaamesBond/LumaLine`. CPC is also gated by upstream OSC-8 bug #26356 (clicks in IDE terminals only today). | **M4 — ✅ DONE 2026-07-01** (§5c): branded domain + CPC money-path + **GA npm publish `lumaline@0.1.0` LIVE** (SLSA provenance). |
| **D7** | **Scale / ops deferrals:** load-test validation of the ~15k writes/s ceiling, richer IVT heuristics (data-min-safe), advertiser API keys, full dashboards/on-call runbook, DR-at-scale. | Not on the money-honesty critical path; the money-critical alerts (ledger-imbalance, payout-failure, reconciliation) land earlier at M3-T6. | **M6 — PARTIAL.** ✅ dashboards/runbook (M6-T1) + transparency (M6-T5) + load harness *built* (M6-T2, PR #29). ⏳ load-run vs prod owner-gated; richer IVT (M6-T3) + advertiser API keys (M6-T4) DEFERRED behind M5 validation. |
| **D8** | **M1 — orphaned `open` window** when a revoked device's `window_open` is retried under the sentinel (the client keeps sending its real token, so the sentinel window's beats/close 401 and it never closes). | **Harmless:** `gross=0`, never credits, no double-bill, no crash; the access token expires in ≤15 min and the existing Phase-4 `sweep_stale_windows` cron abandons stale-open rows. | **M4/M6** (optional: signal client demotion in the open reply) |
| **D9** | **M1 — refresh token has no absolute lifetime + no reuse-detection** (OAuth refresh-rotation BCP). | Bounded by the short **900s** access TTL, 0600 at-rest storage, **manual `device_revoke`**, and the per-window `revoked_at` re-check on the billing path. No payouts until M5. | **M3** (security review): add `devices.refresh_expires_at` + superseded-hash reuse detection → auto-revoke device family |
| **D10** | **M1 — `/earnings` does not re-check `devices.revoked_at`** (a token minted just before logout can read its *own* earnings until exp ≤15 min). | **Self-data only**, RLS-scoped to the caller; zero billing/cross-publisher impact; time-bounded by the short TTL. | **M3** (add a server-side `revoked_at` check on the `/earnings` handler) |
| **D11** | **M4 — CPC advertiser charges have no automated Stripe refund path.** The refund handler (`billing/index.ts`) looks up `advertiser_charges` by `impression_id`, but CPC charges carry `impression_id = NULL`, so a CPC charge can only be **manually** refunded via Stripe today. | **Internal ledger stays correct**: `public.clawback` reverses *both* the impression and click ledger groups for the window, so this is missing Stripe-side *automation* only, not ledger corruption. M4's scope was "wire CPC into the money path"; M4 creates the precondition, so the refund automation is a tracked follow-up. Manual refund remains available. | **M5/M6** (add a click-keyed branch to the refund handler + `clawback_reviews`) |
| **D12** | **M4 — webhook integration tests W8/W9/W11 hard-fail (don't skip) on a partially-configured stack.** They assert `200` for platform/connect-signed events, so a `supabase functions serve` running with only the local dev secret yields `400` → red instead of skip. | Cosmetic test-hygiene gap: the whole integration suite already requires a manually-configured stack + `.env` (the header documents the two-secret precondition); a correctly-configured stack passes. W10 (asserts `400`) is robust regardless. No production impact. | **M6** (gate W8/W9/W11 on served-secret presence) |
| **D13** | **Per-clicker-IP dimension for `scan_click_ivt`** (P2, §5g) — an `ivt:click:clkip` velocity branch keyed on the *clicker's* salted IP, not just the serving side. | The pass-2 gate already voids same-IP clicks in `click_resolve`, and `scan_click_ivt` bounds farms on **serving-side** device/publisher/IP; a per-clicker-IP column would add an end-user IP hash to the **publisher-readable** `clicks` table (`clicks_select_own` RLS), so it needs a `revoke select (clicker_ip_hash)` column-grant to stay data-minimal. Omitted to keep the migration data-minimal. | **Future hardening** (add `clicks.clicker_ip_hash` + column revoke + the `ivt:click:clkip` branch). |
| **D14** | **Ops-layer DoS + direct-origin hardening** (P1, §5g) — Cloudflare WAF / rate-limit keyed on `cf-connecting-ip`; optionally lock direct `*.supabase.co` origin access or require `x-lumaline-edge-proof` at the edge. | The edge resolver already upgrades DoS/IVT keying on the Cloudflare path (trusted vouch → `cf-connecting-ip`), and the **hard bound is the IP-independent in-DB per-device/per-publisher caps**; the WAF is the durable DoS control and the origin-lock removes the bypass but **would break the documented direct-PostgREST-RPC wire-compat**, so it is an infra/policy decision, not code. | **Owner / infra (ops)** |
| **D15** | **Cross-identity / cross-IP low-and-slow Sybil** (P3, §5g) — N accounts across N distinct KYC identities / emails / trusted IPs, each under every per-entity cap and below the shared-IP cluster threshold. | **Not code-eliminable by design.** Bounded operationally: Stripe **KYC** at payout onboarding, the **7-day payout hold > 72h clawback** (unpaid Sybil earnings sit held + reviewable), the **payout-hold review queue** (fed by `scan_publisher_sybil`), and the **fleet-velocity monitor**. Recorded so the accepted residual is never mistaken for closed. | **Operational** (KYC + human review; accepted residual) |
| **D16** | **GDPR Phase 1 — `retention_sweep`'s ledger non-interference assertion is vacuous.** `test/retention-sweep.integration.mjs` R8 asserts `sum(amount_micros)` on `public.ledger_entries` is unchanged across a sweep, but `seedFixtures()` creates **no** `ledger_entries` rows, so it compares `0 == 0` and cannot fail. The property it claims to protect — that retention never disturbs the financial trail — is untested. | **Non-interference is currently structural, not tested**: `app.retention_sweep()` contains no statement referencing `ledger_entries`, `payouts`, or any `impressions` DELETE (verified live at review: batching, idempotency, and row-survival all confirmed by execution). The risk is a *future* edit adding such a statement with nothing to catch it. Owner ruling 2026-07-25: accept as-is for Phase 1, log for a dedicated refinement pass. | **Refinement session** — seed a balanced double-entry pair tied to the old impression in `seedFixtures()` (must satisfy the deferred zero-sum trigger), then assert both `sum(amount_micros)` **and** `count(*)` survive the sweep. |
| **D17** | **GDPR Phase 1 — no exact-boundary retention fixture.** Fixtures straddle at 91d/89d, 8d/6d, 25h/23h; nothing sits at exactly `now() - interval '90 days'`, so an off-by-one in the age predicate (`<` vs `<=`) would go uncaught. | Low consequence: an off-by-one at the exact boundary shifts which of two adjacent rows is scrubbed by a single sweep cycle, and the 91d/89d pair already catches any age predicate that is *broadly* wrong (verified: R3 fails if the age filter is dropped). A literal exact-boundary assertion is also inherently racy — time advances between INSERT and sweep. Owner ruling 2026-07-25: defer as Minor, log for a refinement pass. | **Refinement session** — pin the intended boundary semantics explicitly (either a tolerance-based fixture or a documented decision that `<` is correct and untested at the exact edge). |
| **D18** | **GDPR Phase 1 — `ad_windows` retention fixture cannot catch a filter-column swap.** `seedFixtures()` backdates `ad_windows.started_at` **and** `created_at` to the same value, so test R4 would pass identically whether the sweep filtered on the correct column (`started_at`) or the wrong one (`created_at`). | The implementation was verified to use `started_at` by **reading the code at review**, not by the test — so the current behavior is correct, but it is unprotected against a future edit swapping the column. Low blast radius: both columns are written at window open and differ only in exotic cases. Same family as D16/D17 (test-strength, not defect). | **Refinement session** — backdate only `started_at` in the fixture (leaving `created_at` recent), so the test fails if the filter column is swapped. |
| **D19** | **GDPR Phase 1 — `public.ad_windows` still grows without bound.** The original goal was twofold: remove the personal data (`ip_hash`) *and* stop the table growing unbounded. The shipped remedy scrubs `ip_hash` in place and **abandons the second goal** — rows now live forever on an UNLOGGED table on the serving hot path. | **Deleting these rows was proven unsafe.** `app.advertiser_expected_reserved` sums `ad_windows.reserve_micros` with **no time bound** and is the RHS of money invariant **(C) RESERVED**; `scan_selfdeal_risk` reads it at 30d to release stranded reserves. A 7-day retention DELETE destroyed exactly the exception paths (pending clawback review, `advertiser_insufficient_balance`, A9 dispute hold) where a reserve legitimately outlives 7 days — causing invariant-(C) drift that `advertiser_reconcile_reserved` would "self-heal" by releasing an undrawn hold. Scrub-in-place is the correct trade; the growth problem is real but is **not** a retention problem. | **Unowned — needs a money-aware design.** A row is safe to remove only once `reserve_micros = 0` **and** its impression has reached a terminal state — a different predicate from "old enough". Must never be reintroduced as an age-based DELETE. |

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

- **What IS (code):** `src/statusline.mjs`, `src/client/window.mjs`, `src/client/auth.mjs`,
  `src/lib/{crypto,keyring,url}.mjs`, `src/config.mjs`; `supabase/migrations/` (**34 on `main`** + 3
  uncommitted M7 = 37 on disk; the `fix/security-audit-hardening` working tree further adds the pass-1
  `20260722010000`–`130000` + pass-2 `20260722140000`+ hardening migrations, §5g, uncommitted);
  `supabase/functions/` (`lumaline-feed`, `auth-device`, `billing`,
  `stripe-connect`, `monitor`, `admin-booking`, `click`, `window-open|beat|close`, `_shared`); `test/`
  (**49 files** — hermetic unit ≈147 + integration that self-skip without a local stack; the count only grows).
  **NB:** §4's "49 tests" table is the M0-era snapshot, not the current total.
- **What's PLANNED (docs):** `docs/superpowers/plans/2026-06-28-production-readiness-handoff.md`
  (**plan of record**, M0–M6); `docs/superpowers/specs/2026-06-27-verification-and-economics-design.md`
  (money + threat model).
- **Historical / superseded context only:** `docs/superpowers/plans/2026-06-27-verification-protocol-v1.md`
  (in-memory design → now the dev/test reference, §3a),
  `docs/superpowers/plans/2026-06-27-production-plan.md` (P0–P6 → replaced by M0–M6, §3b).
