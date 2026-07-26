# CLAUDE.md

Guidance for Claude Code working in this repository. **Read this + `docs/AS_BUILT.md` for what
*is*; read `docs/superpowers/MILESTONE_STATUS.md` for where we are and what's next.** Older
`docs/superpowers/plans/*` describe earlier target states — the code + AS_BUILT win.

## What this is

**LumaLine** (npm package `lumaline`; the repo/dir is still named `trustline`) monetizes Claude
Code's status-bar wait-states with a clearly-labeled, signed, clickable sponsored line — using
**only** the official `statusLine` mechanism, never patching Anthropic's code. The whole product is
a wager that you can do transparently what invasive tools (Kickbacks.ai) do by bundle-patching.
Every design choice exists to keep that trust thesis intact; the **trust invariants** below are
non-negotiable.

## Status (as of 2026-07-26)

**This is LIVE with real money, fully self-serve on both sides.** `lumaline@0.1.7` is npm `latest`;
the **first real advertiser charge (€1.10) settled + reconciled 2026-07-04**. M0–M9 all DONE +
merged + deployed: all three dashboards live on lumaline.dev (`/app` publisher, admin, advertiser),
**advertiser deposits LIVE** (prepaid non-refundable ad credit €5–€5000, webhook-credited, ToS v2.0
in force, B2B-only), security-audit hardening deployed (PR #39, 2026-07-22). **Payout countries:
EEA + US/GB/CA/CH** (34; Stripe cross-border; country picker in CLI `--country` + dashboard).
**GDPR account-lifecycle Phases 1–4 merged + DEPLOYED 2026-07-26** (#51–#54, #58, #59; spec
`docs/superpowers/specs/2026-07-25-gdpr-lifecycle-design.md`). `main` == prod == **78 migrations**,
`auth-device` v21, both GDPR crons live (`lumaline-retention-sweep` `53 3 * * *`,
`lumaline-gdpr-complete-pending` `23 * * * *`). Both dashboards deployed incl. the **advertiser
Account page** — an advertiser can finally export, delete, and write off credit. **Only Phase 5
(remaining portal polish) is left; the lifecycle itself is complete on both sides.**

**Four LIVE defects were found and closed on 2026-07-26 — none caused by the GDPR work, all
pre-existing.** Read these before touching payouts or erasure:
- **Publisher earnings were destroyed on erasure.** `gdpr_erase_publisher` gated only on
  payout-in-flight, never the balance; erasure then nulls `stripe_account_id`/`payout_status`, so
  the money became unpayable forever. Proven live with €50. Fixed: `earnings_unpaid` is now a
  *deferrable* refusal. See memory `[[erasure-stranded-publisher-earnings]]` — **every test was
  green because they set `deletion_requested_at` by hand instead of calling `gdpr_self_delete()`.**
- **Prod grant drift → payout redirect.** `anon`/`authenticated` held `arwdDxtm` on 25 tables; a
  publisher could self-verify and point `stripe_account_id` anywhere. Fixed + default privileges
  closed. Memory `[[prod-table-grant-drift]]`.
- **Erasure was reversible** — a rename undid anonymization, both publisher and advertiser sides.
- **Erased advertisers could still deposit.**

**Payout minimum is €1 everywhere** (README, ToS v1.3, CLI, code default). On account closure the
minimum is **waived down to €0.01** (Phase 4) — strictly better than Kickbacks.ai, which forfeits
anything under $10. An unclaimed balance is **never taken**: it stays a liability and converts only
on an express write-off election. No expiry clause — a timed forfeiture is void under RO Civil Code
art. 2517 + Law 193/2000; the statutory 3-year prescription already does the job.

**Still open (policy, not code):** first REAL publisher payout (RO publishers need a PFA/SRL —
`[[ro-publishers-need-pfa]]`); set `LUMALINE_PAYOUT_MIN_MICROS=1000000` explicitly so prod matches
the Terms; **UK + Canada legal review unexamined** (limitation periods differ — UK 6y, CA ~2y);
**breakage/VAT position** for the now-reachable advertiser write-off, which books real
`platform_revenue`; the 3-year write-off policy for unclaimed publisher balances; DAC7; issue #45.
`npm test` is NOT green and `main` is non-deterministic — gate on failing FILES, never a count
(`[[lumaline-test-baseline-is-flaky]]`). See `docs/AS_BUILT.md` §6 D16–D19.

## Repo layout

Two published halves + a dev-only backend, plus a **separate** web repo:

- **`src/` + `bin/`** — the zero-dep npm client that ships to developers (Node ESM, `node:`
  built-ins only, **zero runtime deps**, Node ≥ 18). `package.json#files` publishes only `bin`,
  the four `src/*.mjs`, `src/client`, `src/lib`, `src/keys`, `README.md`. Bin = `lumaline`.
- **`supabase/`** — the **production backend**: `migrations/` (75 on disk = on `main` = on prod) +
  `functions/` (8 Deno/TS edge fns incl. `advertiser-portal`) + `config.toml`/`seed*.sql`. This is
  the real server; deployed to Supabase project **`prmsonskzrubqsazmpwd`**.
- **`poc/`** — dev-only signed-feed + demo drivers (`poc/backend/server.mjs`); the in-memory
  reference the client's *unit tests* run against. **Never published**; holds a dev private key.
- **`test/`** — 49 files, `node --test` (hermetic unit + integration that self-skip without a local
  Supabase stack). `scripts/` — ops/load/transparency tooling. `docs/` — legal, ops, specs, plans.
- **Marketing site + web dashboards** — a **SEPARATE Lovable repo** at
  `~/projects/luma-line-edf7d51e` (TanStack Start + React + shadcn). Hosts `/activate` (publisher
  device-login) and, as of M7, the publisher dashboard at `/app/*`. Reaches this backend via an
  isolated `src/integrations/lumaline/client.ts`. Deploys via Lovable on push to `main`.

## Commands

```bash
npm test                     # node --test — the verification gate (CI runs it on push/PR)
npm run demo                 # cinematic fake session (also demo:plain, demo:plumbing)

node bin/lumaline.mjs doctor      # env + settings path + feed URL + verify-key fp + login state
node bin/lumaline.mjs install     # wire statusLine into ~/.claude/settings.json (reversible)
node bin/lumaline.mjs uninstall   # restore prior statusLine from sidecar/backup
node bin/lumaline.mjs login|logout|earnings|connect   # publisher auth + earnings + bank-connect
node bin/lumaline.mjs statusline  # the per-tick command (Claude invokes this, not you)

# Local backend for integration tests (Docker required):
supabase start && supabase db reset      # boot local stack + apply all migrations
supabase functions deploy <fn> --project-ref prmsonskzrubqsazmpwd --use-api   # prod deploy (owner-gated)
```

Integration tests need the local stack up; some also need `supabase functions serve` + secrets
(`source .env` first) — those **self-skip** without it, but a partially-served stack makes a few
Stripe/monitor suites (W8/W9/W11, CPC-2, MI12) hard-fail rather than skip. The pure-unit count is
~147; the full count only ever grows.

## Production architecture (what the code does today)

The trust loop is **not** a client-asserted dwell + single POST (that was the pre-M0 PoC). In
production it is a **server-verified window** implemented as Postgres `SECURITY DEFINER` RPCs behind
Supabase Edge Functions. Per tick, `src/statusline.mjs`:

1. Reads Claude's JSON on stdin; gets a valid publisher device token (best-effort → anonymous
   sentinel on failure).
2. Fetches the signed ad from `lumaline-feed` → `{ data, sig, keyid }` and **verifies the Ed25519
   signature** via a rotation-safe keyring (`src/lib/keyring.mjs`, keyed by `keyid`). Unverifiable
   or unknown keyid → refuse (`verify_fail`) → show a normal status. **Never displays unsigned
   content.**
3. Drives the window state machine (`src/client/window.mjs`): `window_open` → per-second HMAC
   heartbeat hash-chain `window_beat` (anti-batch ≥500 ms, bound to a coarse activity bucket) →
   `close_window`. Crediting is **idempotent** (`impressions.window_id UNIQUE`).
4. **Idle never bills** — a new window opens only when activity advanced (cost/token delta), gated
   by `COOLDOWN_MS`. The beta **sentinel** (self-promo) identity is `gross = 0` and **never billed**.
5. Cleared revenue posts to a **double-entry, publisher-favored 60/40 ledger** with a **72h clawback
   window**; clicks resolve through a tokenized `click` redirect (`click_token_hash` dedup).
6. Mirrors every event to a local audit log (`~/.lumaline/audit.log`).

**Money layer:** advertisers charged via the `billing` edge fn (idempotent Stripe charges, per-
advertiser aggregation), publishers paid via `stripe-connect` (Express, **EUR/EEA**, two-phase
reserve→transfer→confirm, ledger booked at confirm). Everything is **EUR-micros** (1 EUR =
1,000,000 micros = 100 cents). Payout hold (7d) > clawback (72h) so paid earnings can't be clawed back.

**Edge functions** (`supabase/functions/*`, all `verify_jwt=false`): `lumaline-feed` (signed feed +
window proxy), `auth-device` (RFC 8628 login + `/earnings` + `/activate`), `billing`
(charge/reconcile/refund), `stripe-connect` (onboard/status/webhook/payout/reconcile), `monitor`
(money-path alerts), `admin-booking` (advertiser/campaign CRUD behind `admin_check`), `click`,
`window-open|beat|close`, `_shared` (incl. pure `.mjs` decision helpers importable by `node --test`).

## Trust invariants (do not violate without explicit discussion)

- **Official `statusLine` only** — no bundle patching, CSP changes, or DOM injection beyond the one
  `statusLine` key.
- **Signed content only** — refuse any ad that fails Ed25519 verification, including an unknown `keyid`.
- **No install side-effects** — no `postinstall`, no self-update; wiring only via explicit
  `lumaline install`, fully reversible by `uninstall` (whole-file backup + prior-statusLine sidecar).
- **Honest billing** — credit only after a full server-verified dwell; never on idle; the sentinel
  (`gross = 0`) is never billed (enforced by a DB CHECK + four-layer defense).
- **Money-safety** — no double-charge / double-pay (idempotency keys + reservation locks +
  reconciliation); the transfer/confirm payout core stays untouched.
- **RLS isolation** — publisher A never sees B; the (future) advertiser side must match this rigor.
- **Data minimization** — only `{ windowId, seq, hmac, activity-bucket, ts }` (+ a salted,
  non-reversible IP hash) leaves the machine; everything mirrored to the local audit log. No code,
  paths, prompts, or PII.
- **Zero runtime dependencies** in the client; **secrets never committed** (Ed25519 private key +
  device-JWT secret live only in Supabase Vault).

## Operational facts / gotchas (every session needs these)

- **Backend = Supabase `prmsonskzrubqsazmpwd`.** NEVER the CRM project `kvlfpwzmjxuapjheknnj` (holds
  unrelated PII; the Supabase MCP can stale-bind to it — verify `get_project_url`). **Do NOT use the
  Supabase MCP for LumaLine writes**; use the ref-guarded PAT runner (asserts the ref before every
  query; recreate at `<scratchpad>/sql.mjs` from `.env`'s `SUPABASE_*_REMOTE`) + the CLI `--use-api`.
- **`.env` creds:** the `_REMOTE` suffix = production; bare names = the local stack.
- **Branch + PR always** — `main` is protected (required check: `node --test` Node 18/20). Direct
  main push is blocked; **a self-authored PR is auto-mode-denied → the owner merges.** Production
  writes (DB, secrets, deploys) are owner-gated — stop and ask.
- **Keyids:** current `8720926064dfdf50` (`src/keys/public.pem`), next `31433cdee001fc81`
  (`src/keys/next.pem`; private parked in Vault). Signing is domain-agnostic (verifies through the
  `lumaline.dev` Cloudflare proxy).
- **OSC-8 / CPC:** status-bar clicks work in **IDE terminals** (VS Code/Cursor) but **NOT standalone
  terminals** (foot/kitty/iTerm2/…) due to open upstream regression
  [#26356](https://github.com/anthropics/claude-code/issues/26356) (introduced v2.1.3). The client's
  bytes are a correct OSC-8 hyperlink; there is **no client-side fix**. So **CPVA (views) is the
  dependable model everywhere; CPC works only in IDE terminals today.**

## Key files

- `src/statusline.mjs` — per-tick client (the trust loop). `src/client/window.mjs` — pure window
  state machine. `src/lib/{crypto,keyring,url}.mjs` — Ed25519/HMAC + rotation-safe trust ring.
- `src/config.mjs` — all paths + tunables (env-driven, honors `CLAUDE_CONFIG_DIR`; `LUMALINE_HOME`).
- `src/install.mjs` / `src/uninstall.mjs` — reversible, consent-only settings wiring.
- `supabase/migrations/` + `supabase/functions/` — the production backend (see AS_BUILT §1, §5*).
- `bin/lumaline.mjs` — CLI entry / subcommand dispatch.
- `docs/AS_BUILT.md` — authoritative as-built map + deferral ledger.
  `docs/superpowers/MILESTONE_STATUS.md` — milestone status + next-session handoff (gitignored).
