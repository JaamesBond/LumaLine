# M5 GO-LIVE gate checklist (M5-T1)

**Rule: a single ❌ is a hard NO-GO for the live-key swap.** 🟡 = owner action required.
⚠️ RISK-ACCEPTED = a hard gate the owner has explicitly chosen to accept rather than fully
close. Verified mechanically where possible; evidence per item. Last verified: 2026-07-02.
Final go/no-go signature = owner.

**Status 2026-07-03: 16/17 green + T7 owner-risk-accepted. The ONE remaining gate before the
swap is row 15 — a first real advertiser with a policy-compliant creative (the Rickroll
candidate was rejected at creative review).**

| # | Gate | Status | Evidence |
|---|------|--------|----------|
| 1 | Publisher legal signed (ToS §7 payouts) | ✅ | `publisher-tos.md` v1.1 IN FORCE 2026-07-01, PR #9 owner-merged |
| 2 | Advertiser legal signed (ToS + Ad Policy) | 🟡 | v1.0 IN FORCE flip staged in the M5 PR — **owner merge = sign-off act** |
| 3 | Backups tested (restore drill) | ✅ | 2026-07-02: `pg_dump -Fc` (3.1 MB) via pooler → restored into local scratch DB; 27 migrations, 21 public/app tables, all money-table row counts identical (ledger 0 = clean post-e2e state); impressions Δ1 = post-snapshot live tick (append-only). Errors: excluded infra schemas only |
| 4 | Money-path monitoring live (T6): ledger-imbalance + payout-failure + recon-drift alerts, proven by injected fault | ✅ | **DEPLOYED + DRILLED 2026-07-02 (owner-authorized):** migration applied+stamped, `monitor` fn ACTIVE, secrets + Vault cron secret set, pg_cron `lumaline-monitor-hourly` (`7 * * * *`), auth smoke 200/401. **Drill:** injected T6-DRILL unbalanced leg (constraint trigger bypassed — the exact fault class monitored) → 2 CRITICAL `ledger_zero_sum` alerts fired (per-group + global) + email delivered → cleanup → both auto-resolved + resolution email. Dedup no-spam proven (re-run of an open alert: `email: skipped`). **Bonus real detection on deploy:** `billing_recon_drift` flagged €16 of test-mode Stripe PI residue vs €0 DB (e2e cleanups can't delete Stripe test PIs) — structural, ages out of the 35-day window; the live account starts clean at the swap. Ledger clean post-drill (0 rows, sum 0) |
| 5 | Charge idempotency + reconciliation green (TEST) | ✅ | M2 e2e + M4 CPC acceptance (dry-run bills cleared CPC group exactly once); `UNIQUE(entry_group_id)` + Stripe idempotency keys |
| 6 | Payout idempotency + reconciliation green (TEST) | ✅ | M3 live test-mode e2e 2026-07-01: real €30 EUR transfer → confirm → ledger balanced → `/reconcile` green → real reversal → `payout_reverse` net 0 |
| 7 | Webhook signature verification live | ✅ | M4 multi-secret verify (platform-signed `transfer.reversed`→200, connect-signed `account.updated`→200, bogus→400 on remote) |
| 8 | Sentinel/house never bills | ✅ | Remote constraint `line_items_house_bids_zero` CHECK present (verified 2026-07-02 via `pg_constraint`); house is_house skip in billing fn |
| 9 | Keyid multi-key trust + branded URL in GA client | ✅ | `lumaline@0.1.0` = npm `latest` (SLSA provenance); `src/config.mjs` defaults `feed.lumaline.dev` / `c.lumaline.dev`; keyid `8720926064dfdf50` + next-key parked |
| 10 | Independent external security review (T7): high/criticals closed | ⚠️ RISK-ACCEPTED | **OWNER RISK-ACCEPTANCE 2026-07-02 (NOT an independent human review).** An AI/automated review was run; its only critical was operational (a plaintext `.env` could leak if the working tree is bundled) — **verified git-clean** (both `.env` gitignored, never committed, absent from history, unstaged by `git add -A`; no tracked file holds a real key) and remediated (`scripts/bundle-for-review.sh`, fail-closed). No code-level high/critical surfaced. Also backed by cc's live-DB audit (`docs/ops/live-security-audit-2026-07-02.md`: 0 ERROR/CRITICAL advisors, RLS gates all money tables, anon reads 0 rows, `app.admins` unreachable, admin RPCs internally gated). **The owner explicitly accepts the risk of going live without an independent human review.** Reviewer package remains ready (`docs/ops/t7-external-review-brief.md` + `docs/superpowers/t7/`) should a human pass be commissioned later. |
| 11 | Live Stripe account activated | ✅ | API probe 2026-07-02: `charges_enabled=true, payouts_enabled=true, details_submitted=true`, country=RO, currency=eur |
| 12 | Live restricted key valid + minimal perms | ✅ | Leaked first key ROLLED by owner 2026-07-02; replacement verified same day: all read probes 200, `charges_enabled=true payouts_enabled=true` (RO/EUR), customers:write probe OK (create+delete). Key lives only in `.env` `STRIPE_SECRET_KEY_LIVE` |
| 13 | Connect **live** platform profile complete | ✅ | Owner confirmed 2026-07-03 ("all up and running"); consistent with the API probe (`payouts_enabled=true`, account fully activated) |
| 14 | LIVE webhook endpoints created + secrets staged | ✅ | Created 2026-07-02 (owner-named action, post-rotation key): connected `we_1ToexiCChUMF5SBO8AMAFzgG` (`account.updated`) + platform `we_1ToexiCChUMF5SBOXzth2wQT` (`transfer.reversed`,`transfer.canceled`) → `…/stripe-connect/webhook`. Signing secrets staged comma-split in `.env` `STRIPE_WEBHOOK_SECRET_LIVE` (same multi-secret format the fn verifies); enter Vault only at the gated swap |
| 15 | ≥1 REAL advertiser: contract + KYC + creative + budget + bid>0 + payment method | ❌ | **In progress.** First candidate ("Degen", €5/3 days) **rejected 2026-07-03 at creative review** — landing URL was a Rickroll = bait-and-switch under Ad Policy §4 (verified via page fetch). Owner (admin approver) chose to obtain a compliant creative instead. Awaiting: real ad text + matching landing + bid (CPVA recommended — views work in all terminals; CPC only IDE terminals per #26356). Then seed via `docs/ops/advertiser-onboarding.md`, card via `/billing/setup-link` post-swap. **This is the last open gate before the swap.** |
| 16 | New money-path code adversarially reviewed | ✅ | 2026-07-02: money-safety lens (multi-agent) → 4 findings, all fixed (`8862da9`, `ef4d9e2`): terminal-skip revenue loss (HIGH), drift-dedup alert swallowing, monitor blindness to the no-PM stall, false auto-resolve. Correctness/security/integration lenses reviewed inline with live-stack verification after the agent pool hit a session limit |
| 17 | Test suite green | ✅ | 2026-07-02: `node --test` **324 tests / 279 pass / 0 fail / 45 skipped** (baseline 244 → +80; skips = integration files without the local stack) |

## The swap itself (only after every row above is ✅)

1. `supabase secrets set STRIPE_SECRET_KEY=<sk/rk_live from .env>` (project `prmsonskzrubqsazmpwd`).
2. `supabase secrets set STRIPE_WEBHOOK_SECRET=<STRIPE_WEBHOOK_SECRET_LIVE from .env>` (comma-split connected,platform — same multi-secret fn).
3. Redeploy nothing (secrets hot); run `GET /monitor/status` + a monitor run → all green on live keys.
4. M5-T3: first real cleared impression → `POST /billing/charge?dry_run=true` → review → real run → exactly one live charge → `/billing/reconcile` green → sentinel still bills nothing.
5. M5-T4 (≈7–10 days later, after clearing + hold): `POST /stripe-connect/payout/batch` (owner-authorized `p_min_micros`) → reconciled €1+ live payout. See `docs/ops/publisher-live-onboarding.md`.

**Rollback:** set both secrets back to the test values (kept in `.env`/Vault history); the code is mode-agnostic.
