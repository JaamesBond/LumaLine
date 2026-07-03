# M6 — parallel execution kickoff (START HERE for the M6 session)

**Purpose:** let a second Claude Code session **execute M6 in parallel** while the primary session
validates M5 (first real charge + payout — a time-gated wait: accrual → 72h clearing → 7-day hold).
Companions: `docs/ops/HANDOFF.md` (live M5 state + IDs + tooling), `docs/superpowers/plans/2026-06-28-production-readiness-handoff.md` §M6 (full task cards).

---

## 0. PRIME DIRECTIVE — read before touching anything

**M5 is validating on the LIVE system. This M6 session must not confound or corrupt that.**

- **Prod is single-owner right now = M5 owns it.** M6 is **READ-ONLY on prod**: reads via
  `node scripts/ops/sql.mjs "<select…>"` are fine. **NO** live migrations, **NO** edge-fn deploys,
  **NO** secret changes, **NO** load against the live backend.
- **OFF-LIMITS files (M5's money path — do not edit):**
  `supabase/functions/billing/**`, `supabase/functions/lumaline-feed/**`, `supabase/functions/stripe-connect/**`,
  `supabase/migrations/*clearing_and_ledger*`, `*advertiser_billing*`, `*serving_algorithm*`,
  `*close_window*`, `*cpc_billing*`, `src/statusline.mjs`, `src/client/**`, `poc/**`.
- **Branch discipline** (PR orphaning has bitten this repo repeatedly): one branch per task
  (`m6/t1-dashboard-runbook`, `m6/t5-transparency`), rebase on `main` immediately before opening the
  PR, keep PRs small, and re-check `main` HEAD before/after. Never commit straight to `main`.
- **`node --test` count only grows; never break the suite.** No new runtime deps.

---

## 1. EXECUTE NOW — the safe slice (additive, read-only, zero M5 conflict)

### M6-T1 — on-call runbook + read-only admin dashboard  ← start here
- **Runbook** `docs/ops/oncall-runbook.md`: executable steps for manual clawback (`public.clawback(source_type, source_id, reason)`), suspend a publisher/advertiser (status flip), emergency ledger audit (zero-sum check), key rotation, and swap rollback (restore test secrets). Reference existing RPCs/fns; mark each step owner-gated vs read-only.
- **Read-only admin dashboard**: extend `scripts/ops/watch-billing.mjs` into a fuller read-only view — fill rate, impressions, credited views, fraud flags (`risk_flags`), rate-limit saturation (`rl_buckets`), ledger balance (zero-sum), monitor status. **Reads only** (management-API SELECT via `scripts/ops/sql.mjs` pattern).
- **Test / acceptance:** dashboard renders real series from live reads; runbook steps are executable (read-only ones runnable now, mutating ones dry-documented). No prod writes.

### M6-T5 — public transparency report
- **WHAT:** aggregate **non-PII** report — fill, credited views, clearing prices, publisher-share %, clawback rate — that **reconciles to the ledger**.
- **FILES:** `scripts/ops/transparency-report.mjs` (read-only generator) + `docs/` output; later a portal page (website repo).
- **Test / acceptance:** figures reconcile to the double-entry ledger (zero-sum); an assertion proves **no PII / no raw cost-token deltas** in the output (data-minimization invariant); numbers match direct SQL.

### (Optional) M2-T8 / M3-T8 — advertiser & publisher web dashboards
- Live in the **separate website repo** (Lovable `luma-line`), read RLS-scoped views — isolated from this repo. **BLOCKED on owner UX spec** (fields/flows/OAuth). Don't start until the owner specifies; then scaffold there, not here.

---

## 2. DEFER until M5-T3/T4 are validated (and why)

| Task | Why it must wait |
|------|------------------|
| **M6-T3 richer IVT** | Edits the live clearing/clawback path (`clearing_and_ledger.sql`, risk tables). A migration here could corrupt clearing of the impressions M5 is validating. |
| **M6-T2 load test** | Running a harness against the live backend pollutes real windows/impressions and confounds the charge/reconcile. *Building* the harness code locally is fine; *running* it vs prod is not. |
| **M6-T4 advertiser API keys** | New prod migration during validation = avoidable risk. |

All three are `DEPENDS-ON: M5`. Unblock them only after the primary session reports **M5-T3 charge reconciled** (and, for anything payout-touching, M5-T4).

---

## 3. Cost + validate-later (what "with that comes cost" means)

M6 features generate real cost/usage that must be **reconciled**, exactly like M5's first charge:

- **Every money-touching output reconciles to the ledger.** The transparency report (M6-T5) must tie
  out to the double-entry ledger (zero-sum). Any deferred money-path code (M6-T3/T4) ships with tests
  **and** a reconcile check before it goes live.
- **Build for validatability:** dashboard/report numbers must equal direct SQL; assert non-PII on any
  published surface; no raw activity deltas ever leave the device (M6-T3/T5 hard constraint).
- **Later validation gate:** when M5-T3/T4 are reconciled green, unblock the deferred M6 items and
  validate each the same way — a controlled action + a reconcile to ledger + Stripe. Record results in
  this doc and `go-live-checklist.md`.

---

## 4. Kickoff checklist (first steps for the M6 session)

1. Read `docs/ops/HANDOFF.md` (M5 state, IDs, `.env` suffixes, tooling) and §M6 of the production-readiness handoff (full task cards + acceptance).
2. `git checkout main && git pull && git checkout -b m6/t1-dashboard-runbook`.
3. Start **M6-T1 runbook** (pure docs, zero risk) → the read-only dashboard → then **M6-T5**.
4. Open small PRs; do **not** touch prod or the off-limits files; leave the deferred slice alone until M5 validates.

## Trust invariants (bind M6 too)
Official `statusLine` only · signed content only · honest billing · **data-minimization** (no raw
cost/token deltas ever leave the device — the hard constraint for M6-T3 and the M6-T5 report) ·
reversible · zero runtime deps.
