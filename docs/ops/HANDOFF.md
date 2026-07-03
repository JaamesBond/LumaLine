# LumaLine — session handoff (START HERE)

**Last updated: 2026-07-03 by the go-live session. This is the single entry point for the next
Claude Code session.** Companions: `m5-go-live-plan.md` (the ordered sequence),
`go-live-checklist.md` (gate evidence). Read those for detail; this is the state + next actions.

---

## TL;DR — where we are

**LumaLine is LIVE and billing works end-to-end.** Real Stripe keys are in Vault, a real
advertiser (Degen) serves to a real publisher (the owner), and the first paid impression has
credited. What remains is **volume + time**: accrue enough to clear Stripe's minimum, wait out
(or authorized-early-clear) the 72h clawback, then run the **first real charge (M5-T3)**; the
**first real payout (M5-T4)** is a ~7–10 day tail.

Milestones: **M0–M4 DONE. M5 ~85% — first charge + first payout remain.**

**Parallel work:** M5's remainder is a time-gated wait, so a **second session can execute M6 in
parallel** — see **`docs/ops/M6_KICKOFF.md`** (safe read-only/docs slice now; money-path + load-test
items deferred until M5 validates; prod stays single-owner = M5's).

---

## What is DONE (this session)

- **THE SWAP ✅** — Vault `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` are LIVE (digest-verified:
  `9f6ac48e…`==sha256(rk_live), `480e35c3…`==sha256(2 live webhook secrets)). Monitor all-7-green
  on live keys; `billing_recon_drift` flipped FAIL→PASS (now reconciling the live account).
- **Advertiser Degen LIVE ✅** — friend entered a live Visa ****5369 (customer `cus_Uokl8WXQmyB0o3`);
  owner authorized activation → creative `833331fc…` + line_item `fdb1a9f7…` + campaign + advertiser
  all `active`. Serving to the owner-publisher.
- **Billing pipeline PROVEN ✅** — 36 house windows credited in a 2h window (crediting/dwell/activity
  all work); **first Degen paid impression credited** (window `73061220…`, €0.05 provisional).
- **2 client bugs found + fixed + SHIPPED (`lumaline@0.1.3`, npm `latest`, provenance-signed):**
  1. **Refresh-token race** (PR #26) — `refreshInterval:1` spawns overlapping tick processes that
     redeemed the single-use refresh token in parallel → `invalid_grant` → client silently fell to
     the anonymous sentinel feed forever (house-only, never earns). Fixed with an O_EXCL refresh
     lock + "never drop a still-valid token to anonymous" in `src/client/auth.mjs`.
  2. **View-only dead click URL** (PR #25, `lumaline-feed` v21) — creatives with no `dest_url`
     surfaced a `c.lumaline.dev/c/<token>` URL that 404s. Now gated on `has_dest`.

## What is REMAINING for M5

1. **M5-T3 — first real charge (IN PROGRESS).** Need: accrue **≥ ~€0.50** (Stripe min charge; see
   pricing note) → clear the 72h clawback → `billing/charge` dry-run → owner-authorized real charge
   → `billing/reconcile` green. Currently: **1 Degen credit = €0.05 provisional**, ledger empty
   (impression < 72h old, not yet cleared). Owner left a session running to accrue more.
2. **M5-T4 — first real payout (~7–10 days out).** Publisher Express onboarding (real EEA IBAN) →
   earnings clear (72h) + mature (7-day hold) → `stripe-connect/payout/batch` (owner-authorized) →
   reconcile.
3. **REVERT the weight boost.** Degen `line_item.weight` was set **1→1000** (owner-authorized) to
   force the first Degen credit deterministically. **Set it back to 1** once enough has accrued for
   the charge test (`update public.line_items set weight=1 where id='fdb1a9f7-ad5d-49bc-a079-48ad9f328216'`).
   While it's 1000 the owner sees Degen almost always instead of a ~50/50 house split.

---

## ▶ NEXT SESSION — exact next actions

**First, re-check accrual** (owner has a session running to generate credits):
```
node scripts/ops/watch-billing.mjs                # live monitor, OR one-shot:
node scripts/ops/sql.mjs "select
  (select count(*) from public.ad_windows w join public.creatives c on c.id=w.creative_id join public.line_items li on li.id=c.line_item_id join public.campaigns cm on cm.id=li.campaign_id where cm.advertiser_id='4779db17-99e9-4bde-9723-ffe7dd4f7e58' and w.state='credited') as degen_credited,
  (select coalesce(sum(gross_micros),0) from public.impressions i join public.line_items li on li.id=i.line_item_id join public.campaigns cm on cm.id=li.campaign_id where cm.advertiser_id='4779db17-99e9-4bde-9723-ffe7dd4f7e58') as provisional_micros,
  (select count(*) from public.ledger_entries) as ledger_rows"
```

**When ≥ ~€0.50 (≈10 completed views) has accrued, choose the charge path (owner decides):**
- **Honest path:** wait for the impressions to age past 72h → hourly `clear_events` cron books the
  3-leg ledger → they appear in `uncharged_advertiser_billings` → run the charge.
- **Authorized early-clear test:** owner may authorize force-clearing Degen's own test impressions
  early (`select public.clear_events('0 seconds'::interval)` bypasses the 72h for aged-0) to see the
  full money move TODAY. **This bypasses the clawback — owner must explicitly authorize it.**

**Then the charge (M5-T3), owner authorizes the real run:**
```
# dry-run first (no money): POST billing/charge?dry_run=true  (admin JWT — see seed-degen.mjs for minting)
# review the plan → owner GO → real: POST billing/charge
# then: POST billing/reconcile  → expect green
```
Verify: exactly one live PaymentIntent on the friend's card, reconcile green, sentinel billed €0.
Then **revert the weight to 1** and update this doc + memory.

**After that → M5-T4 payout** per `m5-go-live-plan.md` Phase D.

---

## Key facts, IDs, gotchas (don't re-derive)

- **Supabase project ref:** `prmsonskzrubqsazmpwd`. Stripe acct: RO / **EUR** / charges+payouts enabled.
- **Degen:** advertiser `4779db17-99e9-4bde-9723-ffe7dd4f7e58`, line_item `fdb1a9f7-ad5d-49bc-a079-48ad9f328216`,
  creative `833331fc-a23a-4e10-b1e5-285e90c8f261`, Stripe customer `cus_Uokl8WXQmyB0o3`.
- **Owner publisher:** `bc50d59b-dc14-4b75-a68d-0c032c3b4fc3` (handle `pub_68761bd815f6`).
  Owner admin UUID (for admin JWTs): `68761bd8-15f6-4b59-86b1-15412d407c9a`. Sentinel publisher:
  `5e470000-0000-4000-8000-0000000000b1` (house-only path).
- **PRICING (corrected):** CPVA bills **per attention-second**, not per view. Degen bid €0.01/sec →
  a full 5s view ≈ **€0.05**. Budget €5 ≈ 100 completed views. Stripe min charge ≈ **€0.50** → need
  ~10 views before a charge is possible.
- **Crediting rule** (`close_window`): ≥3 beats + `activity_progress` (cost/token signal advanced in
  ≥1 beat) + full dwell. Idle never credits (by design). Client 0.1.3 must be installed + logged in;
  windows must open under the real publisher, not the sentinel.
- **Tooling (persisted in repo):** `scripts/ops/sql.mjs` = ref-guarded management-API SQL runner
  (reads `SUPABASE_ACCESS_TOKEN_REMOTE` from `.env`). `scripts/ops/watch-billing.mjs` = live billing
  monitor. Admin-JWT minting for the edge fns (billing/charge, admin-booking, setup-link) = HS256 from
  `SUPABASE_JWT_SECRET_REMOTE`, `sub` = owner admin UUID, `role:'authenticated'` — pattern in every
  inline node snippet this session used; the one-time seed script was `seed-degen.mjs` (Degen already
  seeded, not needed again). `.env` live creds use the **`_REMOTE`** / **`_LIVE`** suffixes.
- **AUTO-MODE BLOCKS** cc from prod deploys / DB writes / webhook creation. When the owner has
  explicitly authorized a specific action, run it with `dangerouslyDisableSandbox: true`. Never run
  the swap or a real charge/payout without an explicit per-step owner GO.
- **Publishing:** `git tag vX.Y.Z && git push origin <tag>` → `release.yml` runs
  `npm publish --provenance` via `secrets.NPM_TOKEN` (the LOCAL npm token is stale — CI's works).
  No client self-update → every publisher must `npm update -g lumaline` manually.
- **No product admin dashboard yet** (T8, deferred to M6). Monitoring = `scratchpad/watch-billing.mjs`,
  `lumaline earnings` (CLI), Stripe dashboard, Supabase table editor.
- **Crons active on remote:** `lumaline-clear-events` (hourly, 72h clawback), `lumaline-monitor-hourly`,
  `lumaline-sweep-windows` (10m), `lumaline-scan-ivt` (5m), `lumaline-rl-prune` (5m).

## Trust invariants (never violate without owner discussion)
Official `statusLine` only · signed content only · honest billing (full dwell, never idle, 72h
clawback before pay) · reversible · minimal data leaves the machine · zero runtime deps.
