# M5 go-live — the diligent sequence (2026-07-03)

The exact, ordered path from where we are now to real money flowing, with owner-vs-cc
ownership and a verification per step. Companion: `docs/ops/go-live-checklist.md` (the gate
evidence) — this doc is the *sequence*; that one is the *preconditions*.

> **▶ NEXT SESSION: read `docs/ops/HANDOFF.md` first — it is the single entry point.** This doc is
> the historical sequence; HANDOFF has the current state + exact next actions.

**State now (2026-07-03, GO-LIVE session):** **LumaLine is LIVE.** Swap done (Vault Stripe secrets
live, digest-verified); advertiser **Degen** has a live card + is `active` + serving to the owner
publisher; **billing proven** (first Degen paid impression credited, €0.05 provisional); client
**`lumaline@0.1.3`** shipped (refresh-race fix + view-only click-URL fix). Phase A ✅, Phase B ✅,
**Phase C (first charge) in progress**, Phase D (payout) pending.

- **Phase A — DONE.** `billing` redeployed (M5 live-PM + `/setup-link`); all 8 fns current
  (`lumaline-feed` **v21** with the has_dest fix, `billing`, `auth-device` v11, `monitor` v3,
  `stripe-connect` v9, `admin-booking` v7, `click` v13).
- **Phase B — DONE.** Swap applied + confirmed; post-swap monitor all-green; nothing charged.
- **Phase C — IN PROGRESS.** C1–C4 done (setup-link → card → activate → serving + first credit).
  **C5 remaining:** accrue ≥~€0.50 → clear 72h (or authorized early-clear) → dry-run → real charge →
  reconcile. Degen `line_item.weight` is temporarily **1000** (owner-authorized, to force the first
  credit) — **revert to 1** after the charge test.

---

## Phase A — pre-swap deploys (SAFE, still test mode)

| # | Step | Owner | Verify |
|---|------|-------|--------|
| A1 | **Redeploy `billing`** (ships M5 live-PM + `/setup-link` + retryable no-PM skip) — `bash scratchpad/m5-deploy-billing.sh`. Auto-mode blocks cc from production deploys. | owner runs | script asserts `/setup-link` → 400 (not 404) |
| A2 | Confirm other fns current | ✅ done | feed v19 / auth v11 / monitor v3 / stripe-connect v9 — all post-M5 |
| A3 | Land this plan + billing-gap note | cc (PR) | checklist + this doc merged |

**Exit A:** every edge fn on remote matches `main`; billing exposes `/setup-link`. Still test mode.

## Phase B — THE SWAP (owner GO; the one irreversible step)

Nothing charges at the swap: sentinel/house bill €0; Degen is inactive with no card.

| # | Step | Owner | Verify |
|---|------|-------|--------|
| B1 | `supabase secrets set STRIPE_SECRET_KEY=<sk/rk_live>` + `STRIPE_WEBHOOK_SECRET=<STRIPE_WEBHOOK_SECRET_LIVE, comma-split>` (project `prmsonskzrubqsazmpwd`) — `bash scratchpad/m5-swap.sh` | owner (explicit GO) | script echoes only names, never values |
| B2 | Post-swap smoke | cc | `monitor /run` green on live keys; `billing/reconcile` reachable; `/account` charges_enabled=true |
| B3 | Rollback rehearsed | — | restore the test secrets (kept in `.env`/Vault history); code is mode-agnostic |

**Exit B:** backend is live money; no charge has occurred.

## Phase C — first real charge (M5-T3)

| # | Step | Owner | Verify |
|---|------|-------|--------|
| C1 | `/billing/setup-link` for Degen (LIVE) → send URL to the friend → **they** enter their own card | cc generates; friend acts | Checkout session returns a URL |
| C2 | Confirm PM attached | cc | customer has a card; `choosePaymentMethod` will pick it |
| C3 | Activate Degen creative + line_item (`admin-booking .../activate`) — after owner OKs the ad text | owner OK; cc runs | status → active; feed can serve it |
| C4 | Ad serves to real client users (owner + friends running `lumaline`) | owner/friends | impressions accrue; T6 monitor stays green |
| C5 | After the 72 h clawback window clears: `billing/charge?dry_run=true` → review → real `charge` → `billing/reconcile` | cc; owner authorizes the real run | exactly one live PaymentIntent = the debit; reconcile green; sentinel billed €0 |

**Exit C = M5-T3 DONE:** one real advertiser charged, reconciled.

## Phase D — first real payout (M5-T4, ≈7–10 days after first impression)

| # | Step | Owner | Verify |
|---|------|-------|--------|
| D1 | A publisher (owner/friend) completes Express onboarding (real EEA IBAN) via `lumaline login` + `/connect/onboard` | owner/friend | `/connect/status` → transfers active |
| D2 | Earnings clear (72 h) + mature (7-day hold) | time | `app.publisher_payable_micros` > 0 |
| D3 | `/stripe-connect/payout/batch` (owner-authorized `p_min_micros`) → `/reconcile` | cc; owner authorizes | one reconciled €1+ transfer; no in-clawback share paid |

**Exit D = M5-T4 DONE → M5 COMPLETE.** LumaLine bills advertisers and pays publishers, for real.

## Phase E — post-go-live (M6, later, not blocking)

Dashboards + on-call runbook, load ceiling + DR-at-scale, richer IVT, advertiser API keys,
public transparency report. Per plan doc §M6.

---

## Guardrails (unchanged)

Branch + PR always; `node --test` count only grows (now 339); secrets via Vault/`.env` only,
never logged/committed; **cc never runs the swap or a real charge/payout without an explicit
owner GO for that specific step**; a single red gate is NO-GO; live money = confirm each
irreversible step. Rollback for the swap = restore test secrets.
