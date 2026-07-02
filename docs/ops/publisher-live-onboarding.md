# Publisher live payout onboarding (M5-T4)

What a real publisher must do to receive **live** payouts. Preconditions: every M5
go-live gate green + live Stripe keys active (`docs/ops/go-live-checklist.md`).

## Publisher steps (browser, ~5 min)

1. Install the client: `npm i -g lumaline` → `lumaline install` → `lumaline login`
   (device-code flow; magic-link email).
2. Start payout onboarding: `POST /stripe-connect/connect/onboard` with the device
   bearer (CLI wraps this) → returns a **hosted Stripe Express onboarding link**.
3. Complete it in the browser: real identity + **EEA IBAN** (payouts are EUR, EEA-only;
   `SUPPORTED_COUNTRIES` = EU-27 + IS/LI/NO).
4. Wait for `account.updated` → eligibility flips when Stripe reports transfers active
   (webhook-driven; check `GET /stripe-connect/connect/status`).

## Money timeline (why the first live payout is NOT same-day)

- Earnings accrue per credited view/click → **clear after 72 h** (clawback window)
  → **payable after the 7-day hold** (hold > clawback, by design).
- Payout minimum: **€25** by default (`min_payout_micros`, ToS §7). The batch RPC takes
  `p_min_micros` — an owner-authorized first live payout below the ToS minimum is
  publisher-favorable and allowed for the M5-T4 acceptance (≥ €1).
- So: first live impression → first possible live payout ≈ **7–10 days later**.
  No seeding, no synthetic ledger entries — honest billing invariant.

## Operator steps (admin)

```bash
# after gates green + at least one publisher payable:
POST /stripe-connect/payout/batch      # two-phase, idempotent, one active payout per publisher
GET  /stripe-connect/reconcile         # DB debits == Stripe transfers net of reversals
```

Both admin-gated. First live batch: run with a small `p_min_micros` only with explicit
owner authorization, verify the € lands, then `/reconcile` green + T6 monitor green.
