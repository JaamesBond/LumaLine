# LumaLine Money Timeline

Authoritative reference for how money moves through LumaLine. All billing logic
(`clear_events`, `/billing/charge`, `/billing/refund`, payout holds) must honor the
guarantees listed here. Treat deviations as bugs.

---

## The clawback-immune point

The **clawback-immune point** for any impression or click is:

```
impression.created_at + 72 hours
```

This is when the event becomes eligible for advertiser billing and publisher payout.
**NO charge or payout may precede this point.**

The 72h window is encoded as the `p_older` default on `public.clear_events()` in
`supabase/migrations/20260627033345_clearing_and_ledger.sql`. If that constant changes,
this document must be updated and the billing tests re-run.

---

## Event lifecycle

| Step | Clock | State | What happens |
|------|-------|-------|--------------|
| **T+0 — window open** | impression.created\_at − dwell | `ad_windows.state = 'open'` | Creative served to the developer's terminal. |
| **T+dwell — window close** | impression.created\_at | `impressions.state = 'provisional'` | `close_window()` records gross\_micros and creates the impression row. No ledger entry yet. |
| **T+dwell … T+72h — clawback window** | provisional age | — | `scan_ivt()` (5-min cron) may flag the impression → `risk_flags` row + `clawback_reviews` row (status='pending'). If an admin approves via `approve_clawback()`, `clawback()` reverses the impression (state='clawed\_back') without any ledger or Stripe action — it was never charged. |
| **T+72h — clawback-immune point** | impression.created\_at + 72h | eligible for clearing | `clear_events()` (hourly cron) promotes unflagged provisional impressions to `state='cleared'` and books a balanced 3-leg ledger group (advertiser\_billing / publisher\_earnings / platform\_revenue, 60/40 split). |
| **T+72h+ — billing run** | next `/billing/charge` call | `advertiser_charges.status = 'succeeded'` | `/billing/charge` (admin-triggered) reads `uncharged_advertiser_billings`, issues a Stripe PaymentIntent per cleared group, and records the result in `advertiser_charges`. On success, `impressions.stripe_charge_id` is stamped with the `pi_*` id. |
| **Clawback after charge** | any time post-billing | `clawback_reviews.refund_queued = true` | If `approve_clawback()` runs after a Stripe charge has already been issued, the admin calls `/billing/refund` with the approved review\_id. LumaLine calls `stripe.refunds.create({ payment_intent: pi_id, amount: cents, reason: 'fraudulent' })` and marks `refund_queued=true`. |
| **T+72h + hold — publisher payout** | M3-T2 | TBD | Publisher's 60% share becomes eligible for payout only after the hold period (strictly greater than the clawback window; exact value defined in M3-T2). |

---

## Guarantees

1. **Advertiser charge ≥ clawback-immune point — NEVER before.**
   `clear_events()` only promotes impressions older than 72h; `/billing/charge` only reads
   cleared entries. A provisional impression can never be charged.

2. **Publisher payout hold > clawback window — NEVER during the clawback window.**
   Payout eligibility (M3-T2) is set strictly after the 72h immune point. Publishers cannot
   receive a payout for an impression that could still be clawed back.

3. **Sentinel/house: never charged, never paid (structural).**
   `is_house=true` advertisers have `gross_micros=0` structurally (enforced by
   `close_window()`). `uncharged_advertiser_billings` excludes house rows. Even if
   `approve_clawback()` is called for a house impression, it detects `gross_micros=0`
   and returns a no-op result without calling `clawback()`.

4. **Clawback after charge → Stripe refund enqueued, not silent reversal.**
   The refund goes back through Stripe via `/billing/refund`. The ledger reversal
   (from `clawback()`) is separate from the financial refund. Both must complete.

5. **All reversals require human admin approval (logged: who, when, why).**
   `scan_ivt()` creates `clawback_reviews` rows with `status='pending'`. No impression
   is ever automatically reversed. An admin must call `approve_clawback(review_id, reason)`.
   The approval is recorded with `reviewed_by`, `review_reason`, and `reviewed_at`.

6. **Impressions carry their Stripe PaymentIntent id.**
   After a successful charge, `impressions.stripe_charge_id` is set to the `pi_*` id.
   This allows the `/billing/refund` endpoint to find the charge without a complex join,
   and provides an audit trail at the impression level.

---

## Constants (must match the code)

| Constant | Value | Source |
|----------|-------|--------|
| Clawback-immune window | **72 hours** | `clear_events(p_older default interval '72 hours')` |
| IVT scan window | 6 minutes (lookback), 5 minutes (cadence) | `pg_cron` schedule in `20260627033345_clearing_and_ledger.sql` |
| Billing minimum | 50 cents ($0.50) | `billing/index.ts`: `amountCents < 50 → skipped` |
| Publisher split | 60% | `app.accrue()`: `round(gross * 0.6)` |
| Platform split | 40% | `gross − publisher_share` |
| Micro-USD per cent | 10,000 | `microsToCents(micros) = round(micros / 10000)` |
