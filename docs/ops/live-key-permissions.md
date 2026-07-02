# Live restricted key — required permissions

Create a **restricted key** (Dashboard → Developers → API keys → Create restricted key,
**live mode**). Grant exactly:

| Resource | Permission | Used by |
|----------|-----------|---------|
| Customers | **Write** | billing: get-or-create customer per advertiser |
| PaymentIntents | **Write** | billing: charge cleared groups |
| Payment Methods | **Read** | billing: pick saved PM (live-mode PM selection) |
| Checkout Sessions | **Write** | billing: `/billing/setup-link` (setup mode) |
| Transfers | **Write** | stripe-connect: `/payout/batch` |
| Connect / Accounts | **Write** | stripe-connect: Express onboarding + account status |
| Account Links | **Write** | stripe-connect: hosted onboarding links |
| Webhook Endpoints | **Write** | one-time: create the 2 live endpoints (can be revoked after) |
| Balance | **Read** | monitor: Stripe reachability + recon |
| Events | **Read** | monitor/recon visibility |
| Charges | **Read** | reconcile paths |

Everything else: **None**.

Store it ONLY as `STRIPE_SECRET_KEY_LIVE=` in the repo-root `.env` (gitignored).
Never paste it into chat/issues/commits. It reaches Supabase Vault (`STRIPE_SECRET_KEY`)
only at the final gated go-live swap (`docs/ops/go-live-checklist.md`).

**History:** the first live restricted key (created 2026-07-01/02) was leaked into a local
session transcript by a tooling redaction failure and must be treated as compromised — roll
it before any live traffic.
