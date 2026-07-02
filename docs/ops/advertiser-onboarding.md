# Advertiser onboarding runbook (M5-T2)

Operational steps to onboard a **real, paying advertiser**. Requires: advertiser legal in
force (`docs/legal/advertiser-tos.md` + `docs/legal/ad-policy.md`), an admin bearer token
(`lumaline login` as the seeded admin, or a minted admin JWT), and — for any **live**
charge — every M5 go-live gate green (`docs/ops/go-live-checklist.md`).

Base URL: `https://prmsonskzrubqsazmpwd.supabase.co/functions/v1`
(admin endpoints are gated by `app.admins` via `admin_check`; all calls below need
`Authorization: Bearer <admin JWT>`).

## 1. Contract + KYC (owner, offline)

- Signed advertiser agreement referencing the Advertiser ToS + Ad Policy.
- Verify business identity (registration, VAT if EU) — keep records off-repo.
- Agree: budget (EUR), pricing (CPVA and/or CPC bid), flight dates, creative text + URL.

## 2. Create the advertiser + campaign + line item + creative

```bash
# advertiser
curl -sX POST $BASE/admin-booking/advertisers -H "$AUTH" -H 'content-type: application/json' \
  -d '{"name":"<Legal Name SRL>"}'                      # → advertiser_id

# campaign
curl -sX POST $BASE/admin-booking/campaigns -H "$AUTH" -H 'content-type: application/json' \
  -d '{"advertiser_id":"<id>","name":"<campaign>"}'     # → campaign_id

# line item (bid in EUR micros; both models optional but ≥1 required)
curl -sX POST $BASE/admin-booking/line-items -H "$AUTH" -H 'content-type: application/json' \
  -d '{"campaign_id":"<id>", "cpva_bid_micros":..., "cpc_bid_micros":..., "budget_micros":...}'

# creative (plain text line + click URL — no HTML, per Ad Policy)
curl -sX POST $BASE/admin-booking/creatives -H "$AUTH" -H 'content-type: application/json' \
  -d '{"line_item_id":"<id>","line":"<ad text>","url":"https://…"}'
```

(Exact line-item/creative fields: see `supabase/functions/admin-booking/index.ts` header.)

## 3. Payment method (required BEFORE activation in live mode)

```bash
curl -sX POST $BASE/billing/setup-link -H "$AUTH" -H 'content-type: application/json' \
  -d '{"advertiser_id":"<id>"}'                         # → {url}
```

Send `url` to the advertiser: they open it in a browser and enter their card
(Stripe Checkout, setup mode — attaches the payment method to their Stripe customer).
**Never take card numbers directly.** The advertiser's own card only — platform-owned
cards must never fund advertiser spend (Stripe ToS).

Billing behavior without a payment method (live mode): the charge run **skips** the
advertiser with `no_payment_method` and **pauses** its line items — no credit is extended.

## 4. Activate

```bash
curl -sX PATCH $BASE/admin-booking/creatives/<creative_id>/activate -H "$AUTH"
```

Verify eligibility: fetch the feed and confirm the creative can serve (house fallback no
longer the only candidate).

## 5. First charge (live = M5-T3, owner-authorized)

- Impressions/clicks accrue → clear after the 72 h clawback window.
- Run `POST $BASE/billing/charge?dry_run=true` — review the plan.
- Run `POST $BASE/billing/charge` — exactly one PaymentIntent per cleared group
  (idempotent; UNIQUE on `entry_group_id`).
- Verify: `GET $BASE/billing/reconcile` green; sentinel/house billed **nothing**;
  T6 monitor run green.

## Records

Keep per-advertiser records (contract, KYC evidence, creative approvals) in the owner's
records off-repo. The DB stores only: name, Stripe customer id, campaign/line-item/creative
rows — no card data, ever.
