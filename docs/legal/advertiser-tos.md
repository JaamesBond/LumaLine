# LumaLine Advertiser Terms of Service

**Last updated:** 2026-06-29 · **Effective:** upon owner sign-off · **Status:** v1.0 DRAFT — pending owner sign-off (Aivora SRL)

These Advertiser Terms of Service ("Advertiser Terms") govern your participation
as an **advertiser** on LumaLine, operated by **Aivora SRL** (Romania)
("we", "us", "LumaLine"). "You"/"advertiser" means any person or entity that
books campaigns, submits creatives, or funds ad spend on LumaLine.

By creating an advertiser account, funding a campaign, or submitting creatives,
you agree to these Advertiser Terms and to the
[Advertising Policy](./ad-policy.md), which is incorporated by reference.

How your data is handled is described in the
[Privacy Policy](./privacy-policy.md).

**IMPORTANT — Pre-production notice:** LumaLine's billing system is currently
operating in **test mode** (Stripe test keys only). No real money is charged or
transferred until the production go-live milestone is explicitly enabled by
Aivora SRL. Until that point, campaign spend, charges, and credits shown in the
system are for testing and verification purposes only.

---

## 1. Eligibility

To advertise with LumaLine you must:

- be a legally registered business or an individual at least 18 years old (or
  the age of majority in your jurisdiction) with capacity to enter a contract;
- have a legitimate product or service that complies with the
  [Advertising Policy](./ad-policy.md);
- provide accurate account, billing, and identity information; and
- not be subject to applicable sanctions or export controls.

We may require KYC (Know Your Customer) verification, including identity and
business documentation, before activating campaigns, particularly prior to
production billing go-live.

---

## 2. Campaign creation and creative review

**Booking:** You create and manage campaigns, line items, and creatives through
the advertiser portal or, where agreed, via our admin interface. Campaigns begin
in **`draft`** status and become eligible for serving only when all of: the
advertiser, campaign, line item, and creative are set to **`active`**.

**Creative review:** All creatives must be reviewed and approved by LumaLine
before they serve. The creative review process and content standards are defined
in the [Advertising Policy](./ad-policy.md). We may reject, modify, or
withdraw approval for any creative at any time, at our sole reasonable
discretion.

**Targeting:** v1 targeting is global. See [Advertising Policy §7](./ad-policy.md#7-campaign-targeting-v1).

---

## 3. Billing, charging, and payment

### 3.1 Pre-production (test mode)
Until LumaLine's production billing go-live is explicitly enabled, no real
charges are made. Campaigns may run against test/synthetic inventory with
simulated charges for verification purposes only.

### 3.2 Production billing
Upon production go-live, the following terms apply:

**Charge timing:** We charge the advertiser debit corresponding to a cleared
CPVA impression **only after the 72-hour clawback window has elapsed** (see §5).
This is the "clawback-immune point" — the moment at which the spend is final.
We do not charge before this point.

**Billing minimum:** Individual cleared entries below the Stripe processing
minimum (€0.50) are not individually charged. Such cleared amounts are tracked
in the ledger and may be aggregated into a future charge or waived in a future
release. Until aggregation is implemented, sub-minimum entries are not collected.

**Idempotency:** Each charge is derived from a unique internal ledger entry
group and is processed with an idempotency key, so a retry or system failure
cannot produce a duplicate charge.

**Payment method:** Advertiser billing uses the payment method registered on
your account (Stripe). You authorize us to charge the registered payment method
for cleared ad spend. Failed charges (e.g. declined cards, insufficient
balance) will result in serving being paused for **all of your active line items**
until the payment issue is resolved.

**Budget limits:** Campaign spending is gated by the budget limits you set (daily
and total). Spend stops automatically when a limit is reached. We make no
guarantee of delivery at any particular rate or fill.

**Pricing:** In v1, billing is **CPVA only** (cost-per-viewed-attention-second)
— you pay per verified attention-second at the bid set at line item creation.
CPC (per verified click) is defined in the platform but **not yet billable**; it
will be enabled in a future release. No charge is computed from clicks until CPC
billing is explicitly enabled. The clearing price per delivered impression equals
the cpva_bid at the time the window was opened ("reserve-floor / first-price
clearing"). Bids set after a window opens do not affect that window's clearing
price.

**Reconciliation:** We run reconciliation reports comparing advertiser charges
to cleared CPVA ledger debits. Entries below the billing minimum generate cleared
ledger records but no corresponding charge and are excluded from discrepancy
calculations. We will investigate and correct confirmed discrepancies within a
reasonable period.

---

## 4. Revenue split and publisher payments

Of the gross revenue generated by an advertiser's campaign, **60% goes to the
publisher** whose verified delivery generated the event, and **40% goes to
LumaLine** as the platform fee. This split applies to all cleared CPVA
impression revenue. When CPC billing is enabled in a future release, the same
split will apply to click revenue. The split is computed in integer micro-EUR.

Advertiser charges are based on the **gross** clearing price. Publishers receive
their 60% share separately, after clearing and the hold period.

---

## 5. Clawback, refunds, and the money timeline

### 5.1 Clawback window
Every impression is initially **provisional**. A **72-hour clawback window**
runs from the time of the event. During this window, if we (or our
fraud controls) determine that the traffic was invalid or in violation of this
policy, we may reverse the provisional debit with no charge to you.

### 5.2 Clawback after charge
If a charge has already been made for an event that is later clawed back (only
possible if the charge occurred at or after the clawback-immune point and the
event is subsequently found to be fraudulent), we will issue a **Stripe
refund or credit note** for the corresponding amount. Refunds are processed to
the original payment method and may take 5–10 business days to appear.

### 5.3 Admin approval gate
Clawbacks are **human-gated**: automated IVT signals create a pending review
record, but no reversal is applied until an authorized LumaLine administrator
approves the clawback with a documented reason. This ensures that
false-positive fraud signals do not silently reduce your accrued spend.

### 5.4 Advertiser dispute
If you believe a charge was incorrect, a creative was improperly rejected, or a
clawback was applied in error:

1. Contact **patrascu.matei03@gmail.com** with the relevant details (dates,
   window IDs, ledger entries, amounts).
2. We will **aim to acknowledge** within 5 business days, though no guarantee
   of timing is made.
3. We will review in good faith and provide an outcome with our reasoning within
   a reasonable period.
4. If a charge is found to be in error, we will refund or credit it.

---

## 6. Data minimization and privacy

LumaLine collects **minimal, first-party data** about ad delivery:

- Per impression: verified attention-seconds, a salted non-reversible IP hash,
  window and session identifiers — no personal identifying information about the
  developer beyond what is necessary for fraud prevention.
- Per click: the click event time, a token hash, and whether the parent window
  was credited — no third-party pixel, cookie, or analytics SDK.
- We do not share raw impression or click data with advertisers beyond the
  aggregated delivery and spend reporting available in the advertiser portal.

Advertiser business account data (name, email, billing information) is handled
per our [Privacy Policy](./privacy-policy.md). Advertiser PII is collected only
after M2-T7 legal sign-off; until then, only synthetic/test advertiser accounts
are created.

---

## 7. Acceptable use and prohibited conduct

As an advertiser you must not:

- submit creatives that violate the [Advertising Policy](./ad-policy.md);
- engage in click fraud, impression fraud, or any artificial inflation of
  delivery metrics;
- attempt to reverse-engineer, bypass, or interfere with LumaLine's fraud
  controls, HMAC heartbeat chain, serving algorithm, or billing system;
- misrepresent your identity, products, or billing information;
- use LumaLine to promote content or products in violation of applicable law.

Violations may result in campaign suspension, account termination, reversal of
any outstanding credits, and/or referral to relevant authorities.

---

## 8. Intellectual property

You retain ownership of your ad creative content. By submitting a creative, you
grant LumaLine a limited, non-exclusive, worldwide license to display it through
the LumaLine platform to developers who have opted in to receiving sponsored
content.

You represent and warrant that you own or are licensed to use all content in
your creatives, and that displaying them does not infringe any third-party
intellectual property, privacy, or publicity rights.

---

## 9. Term and termination

These Terms are effective when you create an account or submit a creative, and
continue until terminated. Either party may terminate at any time:

- **You:** by contacting us to close your account. Any outstanding cleared and
  billable charges remain payable. Any budget credits or prepayments are subject
  to our refund policy (contact us).
- **Us:** we may suspend or terminate your account immediately if you breach
  these Terms or the Advertising Policy, or for legal, regulatory, or safety
  reasons. Where possible, we will provide notice and an opportunity to cure
  before termination for policy violations.

Termination does not affect accrued payment obligations.

---

## 10. No warranty

LumaLine is provided **"as is"** and **"as available"** without warranties of
any kind, express or implied. We do not warrant any particular delivery volume,
fill rate, audience reach, conversion rate, or campaign outcome. Ad performance
depends on organic publisher activity and inventory availability.

---

## 11. Limitation of liability

To the maximum extent permitted by law, LumaLine and its operators will not be
liable for any indirect, incidental, special, consequential, or punitive damages
arising out of or relating to these Terms or your use of LumaLine, including
lost profits or business opportunities. Our total aggregate liability to you for
all claims relating to LumaLine will not exceed the **total net amount charged
to you by LumaLine in the 12 months preceding the claim** (or €500, whichever
is greater). Some jurisdictions do not allow certain liability limitations, so
some of the above may not apply to you.

---

## 12. Indemnification

You agree to indemnify and hold LumaLine and its operators harmless from and
against any claims, liabilities, damages, costs, and expenses (including
reasonable legal fees) arising out of or relating to: (a) your creative content
or the products/services advertised; (b) your breach of these Terms or the
Advertising Policy; or (c) any third-party claim that your creative infringes
their rights.

---

## 13. Changes to these Terms

We may update these Terms as the product evolves (for example, at billing
go-live). We will update the "Last updated" date and, for material changes,
give reasonable notice via the repository, website, or the advertiser portal.
Continued participation after an update means you accept the revised Terms.

---

## 14. Governing law

These Terms are governed by the laws of **Romania**, without regard to
conflict-of-laws rules. Disputes will be resolved in the courts of Romania or as
otherwise required by applicable consumer-protection law.

---

## 15. Contact

- **Support / disputes:** patrascu.matei03@gmail.com
- **Legal entity:** Aivora SRL — Str. Prieteniei 3, Constanța, Romania, 900293
