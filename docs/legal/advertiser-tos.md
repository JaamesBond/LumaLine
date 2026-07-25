# LumaLine Advertiser Terms of Service

**Last updated:** 2026-07-25 · **Effective:** upon owner merge · **Status:** v2.1 — replaces v2.0
(2026-07-23) and v1.0 (2026-07-02); sign-off act = owner merge of the PR containing this change

> **v2.1 change (2026-07-25):** §3.1 and §9 previously stated that unused prepaid ad credit is
> *forfeited when your account closes*. It now says forfeiture requires the advertiser's **explicit
> election**, and that exercising the GDPR right to erasure does **not** by itself forfeit credit.
> This aligns the Terms with the shipped behaviour and is **more favourable to the advertiser** than
> v2.0 — nothing here newly takes anything from anyone.

These Advertiser Terms of Service ("Advertiser Terms") govern your participation
as an **advertiser** on LumaLine, operated by **Aivora SRL** (Romania)
("we", "us", "LumaLine"). "You"/"advertiser" means any business entity that
books campaigns, submits creatives, or funds ad spend on LumaLine.

By creating an advertiser account, funding your account, or submitting
creatives, you agree to these Advertiser Terms and to the
[Advertising Policy](./ad-policy.md), which is incorporated by reference.

How your data is handled is described in the
[Privacy Policy](./privacy-policy.md).

> **Material change from v1.0:** LumaLine advertising now operates on a
> **prepaid, non-refundable ad-credit model** (§3) and is offered to
> **businesses only** (§1). LumaLine billing is live: real money is charged.

---

## 1. Eligibility — businesses only

LumaLine advertising is a **business-to-business service**. It is **not offered
to consumers**. To advertise with LumaLine you must:

- be a **legally registered business** (company, sole trader / PFA, or other
  legal entity) — or an individual acting **wholly for purposes relating to
  their trade, business, craft, or profession** — with capacity to enter a
  contract;
- confirm, when creating an account or funding it, that you are acting as a
  business and not as a consumer;
- have a legitimate product or service that complies with the
  [Advertising Policy](./ad-policy.md);
- provide accurate account, billing, business, and identity information
  (including VAT/tax identifiers where applicable); and
- not be subject to applicable sanctions or export controls.

We may require KYC (Know Your Customer) verification, including identity and
business documentation, before activating campaigns or accepting deposits.

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

## 3. Funding, ad credit, and billing

### 3.1 Prepaid ad credit — non-refundable

Self-serve advertising on LumaLine is funded by **prepaid ad credit**:

- **Deposits:** You add funds to your advertiser account by card via Stripe
  Checkout, in **EUR**, within the minimum/maximum deposit bounds shown at
  checkout. A deposit is credited to your ad-credit balance **only after we
  receive verified payment confirmation from Stripe**.
- **NON-REFUNDABLE, SPEND-ONLY:** Ad credit is **non-refundable,
  non-withdrawable, non-transferable, and not redeemable for cash**, in whole
  or in part. Deposited funds can be used **only** to pay for advertising
  delivered through LumaLine. **You will not get deposited funds back**, except
  only: (a) where **we** made a billing error (see §5.4), or (b) where
  mandatory applicable law requires otherwise.
- **Forfeiture requires your explicit instruction:** unused credit becomes ours
  only when **you expressly elect to abandon it** — via the confirmed
  "write off remaining credit" action in your dashboard, or in writing — or
  where **we** terminate your account for breach (see §9). Until then it stays
  recorded to your account as unspent credit. It is still non-refundable and
  non-withdrawable; recording it is not a promise to pay it out.
- **Erasing your personal data does not forfeit your credit:** exercising your
  right to erasure under the GDPR (see the
  [Privacy Policy](./privacy-policy.md)) removes personal data. It does **not**
  by itself transfer your unused credit to us. We will not make the exercise of
  a data-protection right conditional on giving up funds.
- **Deliberate over-deposit is your risk:** deposit amounts are chosen by you;
  deposit only what you intend to spend.
- **Chargebacks are a breach:** Because ad credit is contractually
  non-refundable, initiating a card dispute or chargeback against a deposit
  (other than for genuine unauthorized use of your card) is a material breach
  of these Terms. On a deposit dispute or refund forced through your card
  issuer, we will **reverse the corresponding ad credit**, pause all your
  serving, and may terminate your account. Any spend already delivered against
  that credit remains payable.

### 3.2 Spend and draw-down (prepaid)

- **Reservation:** While your ads serve, a corresponding amount of your ad
  credit is reserved. Serving stops automatically (**no-fill**) when your
  available credit is insufficient — your balance can never go negative and
  you can never be billed beyond your deposited credit.
- **Clearing:** Every impression is initially provisional. A verified CPVA
  impression **clears after the 72-hour clawback window** (§5) and is drawn
  down from your ad-credit balance at clearing. Spend that is clawed back
  before clearing is never drawn down.

### 3.3 Postpay billing (by express agreement only)

For advertisers we expressly approve for postpay billing (registered payment
method, charged in arrears), the following applies:

- **Charge timing:** We charge only for cleared spend, **after** the 72-hour
  clawback window has elapsed (the "clawback-immune point").
- **Billing minimum:** Individual cleared entries below the Stripe processing
  minimum (€0.50) are aggregated into a later charge or waived.
- **Idempotency:** Each charge derives from a unique internal ledger entry
  group and is processed with an idempotency key, so a retry or system failure
  cannot produce a duplicate charge.
- **Failed charges** (declined card, insufficient balance) pause serving for
  all of your active line items until resolved.

### 3.4 Pricing and budget limits

- **Pricing:** In v1, billing is **CPVA only** (cost-per-viewed-attention-
  second) — you pay per verified attention-second at the bid set at line item
  creation. CPC (per verified click) is defined in the platform but **not yet
  billable**; no charge is computed from clicks until CPC billing is explicitly
  enabled. The clearing price per delivered impression equals the cpva_bid at
  the time the window was opened ("reserve-floor / first-price clearing").
  Bids set after a window opens do not affect that window's clearing price.
- **Budget limits:** Campaign spending is gated by the budget limits you set
  (daily and total). Spend stops automatically when a limit is reached. We make
  no guarantee of delivery at any particular rate or fill.
- **Reconciliation:** We run reconciliation comparing charges and ad-credit
  draw-downs to cleared CPVA ledger debits, and will investigate and correct
  confirmed discrepancies within a reasonable period.

---

## 4. VAT and invoicing

- Deposit amounts and prices are stated **exclusive of VAT** unless expressly
  stated otherwise.
- **Romania-established advertisers:** Romanian VAT is added and remitted as
  required by Romanian law.
- **EU advertisers outside Romania** with a valid VAT identification number:
  VAT is subject to the **reverse-charge mechanism** (Art. 196 of Council
  Directive 2006/112/EC) — you account for VAT in your member state. You must
  provide a valid VAT ID; without one we may charge VAT as required by law.
- **Non-EU advertisers:** supplies are generally outside the scope of EU VAT;
  local taxes are your responsibility.
- We issue an **invoice or receipt for each deposit** to the billing details on
  your account. Keep your business and VAT details accurate; invoices are
  issued to the details on file at the time of the deposit.

---

## 5. Clawback, spend corrections, and disputes

### 5.1 Clawback window
Every impression is initially **provisional**. A **72-hour clawback window**
runs from the time of the event. During this window, if we (or our
fraud controls) determine that the traffic was invalid or in violation of this
policy, we may reverse the provisional debit — that spend is never drawn from
your balance (prepaid) and never charged (postpay).

### 5.2 Clawback after clearing
If cleared spend is later found fraudulent and clawed back:

- **Prepaid accounts:** the clawed-back amount is **credited back to your
  ad-credit balance** (it remains subject to §3.1 — spend-only, non-refundable
  as cash).
- **Postpay accounts:** if the spend was already charged, we issue a **Stripe
  refund or credit note** for the corresponding amount, processed to the
  original payment method (5–10 business days).

### 5.3 Admin approval gate
Clawbacks are **human-gated**: automated IVT signals create a pending review
record, but no reversal is applied until an authorized LumaLine administrator
approves the clawback with a documented reason. This ensures that
false-positive fraud signals do not silently reduce your accrued spend.

### 5.4 Advertiser dispute (billing errors)
If you believe a deposit was mis-credited, spend was drawn down incorrectly, a
charge was incorrect, a creative was improperly rejected, or a clawback was
applied in error:

1. Contact **patrascu.matei03@gmail.com** with the relevant details (dates,
   deposit/session IDs, window IDs, ledger entries, amounts).
2. We will **aim to acknowledge** within 5 business days, though no guarantee
   of timing is made.
3. We will review in good faith and provide an outcome with our reasoning within
   a reasonable period.
4. If **we** made an error, we will correct it: mis-credited or mis-drawn
   ad credit is restored to your balance; an erroneous postpay charge is
   refunded or credited. This is the **only** refund path for deposits, beyond
   what mandatory law requires.

Raising a good-faith billing dispute with us under this section is **not** a
breach; going straight to a card chargeback instead is (§3.1).

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
per our [Privacy Policy](./privacy-policy.md).

---

## 7. Acceptable use and prohibited conduct

As an advertiser you must not:

- submit creatives that violate the [Advertising Policy](./ad-policy.md);
- engage in click fraud, impression fraud, or any artificial inflation of
  delivery metrics;
- attempt to reverse-engineer, bypass, or interfere with LumaLine's fraud
  controls, HMAC heartbeat chain, serving algorithm, or billing system;
- misrepresent your identity, business status, products, or billing
  information (including claiming business status while acting as a consumer);
- use LumaLine to promote content or products in violation of applicable law.

Violations may result in campaign suspension, account termination, and — where
we terminate your account for breach — forfeiture of any outstanding ad credit
(§3.1, §9), and/or referral to relevant authorities.

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

These Terms are effective when you create an account, fund it, or submit a
creative, and continue until terminated. Either party may terminate at any
time:

- **You:** by contacting us to close your account, or by deleting it from your
  dashboard. Any outstanding cleared and billable postpay charges remain
  payable. Unused prepaid ad credit remains **non-refundable and
  non-withdrawable** (§3.1) and cannot be spent once your account is closed. It
  becomes ours **only if you expressly elect to abandon it** at closure or in
  writing; otherwise it stays recorded as unspent credit. Either way you will
  not receive it back, except where §5.4 (our billing error) or mandatory
  applicable law requires otherwise.
- **Us:** we may suspend or terminate your account immediately if you breach
  these Terms or the Advertising Policy, or for legal, regulatory, or safety
  reasons. Where possible, we will provide notice and an opportunity to cure
  before termination for policy violations. Any remaining ad credit is governed
  by §3.1: it is forfeited to us only where we terminate your account **for
  your breach**. If we terminate for legal, regulatory, or safety reasons that
  are not your breach, your unused credit is **not** forfeited — it stays
  recorded as unspent credit unless you expressly elect to abandon it, while
  remaining non-refundable and non-withdrawable under §3.1.

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
all claims relating to LumaLine will not exceed the **total net amount paid to
us by you in the 12 months preceding the claim** (or €500, whichever is
greater). Some jurisdictions do not allow certain liability limitations, so
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

We may update these Terms as the product evolves. We will update the "Last
updated" date and, for material changes, give reasonable notice via the
repository, website, or the advertiser portal. **v2.0 is a material change
from v1.0** (prepaid non-refundable funding model; business-only eligibility).
Continued participation after an update means you accept the revised Terms.

---

## 14. Governing law

These Terms are governed by the laws of **Romania**, without regard to
conflict-of-laws rules. Disputes will be resolved in the courts of Romania or as
otherwise required by applicable law.

---

## 15. Contact

- **Support / disputes:** patrascu.matei03@gmail.com
- **Legal entity:** Aivora SRL — Str. Prieteniei 3, Constanța, Romania, 900293
