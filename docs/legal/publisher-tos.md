# LumaLine Publisher Terms of Service

**Last updated:** 2026-06-29 · **Effective:** 2026-06-29 · **Status:** §§1–6, 9–15 v1.0 in force (approved by Aivora SRL); **§7 Payouts and §8 Disputes payout additions are v1.1 DRAFT — pending owner sign-off** (added with the M3 payout rails, still test mode)

These Terms govern your participation as a **publisher** in LumaLine — the
`lumaline` tool that shows a clearly-labeled, signed, sponsored line in the
Claude Code status bar and pays you for verified ad views. "We"/"us"/"LumaLine"
means **Aivora SRL** (Romania). "You"/"publisher" means the developer who
installs LumaLine and logs in.

By logging in (`lumaline login`) and running LumaLine to earn, you agree to these
Terms. If you do not agree, do not log in; you may still run LumaLine
anonymously, in which case you earn nothing (see §4).

How your data is handled is described in the
[Privacy Policy](./privacy-policy.md).

---

## 1. Eligibility

To earn with LumaLine you must:

- be at least **18 years old** (or the age of majority where you live);
- have the legal capacity to enter a contract; and
- not be barred from receiving payments under applicable sanctions or other law.

We may require identity or payment-account verification before paying you, and
may decline accounts where eligibility cannot be established (see §7 for the
payout-onboarding and KYC requirements).

## 2. Participation is opt-in

LumaLine never wires itself into Claude Code or starts earning on its own.

- Installing the package has **no side effects**; it changes your Claude Code
  settings only when you explicitly run `lumaline install`, and that change is
  reversible with `lumaline uninstall`.
- Earning requires an **explicit, opt-in login** (`lumaline login`). Before you
  log in, the client runs as an anonymous **sentinel** identity that is never
  billed and accrues nothing.
- There is no automatic self-update; updates happen only when you update the
  package yourself.

## 3. Acceptable use

You agree to run LumaLine honestly. You must **not**:

- generate fake, automated, robotic, or otherwise non-genuine views or clicks
  (for example via scripts, bots, emulators, click farms, headless sessions, or
  artificially keeping sessions "active");
- run multiple identities or devices to inflate earnings, or otherwise
  manipulate the measurement or billing system;
- tamper with, reverse, spoof, or replay the window/heartbeat protocol or
  signatures;
- interfere with, overload, or attempt to circumvent the service's fraud and
  rate-limiting controls; or
- use LumaLine in any unlawful manner.

We operate **server-side fraud and invalid-traffic (IVT) controls**. Suspected
invalid traffic is flagged automatically and during clearing, and affected
earnings can be **withheld or clawed back** (see §6). Determinations of invalid
traffic are made by us, reasonably and in good faith.

## 4. Earnings: accrual vs. payout

This section is important — please read it carefully.

- **Earnings accrue now; real payouts are not yet live.** As you serve verified
  views (and, where supported, clicks), earnings **accrue** to your ledger. The
  payout rails described in §7 are currently exercised in **Stripe test mode**;
  **real money payouts do not begin until the production "go-live" milestone.**
  Until go-live, any balance you see is **informational only**.
- **Accrual is not a guarantee of payment.** An accrued or "provisional" balance
  is not money owed until it has cleared (see §6), the hold in §7 has elapsed, and
  payouts are live, and is always subject to clawback for invalid traffic, error
  correction, or breach of these Terms.
- **Anonymous and revoked/expired devices earn nothing.** The pre-login sentinel
  identity, and any revoked or expired device, accrue **$0**. Only verified
  views from a logged-in, active device accrue.
- **Currency and minimums.** Earnings are tracked in micro-USD. A minimum payout
  threshold of **US$25.00** applies (see §7); balances below the minimum carry
  forward.
- **Taxes.** You are responsible for any taxes on amounts you receive, and for
  providing any tax information we (or our payment processor) are required to
  collect (see §7).

## 5. Revenue split

Cleared advertiser revenue is shared on a **transparent, publisher-favored
split**: the **publisher receives 60%** of cleared gross revenue for their
verified delivery, and the platform retains 40%. The split is computed in integer
micro-USD at clearing time. We will give reasonable notice before changing the
split.

## 6. Clearing and clawback (invalid traffic)

- **Clearing window.** Earnings are recorded as **provisional** when a view or
  click occurs and become **cleared** only after a clawback window of
  **72 hours**, provided they were not flagged as invalid traffic.
- **Clawback.** If we determine (reasonably and in good faith) that traffic was
  invalid, fraudulent, or in breach of these Terms — whether before or after
  clearing — we may **reverse the associated earnings** and mark them clawed
  back. Because fraud typically affects a view and its click together, a clawback
  may reverse both for the affected window.
- **No payment for unclearable activity.** Activity that never satisfies the
  honest-dwell and verification rules (for example, a click on a window that was
  never genuinely viewed) does not clear and is not paid.

## 7. Payouts

Payouts move your cleared, held 60% share from your LumaLine ledger to your own
bank account. They are operated through our payment processor and are currently
exercised in **Stripe test mode** (no real money moves until production go-live;
see §4).

- **7.1 Payout method (Stripe Connect).** Payouts are made via **Stripe Connect
  (Express)**. Before you can be paid you must complete Stripe's onboarding from
  the CLI/dashboard, which links a payout bank account or debit card to your
  publisher account. We store only a Stripe account reference; your bank details
  are held by Stripe, not by LumaLine (see the [Privacy Policy](./privacy-policy.md)).
- **7.2 Identity (KYC) and tax.** Stripe performs identity verification (KYC) as
  required by law and its own rules; we may withhold a payout until that
  verification succeeds. You are responsible for any taxes on amounts you receive
  and for providing tax information that we or Stripe are required to collect. We
  may withhold amounts where required by law.
- **7.3 Minimum and schedule.** The minimum payout is **US$25.00**. Eligible
  balances at or above the minimum are paid on a periodic batch; a balance below
  the minimum **carries forward** to a later batch until it reaches the minimum.
- **7.4 Hold period (always longer than the clawback window).** A cleared
  earning becomes **payable only after a hold period that is strictly longer
  than the 72-hour clawback window** — currently **7 days** from the underlying
  view or click. This guarantees that **no earning still inside its clawback
  window is ever paid out.** If the hold or clawback window changes we will
  update these Terms and the published money timeline.
- **7.5 Fraud / velocity review.** A payout may be **delayed or held** for
  anomaly, velocity, or fraud review (for example, an unusually large or rapid
  change in earnings). Held payouts are reviewed in good faith; we will release
  or explain them.
- **7.6 Effect of clawback on amounts already paid.** If traffic is found
  invalid **after** the corresponding amount was already paid to you, we may
  **offset** the clawed-back amount against your future earnings, or, where that
  is not possible, **request repayment**. Advertiser refunds do not by themselves
  reduce a correct publisher payout; only a clawback of *your* traffic does.
- **7.7 Supported countries.** Payouts are available only where Stripe Connect
  supports payouts to your country and your account is not subject to sanctions.
  If your country is unsupported your account is marked payout-ineligible with a
  reason; earnings continue to accrue and can be paid if support later becomes
  available.
- **7.8 Currency, fees, and failed transfers.** Payouts are denominated in
  **US dollars**. Currency conversion and any processor fees are handled by
  Stripe and may apply. If a transfer fails or is returned (for example, a
  closed bank account), the amount is **restored to your balance** for a later
  retry once you correct the issue.

## 8. Disputes

If you believe earnings were wrongly withheld, clawed back, calculated, or paid,
you may dispute it by contacting **patrascu.matei03@gmail.com** with the relevant
details (e.g. dates, window ids, amounts from your ledger or audit log).

- We will **acknowledge and respond within 5 business days** of receiving a
  complete dispute.
- We will review the relevant records and our fraud determinations in good faith
  and tell you the outcome and our reasoning. A dispute is resolved by us with a
  recorded resolution (upheld or rejected, with a reason).
- This process does not limit any rights you have under applicable law.

## 9. Account suspension and termination

We may **suspend or terminate** your account, withhold or reverse unpaid
earnings, and/or revoke your devices if we reasonably believe you have breached
these Terms (especially §3), engaged in fraud or invalid traffic, or created risk
to the service or other users. Where practical and lawful, we will tell you why.
You may stop participating at any time (see §10).

## 10. Revocation and logout

You are always in control:

- `lumaline logout` revokes the device token and stops all earning and data flow
  from that device; a revoked device accrues **$0**.
- `lumaline uninstall` removes the status-line wiring and restores your prior
  Claude Code configuration.
- You may request closure of your account and deletion of your data as described
  in the [Privacy Policy](./privacy-policy.md). We may retain the minimum records
  required by law (e.g. ledger entries for accounting); see the Privacy Policy
  for how deletion preserves financial-ledger integrity while removing your
  personal data.

## 11. No warranty

LumaLine is provided **"as is" and "as available," without warranties of any
kind**, express or implied, including merchantability, fitness for a particular
purpose, and non-infringement. We do not warrant that the service will be
uninterrupted, error-free, or that any particular level of earnings or fill will
be available. Sponsored content originates from advertisers; we do not endorse
it.

## 12. Limitation of liability

To the maximum extent permitted by law, LumaLine and its operators will not be
liable for any indirect, incidental, special, consequential, or punitive damages,
or for lost profits or lost earnings, arising out of or relating to these Terms
or your use of LumaLine. To the maximum extent permitted by law, our total
aggregate liability to you for all claims relating to LumaLine will not exceed the
greater of (a) the total cleared, payable earnings actually owed to you at the
time the claim arose, or (b) **US$100**. Some jurisdictions do not allow certain
limitations, so some of the above may not apply to you.

## 13. Changes to these Terms

We may update these Terms as the product evolves (for example, at payout
go-live). We will update the "Last updated" date and, for material changes, give
reasonable notice (e.g. via the repository, website, or a notice in the CLI).
Continued participation after an update means you accept the revised Terms.

## 14. Governing law

These Terms are governed by the laws of **Romania**, without regard to
conflict-of-laws rules, and any disputes will be resolved in the courts of that
jurisdiction (or as otherwise required by applicable consumer-protection law).

## 15. Contact

- **Support / disputes:** patrascu.matei03@gmail.com
- **Legal entity:** Aivora SRL — Str. Prieteniei 3, Constanța, Romania, 900293
