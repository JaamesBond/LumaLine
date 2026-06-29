# LumaLine Advertising Policy

**Last updated:** 2026-06-29 · **Effective:** upon owner sign-off · **Status:** v1.0 DRAFT — pending owner sign-off (Aivora SRL)

This Advertising Policy ("Ad Policy") governs all advertising campaigns placed
on LumaLine ("we", "us", "LumaLine"), a product of **Aivora SRL** (Romania).
"You"/"advertiser" means any person or entity that books campaigns, submits
creatives, or funds ad spend on LumaLine.

By creating a campaign or submitting creatives, you agree to this Ad Policy and
to the [Advertiser Terms of Service](./advertiser-tos.md). This Ad Policy is
incorporated by reference into those Terms.

---

## 1. What LumaLine is

LumaLine displays a **single, clearly labeled sponsored line** in the Claude
Code status bar of logged-in developer tools. Ads are shown only to developers
who have opted in via `lumaline install` and `lumaline login`. All ad content
is signed server-side and displayed verbatim — LumaLine does not render HTML,
images, video, or executable code. The surface is intentionally minimal: one
line of text, optionally clickable.

All impression and click data is **first-party and data-minimized**: we track
only the verified view event (no browsing behavior, no prompts, no code). Ad
targeting in v1 is **global** (no demographic or behavioral targeting).

---

## 2. Eligibility

Advertisers must:

- be a legally registered entity or individual 18 years of age or older with
  legal capacity to enter a contract;
- have a legitimate, lawful product, service, or brand to promote;
- not be subject to applicable sanctions or be a prohibited person or entity
  under any jurisdiction we operate in.

We may require identity, company, and payment verification (KYC) before
activating campaigns or processing payouts, and may decline accounts where
eligibility cannot be established.

---

## 3. Permitted content

Ads may promote:

- developer tools, SaaS products, technical services, or developer-relevant
  brands;
- educational content, courses, or documentation;
- legitimate commercial products and services that are legal in the advertiser's
  and the audience's relevant jurisdictions.

LumaLine's audience is **software developers using Claude Code**. Ads should
be genuinely relevant and useful to this audience. We reserve the right to
reject ads that are misleading, irrelevant, or inconsistent with LumaLine's
product thesis (transparency + honesty).

---

## 4. Prohibited content

The following categories are **absolutely prohibited** and will result in
immediate rejection or removal and may result in account suspension:

**Deceptive and misleading content**
- False, deceptive, or materially misleading claims about any product, service,
  or endorsement
- Ads impersonating Anthropic, Claude, LumaLine, or any legitimate brand
- Bait-and-switch content (landing page substantially different from the ad)
- Fake urgency, countdown timers, or manufactured scarcity claims

**Illegal and harmful content**
- Illegal products, services, or activities in the advertiser's or publisher's
  jurisdiction
- Malware, spyware, adware, phishing, or any security-compromising software
- Weapons (including unlicensed firearms and ammunition), explosives
- Controlled substances, narcotics, or prescription drugs without authorization
- Counterfeit goods or intellectual-property-infringing content

**Offensive and inappropriate content**
- Hate speech, discrimination, or content denigrating any person or group based
  on race, ethnicity, religion, gender, sexual orientation, disability, or other
  protected characteristics
- Pornographic, sexually explicit, or adult content
- Graphic violence, gore, or content designed to shock or disgust
- Harassment, threats, or content targeting a specific individual

**Financial and legal violations**
- Get-rich-quick schemes, Ponzi/pyramid schemes, multi-level marketing
- Unregistered securities, investment schemes, or guaranteed-return products
- Cryptocurrency scams or unregulated investment products
- Payday lending or predatory financial products

**Privacy violations**
- Ads promoting products that harvest personal data without consent
- Any integration with third-party tracking pixels, SDKs, or external analytics
  (LumaLine ads are first-party only; you may not add tracking to your creative)

---

## 5. Creative requirements

All creatives submitted to LumaLine must meet the following standards:

**Format**
- The ad line ("line" field) must be **plain text only** — no HTML, Markdown,
  control characters, emoji (unless prior written approval), or terminal escape
  codes.
- Maximum length: **120 characters** for the ad line, **30 characters** for the
  label (default "sponsored").
- The destination URL ("dest_url"), if present, must be an `https://` URL
  resolving to a page clearly related to the advertised product.

**Disclosure**
- All ads are automatically labeled **"sponsored"** (or an approved equivalent)
  in the status bar. You may not request removal or obscuring of this label.
- If your creative makes a comparative claim ("better than X"), it must be
  substantiated and not denigrate competitors unfairly.
- Any claim that constitutes an endorsement or testimonial must be genuine and
  disclosed in accordance with applicable FTC (US) and ASA (UK) guidelines, as
  well as equivalent rules in other jurisdictions where ads are shown.

**Accuracy**
- The destination URL must be live, secure (HTTPS), and not redirect through
  unsafe intermediaries.
- The ad text must accurately describe what the user will find at the
  destination. Deceptive click-through flows will result in creative rejection.

---

## 6. Review and approval

All creatives start in **`pending_review`** status and become **`active`** only
after our review:

- We typically review submissions within **3 business days**, though we make no
  guarantee of timing.
- We may request modifications or additional information before approving.
- We may reject any creative at our sole reasonable discretion, including for
  content that is technically compliant but inconsistent with LumaLine's brand
  and audience.
- An approved creative may be **suspended or removed** at any time if we
  determine it violates this Ad Policy or the Advertiser ToS.

We will notify you of approval, rejection, or suspension via the contact
information on your account.

---

## 7. Campaign targeting (v1)

In the current version (v1), **all targeting is global** — ads are eligible to
serve to any logged-in LumaLine publisher worldwide. There is no demographic,
geographic, behavioral, or interest-based targeting. Targeting fields are
reserved for future versions; setting `targeting` to any non-empty value
currently results in the line_item being excluded from serving.

---

## 8. Bidding, pricing, and spend

Ads are priced on a **CPVA (cost-per-viewed-attention)** basis: you pay per
verified attention-second of honest dwell, at the bid you set at campaign
creation. In v1, LumaLine uses **first-price / reserve-floor clearing** — you
pay your bid for the clearing interval. A second-price upgrade may be
introduced in a future version.

**Spend limits:**
- Set daily and total budget limits on your line items to control spend.
- Serving stops automatically when a budget is exhausted.
- We make no guarantee of fill or delivery at any particular rate.

Specific bid minimums, floor prices, and available inventory are confirmed in
your campaign agreement or the advertiser portal.

---

## 9. Fraud and invalid traffic (IVT)

We operate **server-side fraud controls** (anti-batch heartbeat checks, IVT
rate scanning, dwell-window verification, click deduplication). We do not pay
for, and you will not be charged for, traffic we determine to be invalid.

If charged for traffic later determined to be IVT, we will **refund or credit**
the corresponding amount via the clawback mechanism described in the Advertiser
Terms of Service. Similarly, if IVT is found on a publisher's traffic, we
reverse those earnings — protecting your spend from fraudulent publishers.

---

## 10. Changes to this policy

We may update this Ad Policy as the product evolves. We will update the "Last
updated" date and, for material changes, give reasonable notice via the
repository, website, or the advertiser portal. Continued participation after an
update means you accept the revised policy.

---

## 11. Enforcement

Violations of this policy may result in:

- creative rejection or removal;
- campaign suspension or termination;
- account suspension or permanent ban;
- withholding of any budget credits or refunds otherwise owed; and/or
- referral to relevant authorities where illegal activity is identified.

---

## 12. Contact

For questions about this policy or to dispute a creative rejection:

- **Support:** patrascu.matei03@gmail.com
- **Legal entity:** Aivora SRL — Str. Prieteniei 3, Constanța, Romania, 900293
