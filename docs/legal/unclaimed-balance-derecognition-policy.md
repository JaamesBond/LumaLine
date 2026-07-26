# Unclaimed balances: derecognition policy (note for the accountant)

**Status:** draft for the accountant · **Prepared:** 2026-07-26 · **Entity:** Aivora SRL (Romania)
**Scope:** when — and whether — an unpaid publisher balance or a residual advertiser credit may stop
being carried as a liability and be recognised as income.

This note exists because the answer is **not** "three years." Romania's three-year prescription
(Civil Code art. 2517) governs the contract, but it does **not** govern how long a UK or Canadian
counterparty has to come and claim. Applying a flat three years would derecognise money that is
still legally owed.

---

## 1. The short version

| Question | Answer |
| --- | --- |
| Is there an expiry clause? | **No.** Publisher ToS §7.9 states expressly that no period exists after which an unclaimed balance silently becomes ours. A timed forfeiture is void under RO Civil Code art. 2517 + Law 193/2000 + Directive 93/13. |
| What converts a balance to income, then? | Only (a) an **express write-off election** by the counterparty, or (b) **expiry of the applicable limitation period**, which is per-counterparty, not per-company. |
| Do we owe anyone an escheat/unclaimed-property remittance? | **No** — see §4. Nexus-dependent, and we have none outside Romania. |
| Is the write-off election safe to book as revenue? | **Depends on B2B vs consumer** — see §3. |

---

## 2. Limitation periods — use the longest applicable *per counterparty*

Derecognition on the basis of a lapsed claim must be keyed to **the counterparty's own law**, because
Publisher ToS §14 (as amended in v1.4) does not displace their home-state mandatory protections, and
§7.9 now says expressly that the longer of the two periods applies.

| Jurisdiction | Period for a contract claim | Runs from |
| --- | --- | --- |
| Romania | 3 years (Civil Code art. 2517) | when payment fell due |
| Germany | 3 years | — |
| France | 5 years | — |
| **England & Wales** | **6 years** (Limitation Act 1980); 12 if executed as a deed (not our case) | accrual of the cause of action |
| **Canada — Ontario** | 2 years basic, **15-year ultimate** | discoverability |
| **Canada — BC, AB, SK, NL, PEI** | ~2 years + provincial long-stop | discoverability |
| **Canada — Québec** | 3 years (CCQ) | — |
| **Canada — New Brunswick, Nova Scotia** | **6 years** (older Limitation of Actions Acts) | — |
| United States | **NOT ESTABLISHED — see §6** | — |

**Operating rule:** derecognise only when the period for *that publisher's* jurisdiction has run,
measured from the date the balance became payable. Do not adopt a single global number until §6 is
closed. If a single conservative figure is wanted for simplicity, it must be **at least** the longest
in the table above and cannot be justified at three years.

**Discoverability caveat (Canada, most provinces):** the two-year clock runs from when the claim was
*reasonably discoverable*, not from when the balance arose. A publisher who was never told a balance
existed has an arguable late discovery date. Where our records do not show that the publisher was
notified of the balance, treat the clock as not yet started.

---

## 3. Write-off elections — two different risk profiles

### 3a. Advertiser residual credit — B2B, safe to recognise

Implemented as `public.advertiser_writeoff_credit()`
(`supabase/migrations/20260726100000_advertiser_erasure_split.sql:137`). It is opt-in, must be
deliberately invoked by the advertiser, books real `platform_revenue`, sets
`deletion_disposition = 'writeoff'`, and is audited to `advertiser_action_log` as `gdpr_writeoff`.

The advertiser side is **business-only** by contract (Advertiser ToS §1, "Eligibility — businesses
only": a "business-to-business service … not offered to consumers", and the advertiser must confirm
at account creation and at funding that they act "as a business and not as a consumer"). UK CRA Part 2 and the Canadian
provincial consumer statutes apply to **consumer** contracts, so they do not reach this path. A B2B
counterparty's deliberate release of a debt owed to it is an ordinary, enforceable act.

**Treatment:** recognise on election. Retain the `advertiser_action_log` entry as the evidence.

> **Open item, flagged not answered:** the **breakage / VAT position** on this recognition is
> unresolved. Prepaid ad credit that is written off is being booked as revenue; whether that is a
> VATable supply, an adjustment to an earlier supply, or non-supply breakage income has not been
> determined. This is a question for the accountant, and it is live — the path is deployed and
> reachable today.

### 3b. Publisher unclaimed balance — consumer, do **not** treat as final

**There is no code path.** Grep across all 78 migrations: no publisher write-off function exists, and
`20260727100000_gdpr_pending_deletion.sql:238-244` explicitly *refuses* `writeoff` as a disposition
because that function moves no money. A publisher write-off is therefore an out-of-band, manual act,
and has never occurred.

That is the correct design and should stay that way. The UK/Canada review found that a
contemporaneous confirmation does **not** immunise a forfeiture from the CRA 2015 Part 2 fairness
test, and that Québec consumers cannot waive statutory rights at all. Building an in-flow "I forfeit
my balance" checkbox would convert a voluntary post-hoc release into a standard non-negotiated
**term** — which is the attackable form. Collect the election only as a separate written statement,
as §7.9 already provides.

**Treatment:** where the publisher is a consumer resident in the UK or Canada, **do not derecognise
on the election alone**. ToS §7.9 (v1.4) now promises to restore the balance if the publisher's own
law makes the election non-binding, so the liability is not extinguished with certainty. Carry it
until the applicable limitation period in §2 has also run. For a publisher who is genuinely acting as
a business, or resident where no such non-waiver rule applies, the election may be treated as final.

**Evidence to keep for any publisher election:** the written statement itself, the date, the
publisher's country at the time, the balance in micros, and whether they were acting as a consumer or
a business. Nothing in the system records this automatically.

---

## 4. Escheat / unclaimed property — no duty, but the trigger is worth knowing

No remittance obligation arises in the UK, Canada, or the US, because all three regimes are
**nexus-scoped** and Aivora SRL has no establishment, registration, branch, authorisation, or bank
account in any of them:

- **UK** — the Dormant Assets Scheme binds UK-authorised banks, building societies, insurers, and
  investment/securities firms. No general statute reaches a foreign company with no UK presence.
- **Canada** — provincial. Alberta's UPPVPA covers holders *doing business in Alberta*; BC's
  Unclaimed Property Act covers designated holders with local connections; other provinces target
  local financial institutions. The uniform-act family generally excludes property held, due and
  owing in a foreign country arising out of a foreign transaction.
- **US** — settled previously: no US nexus, so the second-priority rule in *Texas v. New Jersey* has
  no target.

Publisher ToS §7.9 already carries a conditional undertaking to comply if such a law ever does apply,
using the last address on file. No action needed.

**Trigger to watch:** this answer is contingent, not permanent. It flips on acquiring local nexus —
registering to do business in a province, opening a local bank account, or establishing a branch or
subsidiary. If that is ever contemplated, revisit before, not after.

---

## 5. Data-deletion deadlines — unaffected, no change required

Recorded here only so the same review does not get run twice. The single 25-day alert
(`app.gdpr_complete_pending(p_overdue default interval '25 days')`,
`supabase/migrations/20260727100000_gdpr_pending_deletion.sql:610`, measured from
`deletion_requested_at`) sits inside **every** applicable deadline:

| Regime | Deadline | 25-day alert margin |
| --- | --- | --- |
| EU GDPR Art. 12(3) | one month (+2 months for complex) | ~5 days |
| UK GDPR | one month (+2 months) | ~5 days |
| PIPEDA | 30 days, promptly | 5 days |
| Québec Law 25 | 30 days (extendable to 60) | 5 days |

Two notes: **Québec Law 25 has no size threshold** and reaches foreign organisations targeting
Québec residents, so it applies in full from the first Québec publisher; and we have no mechanism to
*record* a claimed extension. Neither is actionable at current scale.

---

## 6. Open items — do not treat this note as complete

1. **US limitation periods were never examined.** The prior US review settled *escheat* and privacy
   scope only. Several US states run longer than six years on written contracts. Until this is
   checked, "England & Wales at six years is the longest applicable period" is **unverified**, and no
   global derecognition figure should be fixed. We have a US publisher record on production already.
2. **Breakage / VAT on the advertiser write-off** — §3a. Live and unresolved.
3. **The three-year derecognition policy** this note supersedes should not be adopted anywhere else
   in the accounts; if it already has been, it needs correcting to the per-jurisdiction rule.
4. **DAC7** reporting scope remains open and is tracked separately.

---

## 7. Current exposure (production, read-only, 2026-07-26)

Four publisher records: NL ×2, RO ×1, US ×1. **Zero UK, zero Canadian publishers.** One nonzero
balance: **RO, €0.90**, unpaid, `payout_status = pending`. Every other balance is exactly €0.

The UK/Canada analysis above is therefore **prospective**. It has not been exercised against a real
counterparty, and nothing in it has been validated by observed data — there is none to validate
against. It is written now so that it is in place before the first UK or Canadian publisher accrues,
not because a live case is pending.
