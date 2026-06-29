> 
# LumaLine Privacy Policy

**Last updated:** 2026-06-29 · **Status:** Draft v0.1

LumaLine (the `lumaline` npm package) shows a clearly-labeled, cryptographically
signed, sponsored line in the Claude Code status bar and pays developers who run
it ("publishers") for verified ad views. This policy explains exactly what data
LumaLine does and does not handle.

Our guiding rule is **data minimization**: the software is built to send the
smallest amount of data that makes paid, fraud-resistant ad delivery possible,
and to keep everything else on your machine. This policy is written to match what
the code actually does — not an aspirational version of it.

---

## 1. Plain-language summary

- We **never** receive your source code, file paths, prompts, conversation
  content, raw cost or token numbers, environment, or keystrokes. None of that
  leaves your machine.
- Before you log in, LumaLine runs as an anonymous "sentinel" identity. It is
  **never billed and accrues nothing**, and sends no account data.
- After you choose to log in (an explicit `lumaline login` command), we hold a
  small account record: an account id, a handle you choose, an optional country
  code, your device records, and your earnings ledger.
- The only data that leaves your machine during normal operation is a small,
  fixed set of ad-view measurements, a non-reversible salted hash of your IP
  (for abuse/cost control), and — once logged in — a short-lived device token
  that carries only internal UUIDs.
- Everything LumaLine shows or sends is also written to a **local, human-readable
  audit log** on your own machine, so you can see exactly what happened.
- We do **not** sell data. We do **not** bundle any third-party analytics SDK
  (LumaLine has zero runtime dependencies).

---

## 2. Who we are

LumaLine is operated by **Aivora SRL** (Romania); registered address:
**Str. Prieteniei 3, Constanța, Romania, 900293**. For privacy questions or to
exercise your rights, contact **patrascu.matei03@gmail.com**. Aivora SRL is established in the
EU (Romania); a separate GDPR Article 27 EU/UK representative is therefore
generally **not required** (confirm with counsel).

---

## 3. Data that leaves your machine — the complete list

This is the **entire** set of data LumaLine transmits off your device. Nothing
outside this list is sent.

### 3.1 Per ad-view "window" (measurement data)

Each time a sponsored line is shown, the client opens a short measurement
"window" and reports proof that the line stayed visible. For each window we
receive:

- an **opaque, server-issued window id** (a random identifier; it is not derived
  from anything on your machine);
- a **sequence number** for each heartbeat tick;
- an **HMAC heartbeat hash** — a rolling cryptographic value that proves the
  window stayed open for the measured time without revealing its contents;
- a **coarse activity bucket**: exactly one of `none`, `low`, `med`, or `high`.
  This is **not** a raw token count, **not** your cost, and **not** timing data.
  The raw signal used to compute the bucket (e.g. token/cost deltas) is kept
  locally and never sent;
- **timestamps** for the window and its heartbeats.

The purpose is honest, fraud-resistant billing: a view counts only after a full
server-measured dwell with enough honest heartbeats and real activity, so idle
sessions are never billed.

### 3.2 A salted, non-reversible hash of your IP address

For abuse and cost control (rate limiting), the server computes
`SHA-256(server-side secret salt + your IP)` and **immediately discards the raw
IP**. Only the resulting hash and a short-lived per-minute counter are stored.

- The salt lives **only on the server**; it is never sent to your machine.
- Because of the salt, the hash **cannot be reversed** back to an IP address
  (a raw IP would be brute-forceable; salting prevents that).
- We use this hash **only** to stop a single source from flooding the service. A
  flood costs us resources, not money, because the pre-login feed bills nothing.

The data model also **reserves** a field for a **coarse network classifier** (an
autonomous-system identifier — roughly "which ISP or cloud provider," never your
IP address and never a personal identifier). It is **not collected today**; if it
is ever enabled for invalid-traffic detection, it would carry only that coarse
network-level signal, and this policy will be updated to say so.

### 3.3 A short-lived device token (only after you log in)

After you log in via device-code authentication, your client holds a short-lived
bearer token (a JWT). It carries **only internal UUIDs** — a `publisher_id`, a
`device_id`, and an auth subject id. **No email, name, IP, or other personal
information rides in this token or in ad-view traffic.** The token is a
credential, not a data payload.

### 3.4 Earnings reads

When your client (or the website) reads your earnings, the response contains only
**monetary amounts in micro-USD** and **window metadata** (e.g. counts, states,
timestamps). No content from your machine is involved.

---

## 4. Data that NEVER leaves your machine

LumaLine does **not** collect, transmit, or have any access to:

- your source code or repository contents;
- file paths or directory structure;
- prompts, conversation content, or Claude's responses;
- raw cost figures or raw token counts (only the coarse `none/low/med/high`
  bucket derived locally);
- environment variables, secrets, or configuration;
- keystrokes or terminal input.

LumaLine ships with **zero runtime dependencies** and bundles **no third-party
analytics, telemetry, or tracking SDK**. There is no hidden data path.

Everything LumaLine displays or sends is mirrored to a **local, human-readable
audit log** under your LumaLine home directory (by default `~/.lumaline/audit.log`).
This file stays on your machine and is yours to inspect or delete.

---

## 5. Account data (server-side, only after you choose to log in)

Logging in is **opt-in and explicit** — it happens only when you run
`lumaline login` and complete a device-code authorization. Before that, the
install runs as an anonymous **sentinel** identity that is never billed and
accrues nothing, and we hold no account record for you.

Once you log in, we store:

| Data | Purpose |
|------|---------|
| Account identifier (auth user id) | Identifies your account |
| Handle (chosen by you) | Display / account reference |
| Country (optional, ISO 3166-1 alpha-2 code) | Payout eligibility / tax region |
| Device records — id, optional label, client version, created/revoked timestamps | Manage and revoke devices |
| Earnings ledger entries (micro-USD) | Track accrued earnings and payouts |
| Payout account reference (e.g. Stripe account id), once you set up payouts | Pay you |

Each publisher's data is isolated from every other publisher's data by
database row-level security (RLS); you can read only your own rows.

---

## 6. Purpose and legal basis (GDPR Article 6)

| Processing | Purpose | Lawful basis |
|------------|---------|--------------|
| Ad-view window measurements, salted IP hash | Deliver ads, verify views, prevent fraud, protect the service | Legitimate interests (fraud prevention, securing the service) and, after login, performance of our contract with you |
| Device token (UUID-only JWT) | Authenticate your device to the service | Performance of contract |
| Account record + earnings ledger | Operate your publisher account and pay you | Performance of contract |
| Retaining ledger/accounting records | Meet tax, accounting, and audit obligations | Legal obligation |

We do **not** rely on, or carry out, any processing for advertising profiling or
ad targeting based on your activity.

---

## 7. Data sharing

- **We do not sell your data.** Ever.
- **Advertisers** receive only **aggregate delivery statistics** (e.g. how many
  verified views/clicks a campaign got and what it owes). They never receive
  publisher identities, handles, IPs, device ids, or any personal data.
- **Service providers / sub-processors** process data on our behalf under
  contract, only to run the service:
  - **Supabase** — database, authentication, edge functions, and secret storage,
    hosted on **Amazon Web Services (AWS)** infrastructure. Holds your account
    record, earnings ledger, and the salted IP hash.
  - **Stripe** — payment processing and publisher payouts (active once payouts go
    live). Processes payout-account details.
  - **Resend** (resend.com) — transactional email delivery; sends the one-time
    sign-in code during `lumaline login` (login verification only). Processes your
    email address for that purpose.

  We use no other sub-processors, and we update this list before any change.
- We may disclose data if **required by law** (valid legal process) or to protect
  the rights, safety, or security of LumaLine, our users, or the public.

---

## 8. Retention

Retention is tiered by purpose (subject to legal review):

- **Rate-limit counters** (salted IP hash + per-minute count): pruned within
  about **5 minutes** — they exist only for the current minute's budget. These
  are an abuse/cost guard, **not** the record that proves a view.
- **Raw operational data** (transient window state and similar short-lived
  records): retained for up to **90 days**, then deleted or aggregated.
- **Impression/click records and the earnings ledger** (the verified-delivery and
  billing record): retained for as long as your account is active and thereafter
  for **7 years** to meet accounting, tax, and audit obligations, then deleted or
  anonymized.
- **Account records**: retained while your account exists; deleted or anonymized
  after account closure subject to the accounting retention above.

---

## 9. Your rights — GDPR (EEA/UK users)

If you are in the EEA or UK, you have the right to:

- **Access** the personal data we hold about you;
- **Rectify** inaccurate data (e.g. correct your handle or country);
- **Erase** your data ("right to be forgotten"), subject to records we must keep
  by law (e.g. ledger entries required for accounting);
- **Restrict** or **object to** certain processing, including processing based on
  legitimate interests;
- **Portability** — receive your data in a structured, machine-readable format;
- **Withdraw consent** where processing relies on consent, and **log out / revoke
  a device** at any time (see §12);
- **Complain** to your local supervisory authority.

To exercise any of these, see §11.

## 10. Your rights — CCPA/CPRA (California users)

If you are a California resident:

- **We do not sell or "share" your personal information** as those terms are
  defined under the CCPA/CPRA.
- You have the right to **know** what personal information we hold, to **delete**
  it (subject to legally required retention), to **correct** it, and to **not be
  discriminated against** for exercising these rights.

To exercise these rights, see §11.

## 11. How to exercise your rights (including deletion)

- **Self-service:** you can stop all data flow at any time by logging out /
  revoking the device (`lumaline logout`) and uninstalling (`lumaline uninstall`).
  Revoked devices and the anonymous sentinel identity send and accrue nothing.
  You can also delete your local audit log yourself.
- **Requests to us:** email **patrascu.matei03@gmail.com** with your
  request (access, correction, deletion, or portability). We will respond within
  the period required by applicable law (generally within **30 days** for GDPR /
  **45 days** for CCPA, with any permitted extension). We may need to verify that
  the request comes from you before acting.
- **Note on erasure limits:** we may retain the minimum records we are legally
  required to keep (for example, ledger entries needed for tax and accounting),
  and will delete or anonymize the rest.

---

## 12. Security

- **Tokens are short-lived bearer credentials** carrying only UUIDs; they expire
  quickly and can be revoked by revoking the device.
- **Signing secrets stay server-side.** The client only ever verifies signatures
  against a bundled public key; it never holds a private signing key, and it
  refuses to display any ad whose signature does not verify.
- **Row-level security (RLS)** isolates each publisher's data in the database, so
  one publisher can never read another's records.
- The salted IP hashing described in §3.2 is designed so the raw IP is never
  stored and the hash cannot be reversed.

No system is perfectly secure, but these measures reflect the
data-minimization-first design of the product.

---

## 13. Children

LumaLine is a developer tool and is **not directed at children**. We do not
knowingly collect personal data from anyone under **16**. If you believe a child
has provided us data, contact us (see §11) and we will delete it.

---

## 14. Changes to this policy

We may update this policy as the product evolves (for example, when payouts go
live or sub-processors change). We will update the "Last updated" date and, for
material changes, provide reasonable notice (e.g. via the repository, website, or
a notice in the CLI). Continued use after an update means you accept the revised
policy.

---

## 15. Contact

- **Privacy / data requests:** patrascu.matei03@gmail.com
- **Legal entity:** Aivora SRL — Str. Prieteniei 3, Constanța, Romania, 900293
- **EU/UK representative:** not required (EU-established controller) — confirm with counsel
- **Governing jurisdiction for this policy:** Romania

---

### OWNER-TODO checklist (must be resolved before publishing)

- [x] Legal entity + registered address — Aivora SRL, Str. Prieteniei 3, Constanța, Romania, 900293
- [x] Privacy contact email — patrascu.matei03@gmail.com *(consider a role address on your domain later)*
- [x] EU/UK representative — not required (EU-established); confirm with counsel
- [x] Governing jurisdiction — Romania
- [x] Named sub-processors — Supabase (on AWS), Stripe, Resend
- [x] Retention windows set — rate-limit ~5min, raw operational 90d, ledger/accounting 7y
