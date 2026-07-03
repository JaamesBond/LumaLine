# LumaLine — on-call runbook (M6-T1)

**The single operational entry point for an on-call incident.** Executable steps for the
money-critical actions: manual clawback, suspend a publisher/advertiser, emergency ledger audit,
key rotation, and swap rollback. Companions: `HANDOFF.md` (live state + IDs), `key-rotation.md`
(ed25519 signing key), `backup-recovery.md` (PITR / restore), `money-timeline.md` (when money moves).

---

## 0. How to read this runbook

Every step is tagged with who may run it and what it touches:

| Tag | Meaning | How to run |
|-----|---------|-----------|
| 🔎 **READ-ONLY** | A SELECT / status probe. Safe to run any time, including while M5 validates. | `node scripts/ops/sql.mjs "<select…>"` or the dashboards below. |
| 🔐 **OWNER-GATED** | Mutates prod (DB write, secret change, edge-fn deploy). | **Never** without an explicit per-incident owner GO. Then run with `dangerouslyDisableSandbox: true` (auto-mode blocks prod writes by default). |

**Prime directive during M5 validation:** prod is single-owner. Run 🔎 steps freely; do **not**
run any 🔐 step until the incident is real and the owner has said GO. Reading off-limits files is
fine; editing them is not.

### Tooling quick-reference (all read the management PAT from repo-root `.env`)

```bash
node scripts/ops/dashboard.mjs              # full read-only ops snapshot (fill, ledger, fraud, rl, monitor)
node scripts/ops/dashboard.mjs --watch      # same, refreshes every 5s
node scripts/ops/dashboard.mjs --json       # machine-readable, one JSON object
node scripts/ops/watch-billing.mjs          # focused live billing ticker (Degen/ledger/earnings)
node scripts/ops/transparency-report.mjs    # public non-PII aggregate report (reconciles to ledger)
node scripts/ops/sql.mjs "<sql>"            # ref-guarded management-API SQL runner (postgres role)
```

`sql.mjs` runs as the `postgres` role via the management API, so it can SELECT any table and EXECUTE
any RPC regardless of RLS/grants — which is exactly why a mutating query through it is 🔐.

### IDs quick-reference (don't re-derive — from `HANDOFF.md`)

| Thing | Value |
|-------|-------|
| Supabase project ref | `prmsonskzrubqsazmpwd` |
| Owner admin UUID (mint admin JWTs) | `68761bd8-15f6-4b59-86b1-15412d407c9a` |
| Owner publisher | `bc50d59b-dc14-4b75-a68d-0c032c3b4fc3` |
| Sentinel publisher (house-only, never bills) | `5e470000-0000-4000-8000-0000000000b1` |
| Advertiser "Degen" | `4779db17-99e9-4bde-9723-ffe7dd4f7e58` |
| Degen line_item / creative | `fdb1a9f7-ad5d-49bc-a079-48ad9f328216` / `833331fc-a23a-4e10-b1e5-285e90c8f261` |
| House advertiser | `LumaLine (self-promo)` (`is_house=true`) |

---

## 1. Manual clawback — reverse a fraudulent / disputed window

Fraud is the **pair** on a window: the CPVA impression *and* any CPC click. `public.clawback()`
reverses **every** ledger group booked for the window, marks all billable sources `clawed_back`, and
records one window-keyed risk flag. Reversing marks legs `reversed` (amounts unchanged, so each group
still sums to 0) and removes them from cleared balance.

### 1a. 🔎 Investigate first — what will be reversed

```bash
# Given an impression OR click id, find its window and every ledger group on that window.
node scripts/ops/sql.mjs "
with w as (
  select coalesce(
    (select window_id from public.impressions where id='<SOURCE_ID>'),
    (select window_id from public.clicks      where id='<SOURCE_ID>')) as window_id)
select le.account, le.state, le.amount_micros, le.event_type, le.source_type, le.source_id
from public.ledger_entries le, w
where (le.source_type='impression' and le.source_id in (select id from public.impressions where window_id=w.window_id))
   or (le.source_type='click'      and le.source_id in (select id from public.clicks      where window_id=w.window_id))
order by le.entry_group_id, le.account"
```

### 1b. 🔐 Execute the clawback (owner GO required)

Two paths — pick by how the fraud surfaced:

**Direct (ops-initiated, service_role):**
```bash
# p_source_type ∈ {'impression','click'} — either source on the window works.
node scripts/ops/sql.mjs "select public.clawback('impression','<SOURCE_ID>','ivt:manual')"
# → {"window_id":…,"entries_reversed":N,"impressions_clawed_back":N,"clicks_clawed_back":N}
```

**Human-gated review queue (when `scan_ivt` flagged it into a review):** admins act on the pending
review, not the raw source. These are `authenticated` admin RPCs — call via PostgREST with an admin JWT
(`sub` = owner admin UUID, `role:'authenticated'`, HS256 over `SUPABASE_JWT_SECRET_REMOTE`):
```
POST /rest/v1/rpc/approve_clawback   {"p_review_id":"…","p_reason":"…"}   # calls clawback() + records decision
POST /rest/v1/rpc/reject_clawback    {"p_review_id":"…","p_reason":"…"}   # leaves the impression paid
```
Sentinel (gross=0) is a no-op — house traffic never bills, so it can't be clawed.

### 1c. 🔎 Verify — the window is out of cleared balance and the ledger still balances

```bash
node scripts/ops/sql.mjs "select
  (select count(*) from public.impressions where window_id='<WINDOW_ID>' and state<>'clawed_back') as imps_not_clawed,
  (select coalesce(sum(amount_micros),0) from public.ledger_entries) as global_sum,   -- must stay 0
  (select count(*) from (select entry_group_id from public.ledger_entries group by 1 having sum(amount_micros)<>0) u) as unbalanced_groups"
```
Expect `imps_not_clawed=0`, `global_sum=0`, `unbalanced_groups=0`.

**Client-side dispute path (publisher-facing):** `public.resolve_dispute(p_dispute_id, p_status, p_resolution)`
(admin JWT) transitions a publisher dispute `open → resolved|rejected` with an audit trail. Idempotent.

---

## 2. Suspend a publisher / advertiser · pause serving

Status flips. Suspension stops *future* accrual; it does **not** reverse already-cleared money (use §1
clawback for that). All 🔐.

### 2a. 🔎 Identify the target

```bash
node scripts/ops/sql.mjs "select id, status from public.publishers where id='<PUB_ID>'"
node scripts/ops/sql.mjs "select a.id, a.name, a.status from public.advertisers a where a.id='<ADV_ID>'"
```

### 2b. 🔐 Flip status (owner GO)

```bash
# Publisher (enum publisher_status: active|suspended)
node scripts/ops/sql.mjs "update public.publishers set status='suspended' where id='<PUB_ID>'"

# Advertiser (enum advertiser_status: active|suspended) — also stop its delivery by pausing the
# campaign/line_items so the serving RPC drops it immediately (status='suspended' alone gates future
# eligibility; pausing is the fast kill):
node scripts/ops/sql.mjs "update public.advertisers set status='suspended' where id='<ADV_ID>'"
node scripts/ops/sql.mjs "update public.campaigns  set status='paused' where advertiser_id='<ADV_ID>'"
node scripts/ops/sql.mjs "update public.line_items set status='paused'
  where campaign_id in (select id from public.campaigns where advertiser_id='<ADV_ID>')"
```

Reverse a suspension by setting the status back to `active` / `active` and un-pausing.

### 2c. 🔎 Confirm no new eligible delivery

```bash
node scripts/ops/dashboard.mjs        # advertisers/publishers panel shows the new status; fill panel shows serving
```

---

## 3. Emergency ledger audit — the zero-sum invariant

The ledger is the single source of truth. **Invariant: every `entry_group_id` sums to 0, and the
global sum is 0.** A non-zero result means the deferred `ledger_group_balances` constraint trigger
was bypassed or disabled — a P0 money incident. All 🔎 (runnable now).

### 3a. 🔎 The one-shot audit

```bash
node scripts/ops/sql.mjs "select
  (select coalesce(sum(amount_micros),0) from public.ledger_entries) as global_sum,
  (select count(*) from (select entry_group_id from public.ledger_entries
     group by 1 having sum(amount_micros)<>0) u) as unbalanced_groups,
  (select coalesce(jsonb_agg(jsonb_build_object('account',account,'state',state,'sum',s)),'[]')
     from (select account, state, sum(amount_micros) s from public.ledger_entries
           group by account, state order by account, state) x) as by_account_state"
```
Expect `global_sum=0`, `unbalanced_groups=0`. The per-account/state breakdown lets you eyeball the
60/40 split: for cleared accrual, `-publisher_earnings ≈ 0.6 × advertiser_billing`.

### 3b. 🔎 Cross-check via the monitor RPC (identical logic, independent path)

```bash
node scripts/ops/sql.mjs "select public.monitor_ledger_unbalanced(50)"
# → {"groups":[], "global_sum_micros":0}  ← groups MUST be empty
```

### 3c. 🔐 If unbalanced — do NOT patch the ledger. Escalate.

The ledger is append-only. Never `UPDATE`/`DELETE` a leg to "fix" a sum. Capture the offending
`entry_group_id`s (3a lists them), snapshot with `backup-recovery.md`, and page the owner. Root-cause
is a trigger bypass, not a data typo.

---

## 4. Stuck / failed payout · failed charge triage — 🔎 read-only

```bash
# Payouts not in a terminal state, oldest first (stuck if pending > 6h — the monitor's threshold):
node scripts/ops/sql.mjs "select id, publisher_id, amount_micros, status, stripe_transfer_id, created_at
  from public.payouts where status not in ('paid','failed','canceled') order by created_at limit 50"

# Recent failed charges + billing-paused line items:
node scripts/ops/sql.mjs "select status, count(*), sum(amount_micros) from public.advertiser_charges
  where status in ('failed','pending') group by status"

# What the money-path monitor currently thinks (open alerts + per-check state):
node scripts/ops/sql.mjs "select public.monitor_status()"
```

Payout ledger mechanics (booked at **confirm**, never at reserve) and the crash-safe re-run path are
in `20260629100000_payout_rails.sql`'s header. Remediation RPCs (`payout_fail`, `payout_reverse`,
`payout_confirm`) are service_role and 🔐 — the `stripe-connect` edge fn owns them; run manually only
on an owner-authorized recovery.

---

## 5. Key rotation / key compromise — cross-link

Ed25519 **signing** key (the feed-trust key clients verify) has its own full runbook:
**`docs/ops/key-rotation.md`** — planned rotation order (never blacks out clients), compromise
response (flip to the already-bundled NEXT key), and keyid recovery. Do not improvise; follow it.

Current keyids: `src/keys/public.pem` = `8720926064dfdf50` (active), `src/keys/next.pem` =
`31433cdee001fc81` (bundled standby).

---

## 6. Swap rollback — restore Stripe **test** secrets — 🔐 owner-gated

The go-live "swap" set the live Stripe keys as **Supabase edge-function secrets** (read by the billing
+ stripe-connect fns via `Deno.env.get("STRIPE_SECRET_KEY")` / `STRIPE_WEBHOOK_SECRET`). Rollback =
put the **test** keys back and re-arm the test guard. Nothing in-flight charges at rollback (house/
sentinel bill €0; a paused advertiser can't serve). Mirrors Phase B1 of `m5-go-live-plan.md`
(`scratchpad/m5-swap.sh` — echoes names only, never values).

```bash
# OWNER, on the machine with the LumaLine project linked (NOT the CRM project — see the LumaLine-vs-CRM
# gotcha in memory), with test values from `.env` (STRIPE_*_TEST). Never paste secret values into logs.
supabase secrets set --project-ref prmsonskzrubqsazmpwd \
  STRIPE_SECRET_KEY="sk_test_…" \
  STRIPE_WEBHOOK_SECRET="whsec_test_…" \
  STRIPE_ASSERT_TEST="true"      # re-arms the sk_test_* guard so a live key can't slip back in
```

### 6a. 🔎 Confirm the rollback took

```bash
# Monitor should stay green on the restored keys; a real charge attempt must now refuse a live key.
node scripts/ops/sql.mjs "select public.monitor_status()"          # no new open critical alerts
# then hit the billing/stripe-connect fns' /account or /run health path with an admin JWT and confirm
# STRIPE_ASSERT_TEST rejects non-sk_test_* (the inline `STRIPE_ASSERT_TEST==='true' && !key.startsWith('sk_test_')`
# guard in getStripe(), supabase/functions/billing/index.ts).
```

Re-doing the live swap later = re-run Phase B1 with the live values and `STRIPE_ASSERT_TEST` unset/false.

---

## 7. Backups / recovery / GDPR deletion — cross-link

- **PITR / restore drill:** `docs/ops/backup-recovery.md`.
- **GDPR erasure:** `public.gdpr_delete_publisher(p_publisher_id uuid)` (🔐 admin) — right-to-erasure
  for a publisher. Verify the ledger still balances afterward with §3a (the audit is state-invariant).

---

## Trust invariants (bind every step here)

Official `statusLine` only · signed content only · honest billing (full dwell, never idle, 72h clawback
before pay) · **data-minimization** (no raw cost/token deltas ever leave the device) · reversible ·
zero runtime deps. A runbook step that would violate one of these is wrong — stop and escalate.
