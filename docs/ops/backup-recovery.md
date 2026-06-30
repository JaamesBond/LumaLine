# LumaLine Backup, Recovery & GDPR Deletion

**Status:** M3-T5. Procedure + local restore drill are **done and validated by cc**. The
**production PITR restore drill on `prmsonskzrubqsazmpwd` is OWNER-GATED** (requires a paid
Supabase plan with PITR; see "Owner gate" below). This document does **not** claim the
production money-safety recovery gate is closed — only that the procedure works and was
exercised locally.

The financial ledger (`ledger_entries`, `impressions`, `payouts`, `advertiser_charges`) is the
asset that matters here: real funds depend on it. Recovery and deletion must both preserve its
**zero-sum integrity** (every `entry_group_id` sums to 0).

---

## 1. Backup layers

| Layer | What it protects | Cadence / retention | Status |
|---|---|---|---|
| **Migrations-as-code** (`supabase/migrations/`) | Full schema (tables, RPCs, RLS, grants, cron) | Every change; in git | ✅ Proven: a fresh `supabase db reset` reproduces the live object set with zero drift (M0 exit). |
| **Supabase managed backups** | Full database (data) | Free tier: daily logical snapshot, limited retention. **Pro tier: PITR (WAL), ~2-min RPO.** | ⚠️ Project is on the lower tier → **no PITR today**. Owner gate below. |
| **On-demand logical dump** (`pg_dump -Fc`) | Full data, portable | Manual / scriptable; before risky migrations | ✅ Procedure validated locally (below). |

**RPO/RTO targets (for the money path):**

- **RPO target: ≤ 5 minutes.** Achievable only with **PITR** (Pro plan). On the current tier the
  effective RPO is "since the last daily snapshot" — **not acceptable for live money** → this is
  why PITR is a hard owner gate before M5 go-live.
- **RTO target: ≤ 1 hour** to restore the ledger into a usable state and reconcile.

---

## 2. Restore procedure (validated)

The same procedure runs against a local stack (drill) or production (real incident). For
production, prefer **PITR restore to a timestamp** once the plan supports it; the logical-dump
path below is the portable fallback and the procedure used for the drill.

```bash
# 0. Identify the recovery point. PITR: pick a timestamp just before the incident.
#    Logical: use the most recent pg_dump artifact.

# 1. Capture a logical backup (or use the managed/PITR snapshot).
pg_dump "$DB_URL" -Fc -f ledger_backup.dump          # full DB; or -n public -n app for ledger-only

# 2. Restore into an ISOLATED scratch target first (never straight over production).
createdb lumaline_restore_drill
pg_restore -d "$SCRATCH_URL" --no-owner --no-privileges ledger_backup.dump

# 3. Verify ledger integrity on the restored copy BEFORE any cutover:
#    - row counts match the source
#    - EVERY entry_group_id sums to 0 (zero-sum invariant intact)
psql "$SCRATCH_URL" -tAc "
  select count(*) from (
    select entry_group_id from public.ledger_entries
    group by 1 having sum(amount_micros) <> 0
  ) imbalanced;"      -- MUST be 0

# 4. Reconcile against Stripe (charges + transfers) for the recovery window
#    using the billing/payout reconciliation routines before resuming money movement.

# 5. Only then promote the restore (or replay missing migrations onto it).
```

### Local drill result (2026-06-29, cc)

Exercised steps 1–3 against the local stack with seeded balanced ledger groups:

| Metric | Value |
|---|---|
| Backup scope | `public` + `app` schemas, `pg_dump -Fc` |
| Dump size | 192 KB |
| Dump time | **133 ms** |
| Restore time | **479 ms** |
| Round-trip | rows + `sum(amount_micros)` identical source↔restore |
| Zero-sum post-restore | **0 imbalanced groups** ✅ |

(The drill dumped a schema subset, so cross-schema `auth` references — the `auth.users` FK and
`auth.uid()` in RLS policies — were "ignored on restore"; a full-database restore in a real
incident includes the `auth` schema and does not hit these. The financial **data** round-tripped
exactly.)

---

## 3. GDPR deletion (right to erasure)

`public.gdpr_delete_publisher(p_publisher_id uuid)` (migration `20260629090000_gdpr_deletion.sql`)
is the erasure workflow. Admin-gated (`app.is_admin()`), idempotent, and **refuses while a payout
is in flight** (`status in ('pending','in_transit')`).

**Removed / scrubbed (PII):** `publishers.handle` → `deleted-<id8>`; `country`, `stripe_account_id`
→ null; `devices` + `device_auth_codes` deleted; `disputes.description` → `[redacted: account
deleted]` (row kept for audit); `auth.users` email/phone/metadata tombstoned + sessions/identities
revoked.

**Preserved (financial integrity):** `impressions`, `ledger_entries`, `payouts` are **never
deleted**. The `publishers` row is **anonymized in place** (not deleted) so it remains the opaque
anchor for those records — deleting it would cascade-destroy the ledger (publishers.auth_user_id is
`on delete cascade`, and the financial tables FK `publishers(id)`).

Verified by `test/gdpr-deletion.integration.mjs` (T47–T52): after deletion, PII is gone, devices
are removed, and the publisher's ledger group is **byte-identical and still zero-sum balanced**.

This satisfies the data-minimization invariant and the Privacy Policy's deletion right while
honoring the lawful-retention carve-out for accounting records.

---

## 4. Owner gate (before M5 go-live)

cc cannot do these; they are required before real money flows:

1. **Confirm/upgrade the Supabase plan to one with PITR** on `prmsonskzrubqsazmpwd` and confirm the
   retention window. Without PITR the RPO target above is not met.
2. **Run a production restore drill** (PITR restore to a timestamp into a scratch project),
   recording the real production RTO/RPO. The local drill validates the *procedure*, not the
   production *capability*.
3. **Schedule periodic drills** (e.g. quarterly) and record results here.
