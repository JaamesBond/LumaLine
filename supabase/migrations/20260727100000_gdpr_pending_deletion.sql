-- lumaline GDPR Phase 3 — the pending-deletion state machine.
--
-- A deletion request that cannot complete immediately must SCHEDULE ITSELF, not dead-end.
-- Today public.gdpr_self_delete() and public.advertiser_gdpr_self_delete() return
-- {ok:false, reason} when money is in flight and arrange NOTHING: the data subject has to come
-- back and retry by hand while the Art. 12(3) one-month response clock runs against us. A refusal
-- is not an answer to an erasure request; it is a deferral we never recorded.
--
-- WHAT THIS ADDS
--   1. A `deletion_requested_at` watermark on BOTH roles, mirroring the existing `deleted_at`
--      idiom. Set when a request could not complete; NULL once erased or cancelled.
--   2. The request path becomes ERASE-OR-ENTER-PENDING. The GATE ITSELF IS UNCHANGED — what
--      changes is what happens when it refuses.
--   3. A FREEZE, so a pending account does nothing new while it waits.
--   4. app.gdpr_complete_pending() — an hourly cron that re-runs the same gate and completes the
--      ones that now pass, delegating to the UNCHANGED erasure bodies. No fork, ever: two copies
--      of an erasure body is how the ledger/refusal invariants drift apart.
--   5. A 25-day alert, so the Art. 12(3) one-month deadline surfaces BEFORE it is missed.
--   6. Cancel, available right up until erasure fires.
--
-- WHY A FREEZE AT ALL. Between "I asked to be erased" and "the blocker cleared" the account is in
-- a state the user has already repudiated. Letting it keep serving, spending or minting sessions
-- in that window would mean honouring the request in name only.
--
-- HOW THIS SITS AGAINST WHAT ALREADY SHIPPED (Phases 1-2 + the erased-surface audit):
--   * Phase 2 (20260726100000) REMOVED the advertiser idle-balance gate, so an advertiser now
--     enters pending only for in-flight TRANSACTIONS (topup_pending / charge_pending /
--     uncharged_postpay_billings), which self-resolve in days. `spend_down` is therefore the
--     PRINCIPAL DELIBERATE use of the pending state, not an edge case.
--   * Erasure is now TERMINAL (20260726110000 + 20260726120000): window_open carries
--     `a.deleted_at is null` and nine self-serve RPCs refuse an erased org. The freeze never
--     fights those gates — it operates strictly BEFORE deleted_at is set, so the two never
--     overlap.
--   * `deletion_disposition` already exists with CHECK (dormant|writeoff). Phase 2 deliberately
--     WITHHELD 'spend_down' until the cron that honours it existed. That cron is this migration.

-- ===========================================================================
-- 1. The watermark columns + the spend_down disposition.
-- ===========================================================================

alter table public.publishers  add column if not exists deletion_requested_at timestamptz;
alter table public.advertisers add column if not exists deletion_requested_at timestamptz;

comment on column public.publishers.deletion_requested_at is
  'Set when a self-serve erasure could not complete immediately (money in flight). An hourly cron '
  're-runs the gate and completes it. NULL once erased or cancelled. Not a protected column.';
comment on column public.advertisers.deletion_requested_at is
  'Set when a self-serve erasure could not complete immediately, or when the advertiser elected '
  'spend_down. An hourly cron completes it. NULL once erased or cancelled.';

-- Neither column is guarded by app.advertisers_protect_cols: its EFFECTIVE definition
-- (20260722200000 §2, which superseded 20260716150000 §8) guards only is_house / status /
-- stripe_customer_id / billing_mode / dispute_hold_at. publishers carries no protect trigger at
-- all. Verified against the live catalog, not from memory — the request/cancel RPCs run as
-- `authenticated` and would raise 42501 here if either column were protected.

-- spend_down joins the disposition set now that app.gdpr_complete_pending() (below) exists to
-- honour it. Phase 2 deliberately withheld it: accepting a value nothing acted on would have been
-- a silent broken promise about a user's money. Extending a CHECK requires drop + recreate —
-- there is no ALTER CONSTRAINT for a CHECK expression. The name below is the one Postgres actually
-- assigned to 20260726100000's inline constraint (confirmed from pg_constraint, not guessed).
alter table public.advertisers drop constraint if exists advertisers_deletion_disposition_check;
alter table public.advertisers add constraint advertisers_deletion_disposition_check
  check (deletion_disposition in ('dormant', 'writeoff', 'spend_down'));

comment on column public.advertisers.deletion_disposition is
  'What is to become of a residual prepaid balance at GDPR erasure: dormant (left on the books as '
  'an unspent, unrecognized liability — the default), writeoff (deliberately zeroed by the '
  'advertiser via advertiser_writeoff_credit()), or spend_down (Phase 3: erasure is DEFERRED until '
  'the credit is exhausted, completed by app.gdpr_complete_pending()). NULL when no erasure has '
  'been requested.';

-- The cron scans exactly this predicate on both tables. Partial, so the index holds only the rows
-- actually pending — normally a handful — and costs nothing once they drain. Both tables are small
-- enough that a plain (non-CONCURRENT) build is a sub-second exclusive lock at deploy time.
create index if not exists publishers_pending_deletion_idx
  on public.publishers (deletion_requested_at)
  where deletion_requested_at is not null and deleted_at is null;

create index if not exists advertisers_pending_deletion_idx
  on public.advertisers (deletion_requested_at)
  where deletion_requested_at is not null and deleted_at is null;
