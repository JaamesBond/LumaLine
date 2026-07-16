-- lumaline M9-T2 — advertiser prepay ledger accounts (additive enum + per-advertiser dimension).
--
-- Prepay funding rides the EXISTING zero-sum double-entry book (ledger_and_payouts.sql:1-65)
-- rather than a parallel money store. To do that the ledger_account enum (enums.sql:34-39)
-- gains two accounts and ledger_entries gains a nullable per-advertiser dimension:
--
--   * advertiser_funds    — held-deposit LIABILITY. Carried as NEGATIVE legs, exactly like
--                           publisher_earnings (enums.sql:36): a credited deposit is money the
--                           platform owes back as ad delivery, drawn down as spend settles.
--   * advertiser_bad_debt — platform chargeback LOSS. A POSITIVE/debit leg booked when a
--                           disputed deposit is reversed for more than the remaining balance
--                           (spend already delivered): the shortfall is written off, never
--                           clawed from already-paid publishers.
--
-- Deposit cash-in continues to move through platform_cash (enums.sql:38). The full accounting,
-- all zero-sum, riding the deferred ledger_group_balances constraint trigger unchanged
-- (ledger_and_payouts.sql:36-65):
--
--   deposit    (amount D):  Dr platform_cash      +D
--                           Cr advertiser_funds    −D
--   draw-down  (spend  G):  Dr advertiser_funds    +G      -- releases the held liability
--                           Cr advertiser_billing  −G      -- nets the receivable app.accrue
--                                                          --   books at clearing_and_ledger.sql:59
--   chargeback (reversal R, balance B):
--                           Cr platform_cash       −R      -- bank reclaims the deposit cash
--                           Dr advertiser_funds    +min(R,B)   -- unwind still-held liability
--                           Dr advertiser_bad_debt +max(0,R−B) -- write off the over-spent gap
--
-- STANDALONE MIGRATION: Postgres forbids USING a freshly ADD'd enum value in the same
-- transaction that added it. Nothing here references the new literals (DDL only), and every
-- later migration (170000 prepay primitives, 180000 serving reserve) lives in its own file, so
-- the literals are committed-and-usable by the time any function names them. Do not fold enum
-- additions and the functions that emit those legs into one migration.

alter type public.ledger_account add value if not exists 'advertiser_funds';
alter type public.ledger_account add value if not exists 'advertiser_bad_debt';

-- Per-advertiser dimension on the ledger. Nullable: legacy publisher_earnings / platform_*
-- legs leave it NULL; advertiser_funds / advertiser_bad_debt / the netting advertiser_billing
-- legs carry it. Default NO ACTION on delete (no ON DELETE clause, matching spec) preserves
-- financial history — an advertiser with ledger legs cannot be hard-deleted out from under them.
alter table public.ledger_entries
  add column if not exists advertiser_id uuid references public.advertisers (id);

comment on column public.ledger_entries.advertiser_id is
  'Per-advertiser dimension for prepay legs (advertiser_funds / advertiser_bad_debt / the netting advertiser_billing draw-down leg). NULL on publisher_earnings / platform_* legs. Widens NO row visibility: ledger_entries RLS (ledger_and_payouts.sql:70-83) exposes only a publisher''s own publisher_earnings legs plus admin; no advertiser policy references this column.';

create index if not exists ledger_entries_advertiser_idx
  on public.ledger_entries (advertiser_id, account, state)
  where advertiser_id is not null;
