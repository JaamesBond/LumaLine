-- lumaline Phase 1 schema — transparency views.
-- All use security_invoker=on so the *querying* user's RLS applies: a publisher
-- sees only their own rows, an admin sees everything, through the same view.

-- ---------------------------------------------------------------------------
-- v_publisher_balance — cleared earnings, paid, reversed, and net payable.
-- Ledger-derived (the single source of truth). Because publisher_earnings legs
-- are stored negative, magnitudes are negated. Once Phase 5 books payout debits
-- as positive cleared publisher_earnings legs, paid_micros captures them and
-- balance_micros nets out automatically (no double counting).
-- ---------------------------------------------------------------------------
create view public.v_publisher_balance
with (security_invoker = on) as
select
  p.id as publisher_id,
  coalesce(-sum(le.amount_micros) filter (where le.state = 'cleared' and le.amount_micros < 0), 0) as earned_micros,
  coalesce( sum(le.amount_micros) filter (where le.state = 'cleared' and le.amount_micros > 0), 0) as paid_micros,
  coalesce(-sum(le.amount_micros) filter (where le.state = 'reversed'), 0)                          as reversed_micros,
  coalesce(-sum(le.amount_micros) filter (where le.state = 'cleared'), 0)                           as balance_micros
from public.publishers p
left join public.ledger_entries le
  on le.publisher_id = p.id
 and le.account = 'publisher_earnings'
group by p.id;

comment on view public.v_publisher_balance is
  'Per-publisher cleared earnings / paid / reversed / net payable, derived from the ledger. RLS-scoped.';

grant select on public.v_publisher_balance to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- v_publisher_window_clearing — per-window gross transparency (what each
-- watched window cleared at), with any click gross for the same window.
-- ---------------------------------------------------------------------------
create view public.v_publisher_window_clearing
with (security_invoker = on) as
select
  i.window_id,
  i.publisher_id,
  i.line_item_id,
  i.creative_id,
  i.attention_seconds,
  i.multiplier,
  i.gross_micros                       as impression_gross_micros,
  coalesce(c.click_gross_micros, 0)    as click_gross_micros,
  i.state,
  i.created_at
from public.impressions i
left join (
  select window_id, sum(gross_micros) as click_gross_micros
  from public.clicks
  group by window_id
) c on c.window_id = i.window_id;

comment on view public.v_publisher_window_clearing is
  'Per-window clearing price (impression + click gross). RLS-scoped to the publisher''s own windows.';

grant select on public.v_publisher_window_clearing to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- v_campaign_delivery — per line-item delivery (admin-facing). Aggregates
-- impressions and clicks separately to avoid a cartesian blow-up. Campaigns /
-- line_items are admin-only via RLS, so non-admins see no rows here.
-- ---------------------------------------------------------------------------
create view public.v_campaign_delivery
with (security_invoker = on) as
with imp as (
  select line_item_id,
         count(*)               as impressions_count,
         sum(attention_seconds) as attention_seconds,
         sum(gross_micros)      as impression_gross_micros
  from public.impressions
  group by line_item_id
),
clk as (
  select line_item_id,
         count(*)          as clicks_count,
         sum(gross_micros) as click_gross_micros
  from public.clicks
  group by line_item_id
)
select
  c.id            as campaign_id,
  c.advertiser_id,
  li.id           as line_item_id,
  coalesce(imp.impressions_count, 0)      as impressions_count,
  coalesce(imp.attention_seconds, 0)      as attention_seconds,
  coalesce(imp.impression_gross_micros, 0) as impression_gross_micros,
  coalesce(clk.clicks_count, 0)           as clicks_count,
  coalesce(clk.click_gross_micros, 0)     as click_gross_micros
from public.campaigns c
join public.line_items li on li.campaign_id = c.id
left join imp on imp.line_item_id = li.id
left join clk on clk.line_item_id = li.id;

comment on view public.v_campaign_delivery is
  'Per line-item delivery + spend (admin-facing). RLS on campaigns/line_items restricts to admins.';

grant select on public.v_campaign_delivery to authenticated, service_role;
