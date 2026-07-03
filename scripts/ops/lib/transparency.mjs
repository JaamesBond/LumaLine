// LumaLine public transparency report — PURE aggregation + reconciliation + data-minimization
// guard (M6-T5). No I/O: buildReport() takes already-aggregated, non-identifying rows and returns
// the public report object; reconcile() proves it ties out to the double-entry ledger; assertNonPII()
// is the data-minimization backstop that refuses to emit anything identifying or any raw activity
// delta. transparency-report.mjs is the thin live-DB wrapper; transparency-report.test.mjs tests THIS
// module hermetically (node --test, no network) — same split as the _shared/*-logic.mjs modules.
//
// TRUST INVARIANT (hard): the report is built from aggregate numbers ONLY. It must reconcile to the
// ledger (zero-sum) and must never contain a UUID, ip_hash/asn/device, publisher/advertiser identity,
// a name, an email, a Stripe id, or any cost/token/activity delta. assertNonPII enforces both a
// key whitelist AND a value denylist so an accidental field can never leak.

const ACCRUAL_EVENTS = new Set(['cpva_accrual', 'cpc_accrual']);
const BILLABLE_IMPRESSION_STATES = new Set(['provisional', 'cleared']);

// basis points; null when the denominator is zero (avoid a misleading 0% vs "n/a").
export const bps = (num, den) => (den ? Math.round((Number(num) / Number(den)) * 10000) : null);
// integer-micro average; null when count is zero.
const perUnit = (total, count) => (count ? Math.round(Number(total) / Number(count)) : null);

// Sum signed ledger amounts matching a predicate over the grouped rows.
function ledgerSum(rows, pred) {
  return (rows || []).filter(pred).reduce((a, r) => a + Number(r.amount_micros || 0), 0);
}
function ledgerCount(rows, pred) {
  return (rows || []).filter(pred).reduce((a, r) => a + Number(r.n || 0), 0);
}

/**
 * buildReport(input) -> public report object.
 * input = {
 *   ledger:  [{ account, state, event_type, amount_micros, n }],  // grouped
 *   ledger_global_sum_micros, unbalanced_group_count,
 *   windows: { open, credited, abandoned, void },
 *   impressions: [{ state, n, gross_micros, attention_seconds }],
 *   clicks_credited,
 *   generated_at,   // ISO string (a timestamp, not PII); optional
 * }
 */
export function buildReport(input) {
  const led = input.ledger || [];
  const isAccrual = (r) => ACCRUAL_EVENTS.has(r.event_type);

  // --- money that CLEARED (aged past the 72h clawback and booked to the ledger) ---
  const grossCleared = ledgerSum(led, (r) => r.account === 'advertiser_billing' && r.state === 'cleared' && isAccrual(r));
  // publisher_earnings / platform_revenue accrual legs are stored negative -> negate to magnitude.
  const publisherCleared = -ledgerSum(led, (r) => r.account === 'publisher_earnings' && r.state === 'cleared' && isAccrual(r));
  const platformCleared = -ledgerSum(led, (r) => r.account === 'platform_revenue' && r.state === 'cleared' && isAccrual(r));

  // --- money reversed by clawback (removed from cleared balance) ---
  const grossReversed = ledgerSum(led, (r) => r.account === 'advertiser_billing' && r.state === 'reversed' && isAccrual(r));
  const reversedGroupCount = ledgerCount(led, (r) => r.account === 'advertiser_billing' && r.state === 'reversed' && isAccrual(r));

  // --- delivery (non-money) ---
  // billable_n = impressions with gross>0 (paid). House/no-fill views (gross=0) stay provisional
  // forever and never enter the money ledger, so the MONEY blocks count billable_n while DELIVERY
  // counts every recorded impression (n). Fall back to n when billable_n is absent (test fixtures).
  const imp = Object.fromEntries((input.impressions || []).map((r) => [r.state, r]));
  const billable = (row) => Number(row?.billable_n ?? row?.n ?? 0);
  const clearedViews = billable(imp.cleared);
  const clearedAttention = Number(imp.cleared?.attention_seconds || 0);
  const creditedViews = (input.impressions || [])
    .filter((r) => BILLABLE_IMPRESSION_STATES.has(r.state))
    .reduce((a, r) => a + Number(r.n || 0), 0);
  const provisionalGross = Number(imp.provisional?.gross_micros || 0);
  const provisionalViews = billable(imp.provisional);

  const w = input.windows || {};
  const terminal = Number(w.credited || 0) + Number(w.abandoned || 0) + Number(w.void || 0);

  const report = {
    report: 'lumaline-transparency',
    version: 1,
    generated_at: input.generated_at || null,
    currency: 'EUR',

    cleared: {
      gross_micros: grossCleared,
      publisher_micros: publisherCleared,
      platform_micros: platformCleared,
      publisher_share_bps: bps(publisherCleared, grossCleared),
      view_count: clearedViews,
      attention_seconds: clearedAttention,
      avg_gross_per_view_micros: perUnit(grossCleared, clearedViews),
      avg_gross_per_attention_second_micros: perUnit(grossCleared, clearedAttention),
    },

    provisional: {
      gross_micros: provisionalGross, // accruing, NOT yet cleared, NOT yet billable
      view_count: provisionalViews,
    },

    clawback: {
      reversed_gross_micros: grossReversed,
      reversed_group_count: reversedGroupCount,
      // share of ever-accrued gross that was clawed back
      clawback_rate_bps: bps(grossReversed, grossCleared + grossReversed),
    },

    delivery: {
      windows_open: Number(w.open || 0),
      windows_credited: Number(w.credited || 0),
      windows_abandoned: Number(w.abandoned || 0),
      windows_void: Number(w.void || 0),
      windows_terminal: terminal,
      fill_rate_bps: bps(Number(w.credited || 0), terminal),
      credited_views: creditedViews,
      clicks_credited: Number(input.clicks_credited || 0),
    },

    reconciliation: {
      ledger_global_sum_micros: Number(input.ledger_global_sum_micros || 0),
      unbalanced_group_count: Number(input.unbalanced_group_count || 0),
      zero_sum_ok: false,
      accrual_identity_ok: false,
      publisher_split_ok: false,
      all_ok: false,
    },
  };

  // reconcile mutates report.reconciliation in place and returns the same report.
  return reconcile(report);
}

/**
 * reconcile(report) -> report, with reconciliation.* filled from the report's own figures.
 *   zero_sum_ok        : the whole ledger sums to 0 and no group is unbalanced (THE invariant).
 *   accrual_identity_ok: cleared gross == publisher + platform (each accrual group is +G,-0.6G,-0.4G).
 *   publisher_split_ok : the split is publisher-favored (>=50%) and near the documented 60%.
 */
export function reconcile(report) {
  const r = report.reconciliation;
  const c = report.cleared;

  r.zero_sum_ok = r.ledger_global_sum_micros === 0 && r.unbalanced_group_count === 0;
  r.accrual_identity_ok = c.gross_micros === c.publisher_micros + c.platform_micros;
  r.publisher_split_ok =
    c.gross_micros === 0 ||
    (c.publisher_micros >= c.platform_micros &&
      c.publisher_share_bps !== null &&
      c.publisher_share_bps >= 5000 &&
      c.publisher_share_bps <= 7000);
  r.all_ok = r.zero_sum_ok && r.accrual_identity_ok && r.publisher_split_ok;
  return report;
}

// --- data-minimization guard --------------------------------------------------------------------
// Every key the public report is allowed to contain. Any other key -> throw (defense against an
// accidental identifying field being added later).
const ALLOWED_KEYS = new Set([
  'report', 'version', 'generated_at', 'currency',
  'cleared', 'provisional', 'clawback', 'delivery', 'reconciliation',
  'gross_micros', 'publisher_micros', 'platform_micros', 'publisher_share_bps',
  'view_count', 'attention_seconds', 'avg_gross_per_view_micros', 'avg_gross_per_attention_second_micros',
  'reversed_gross_micros', 'reversed_group_count', 'clawback_rate_bps',
  'windows_open', 'windows_credited', 'windows_abandoned', 'windows_void', 'windows_terminal',
  'fill_rate_bps', 'credited_views', 'clicks_credited',
  'ledger_global_sum_micros', 'unbalanced_group_count',
  'zero_sum_ok', 'accrual_identity_ok', 'publisher_split_ok', 'all_ok',
]);

// Substrings that must never appear anywhere in the serialized report (keys OR values). Identity,
// contact, payment-processor ids, and — the hard data-minimization line — anything cost/token/activity.
const PII_SUBSTRINGS = [
  'ip_hash', 'asn', 'device', 'publisher_id', 'advertiser_id', 'campaign_id', 'line_item',
  'creative', 'window_id', 'impression_id', 'click_token', 'nonce', 'challenge', 'prev_hash',
  'stripe', 'email', '@', 'cost', 'token', 'activity',
];
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
const IPV4_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;

function walkKeys(obj, path, out) {
  if (obj === null || typeof obj !== 'object') return;
  for (const k of Object.keys(obj)) {
    if (!ALLOWED_KEYS.has(k)) out.push(`${path}${k}`);
    walkKeys(obj[k], `${path}${k}.`, out);
  }
}

/**
 * assertNonPII(report) -> report. Throws if the report contains a non-whitelisted key, a UUID, an
 * IPv4, or any PII/cost/token/activity substring. This is the data-minimization invariant, asserted
 * on the actual bytes that would be published — not a promise about how the report was built.
 */
export function assertNonPII(report) {
  const badKeys = [];
  walkKeys(report, '', badKeys);
  if (badKeys.length) throw new Error(`transparency: non-whitelisted key(s): ${badKeys.join(', ')}`);

  const serialized = JSON.stringify(report).toLowerCase();
  if (UUID_RE.test(serialized)) throw new Error('transparency: output contains a UUID');
  if (IPV4_RE.test(serialized)) throw new Error('transparency: output contains an IPv4 address');
  for (const s of PII_SUBSTRINGS) {
    if (serialized.includes(s)) throw new Error(`transparency: output contains banned substring "${s}"`);
  }
  return report;
}

// Human-readable Markdown for docs/ publication. Pure string, no I/O.
export function toMarkdown(report) {
  const c = report.cleared, p = report.provisional, cb = report.clawback, d = report.delivery, rc = report.reconciliation;
  const eur = (m) => (m == null ? 'n/a' : '€' + (Number(m) / 1_000_000).toFixed(4));
  const pctOf = (b) => (b == null ? 'n/a' : (b / 100).toFixed(2) + '%');
  return `# LumaLine transparency report

_Generated ${report.generated_at || '(unstamped)'} · currency ${report.currency} · schema v${report.version}_

Aggregate, non-identifying figures that reconcile to LumaLine's double-entry ledger. No per-publisher,
per-advertiser, or per-device data appears here, and no raw cost/token/activity signal ever leaves a
device — the report is built from cleared ledger totals and coarse delivery counts only.

## Cleared money (passed the 72h clawback window, booked to the ledger)

| Metric | Value |
|---|---|
| Advertiser gross cleared | ${eur(c.gross_micros)} |
| Publisher share | ${eur(c.publisher_micros)} (${pctOf(c.publisher_share_bps)}) |
| Platform share | ${eur(c.platform_micros)} |
| Cleared views | ${c.view_count} |
| Cleared attention-seconds | ${c.attention_seconds} |
| Avg clearing price / view | ${eur(c.avg_gross_per_view_micros)} |
| Avg clearing price / attention-second | ${eur(c.avg_gross_per_attention_second_micros)} |

## Provisional (accruing — not yet cleared, not yet billable)

| Metric | Value |
|---|---|
| Provisional gross | ${eur(p.gross_micros)} |
| Provisional views | ${p.view_count} |

## Clawback

| Metric | Value |
|---|---|
| Reversed gross | ${eur(cb.reversed_gross_micros)} |
| Reversed groups | ${cb.reversed_group_count} |
| Clawback rate | ${pctOf(cb.clawback_rate_bps)} |

## Delivery

| Metric | Value |
|---|---|
| Fill rate (credited / terminal windows) | ${pctOf(d.fill_rate_bps)} |
| Credited views | ${d.credited_views} |
| Windows: open / credited / abandoned / void | ${d.windows_open} / ${d.windows_credited} / ${d.windows_abandoned} / ${d.windows_void} |
| Credited clicks | ${d.clicks_credited} |

## Reconciliation to the ledger

| Check | Result |
|---|---|
| Ledger zero-sum (global=0, 0 unbalanced groups) | ${rc.zero_sum_ok ? '✓' : '✗'} |
| Accrual identity (gross = publisher + platform) | ${rc.accrual_identity_ok ? '✓' : '✗'} |
| Publisher-favored split (~60%) | ${rc.publisher_split_ok ? '✓' : '✗'} |
| **All checks pass** | ${rc.all_ok ? '✓' : '✗'} |
`;
}
