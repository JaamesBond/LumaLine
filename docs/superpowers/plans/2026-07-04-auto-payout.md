# M5-T4 Auto-Payout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publishers self-onboard their bank (`lumaline connect`) and get paid automatically every week, with branded email notifications — no owner in the loop.

**Architecture:** Reuse the proven `stripe-connect` payout core (reserve→transfer→confirm, double-pay-safe) untouched. Add a pg_cron trigger (twin of the live `app.run_monitor()`), a cron-secret auth path on `/payout/batch`, an env-tunable €1 minimum, a `lumaline connect` client command over the existing hosted onboarding, and best-effort branded Resend emails that can never block a payout.

**Tech Stack:** Node ≥18 ESM zero-dep client (`src/`, `bin/`); Deno + TypeScript edge fn (`supabase/functions/stripe-connect`); shared pure `.mjs` (`supabase/functions/_shared/`) importable by both Deno and `node --test`; Postgres migrations (pg_cron + pg_net + Vault); Resend HTTP API.

## Global Constraints

- Client is **zero runtime deps**, `node:` built-ins only, Node ≥ 18, ESM `.mjs`. No build step.
- Money-safety invariants are **non-negotiable**: no double-pay, house never charged, idempotent re-runs. The transfer/confirm/reconcile core in `stripe-connect/index.ts` is **NOT modified** except to add auth + min-arg + post-loop emails.
- Emails are **best-effort**: every send is wrapped so a failure logs and continues — it must never block, reverse, or fail a payout.
- Prod project ref is **`prmsonskzrubqsazmpwd`** (never the CRM `kvlfpwzmjxuapjheknnj`). All remote writes ref-guarded + owner-gated.
- Payout minimum = **€1** via `LUMALINE_PAYOUT_MIN_MICROS` (default `1000000`).
- Cron cadence = **weekly, Monday 09:00 UTC** (`0 9 * * 1`), scheduled by the controller at deploy (NOT in the migration), mirroring the monitor.
- Cron auth = header **`x-lumaline-cron-secret`** constant-time-compared to fn env `LUMALINE_CRON_SECRET` (= Vault `lumaline_cron_secret`).
- Email `from` = env `LUMALINE_EMAIL_FROM` default `"LumaLine <payouts@send.lumaline.dev>"`; pure HTML, all CSS inline, **no external asset fetches**, plain-text fallback on every email; green brand accent `#16A34A`.
- Pure logic (email builders, constant-time compare, min parse) lives in `_shared/*.mjs` and is unit-tested by `node --test`; the Deno fn imports it. Integration tests self-skip when the local stack is down.

---

### Task 1: `lumaline connect` client command + config + copy fixes

**Files:**
- Modify: `src/config.mjs` (add `STRIPE_CONNECT_BASE` near `AUTH_BASE`, ~line 59)
- Modify: `src/client/auth.mjs` (add `connect()`; fix stale payout copy in `login`+`earnings`)
- Modify: `bin/lumaline.mjs` (add `case 'connect'`, ~line 41; add help line, ~line 113)
- Test: `test/client-connect.test.mjs` (create)

**Interfaces:**
- Consumes: `getValidAccessToken({file, authBase, fetchImpl, now, timeoutMs})` → token string | null; `postJson(fetchImpl, url, body, {timeoutMs, bearer})` → `{ok, status, data}`; `out(...)` console writer — all already in `src/client/auth.mjs`.
- Produces: `connect({connectBase?, fetchImpl?, now?, timeoutMs?, out?}) : Promise<void>`; `STRIPE_CONNECT_BASE: string`.

- [ ] **Step 1: Write the failing test**

```javascript
// test/client-connect.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { connect } from '../src/client/auth.mjs';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function tokenFile() {
  const d = mkdtempSync(join(tmpdir(), 'lumaline-connect-'));
  const f = join(d, 'device-token.json');
  writeFileSync(f, JSON.stringify({
    access_token: 'hdr.' + Buffer.from(JSON.stringify({ exp: Math.floor(Date.now()/1000)+3600 })).toString('base64url') + '.sig',
    refresh_token: 'r', publisher_id: 'p1', device_id: 'd1',
  }));
  return f;
}

test('connect: already onboarded → prints connected, does NOT call onboard', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return { ok: true, status: 200, json: async () => ({ ok: true, onboarded: true, payout_status: 'eligible' }) };
  };
  const lines = [];
  await connect({ file: tokenFile(), connectBase: 'https://x/stripe-connect', fetchImpl, out: (s) => lines.push(s) });
  assert.ok(calls.some((u) => u.endsWith('/connect/status')), 'checks status');
  assert.ok(!calls.some((u) => u.endsWith('/connect/onboard')), 'must NOT onboard when already onboarded');
  assert.match(lines.join('\n'), /connected|active/i);
});

test('connect: not onboarded → posts onboard, prints the onboarding_url', async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith('/connect/status')) return { ok: true, status: 200, json: async () => ({ ok: true, onboarded: false, payout_status: 'pending' }) };
    return { ok: true, status: 200, json: async () => ({ ok: true, account_id: 'acct_1', onboarding_url: 'https://connect.stripe.com/setup/abc' }) };
  };
  const lines = [];
  await connect({ file: tokenFile(), connectBase: 'https://x/stripe-connect', fetchImpl, out: (s) => lines.push(s) });
  assert.match(lines.join('\n'), /connect\.stripe\.com\/setup\/abc/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/client-connect.test.mjs`
Expected: FAIL — `connect` is not exported from `src/client/auth.mjs`.

- [ ] **Step 3: Add `STRIPE_CONNECT_BASE` to `src/config.mjs`**

Insert immediately after the `AUTH_BASE` export (~line 59):

```javascript
// Stripe Connect (publisher payout onboarding + status). Same branded host as AUTH_BASE — the
// Cloudflare proxy forwards feed.lumaline.dev/<fn>/... to /functions/v1/<fn>/... for any fn.
export const STRIPE_CONNECT_BASE = env.LUMALINE_CONNECT || FEED_BASE.replace(/\/lumaline-feed\/?$/, '/stripe-connect');
```

- [ ] **Step 4: Add `connect()` to `src/client/auth.mjs`**

Add after `earnings()` (mirrors its shape). If `out` is not already a module-level helper, pass it in (default `console.log`):

```javascript
// --- connect (self-serve bank onboarding) ----------------------------------------------
export async function connect({
  file = DEVICE_TOKEN, connectBase = STRIPE_CONNECT_BASE, fetchImpl = fetch,
  now = Date.now, timeoutMs = FETCH_TIMEOUT_MS, out = console.log,
} = {}) {
  const token = await getValidAccessToken({ file, authBase: AUTH_BASE, fetchImpl, now, timeoutMs });
  if (!token) { out('Not logged in. Run `lumaline login` first.'); return; }

  const st = await postJsonGet(fetchImpl, `${connectBase}/connect/status`, { bearer: token, timeoutMs });
  if (st.ok && st.data?.onboarded) {
    out(`✓ Bank connected — weekly payouts active (status: ${st.data.payout_status ?? 'ok'}, €1 minimum).`);
    return;
  }
  const res = await postJson(fetchImpl, `${connectBase}/connect/onboard`, {}, { bearer: token, timeoutMs });
  if (res.status === 422) { out(`Payouts aren't supported in your region yet${res.data?.error ? ': ' + res.data.error : ''}.`); return; }
  if (!res.ok || !res.data?.onboarding_url) { out(`Could not start onboarding (HTTP ${res.status}${res.data?.error ? ': ' + res.data.error : ''}).`); return; }
  out('Connect your bank to receive payouts — open this secure Stripe page:');
  out(`  ${res.data.onboarding_url}`);
  out('  (You enter your IBAN on Stripe; LumaLine never sees it. Re-run `lumaline connect` to check status.)');
}
```

`/connect/status` is a GET; add a tiny GET-with-bearer helper next to `postJson`:

```javascript
async function postJsonGet(fetchImpl, url, { timeoutMs = FETCH_TIMEOUT_MS, bearer } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { method: 'GET', headers: bearer ? { authorization: `Bearer ${bearer}` } : {}, signal: ctrl.signal });
    let data = null; try { data = await res.json(); } catch { /* empty */ }
    return { ok: res.ok, status: res.status, data };
  } catch { return { ok: false, status: 0, data: null }; }
  finally { clearTimeout(t); }
}
```

Ensure `STRIPE_CONNECT_BASE` and `AUTH_BASE` are imported from `../config.mjs` at the top of `auth.mjs`.

- [ ] **Step 5: Fix the stale go-live copy**

In `src/client/auth.mjs`, `login()` line ~211, replace:
`out('    (Payouts begin only at the production go-live; until then balances are informational.)');`
with:
`out('    (Run `lumaline connect` to receive weekly automatic payouts, €1 minimum.)');`

In `earnings()` line ~255, replace:
`out('  Note: earnings ACCRUE now but real payouts begin only at the production go-live.');`
with:
`out('  Paid out automatically each week once you `lumaline connect` your bank (€1 minimum).');`

- [ ] **Step 6: Wire `bin/lumaline.mjs`**

Add after the `earnings` case (~line 41):

```javascript
    case 'connect':
      await (await import('../src/client/auth.mjs')).connect({});
      break;
```

Add to the `help()` usage block after the `earnings` line (~line 113):
```javascript
  lumaline connect      Connect your bank (Stripe) to receive automatic weekly payouts
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `node --test test/client-connect.test.mjs`
Expected: PASS (2 tests).

- [ ] **Step 8: Commit**

```bash
git add src/config.mjs src/client/auth.mjs bin/lumaline.mjs test/client-connect.test.mjs
git commit -m "feat(client): lumaline connect — self-serve bank onboarding + refresh payout copy"
```

---

### Task 2: Branded HTML email builders + Resend sender (`_shared/email.mjs`)

**Files:**
- Create: `supabase/functions/_shared/email.mjs`
- Test: `test/email-builders.test.mjs` (create)

**Interfaces:**
- Produces:
  - `paidEmail({handle, amountEur}) : {subject, html, text}`
  - `connectNudgeEmail({handle, amountEur}) : {subject, html, text}`
  - `sendEmail({to, subject, html, text, apiKey, from, fetchImpl?}) : Promise<'sent'|`failed:${string}`>`

- [ ] **Step 1: Write the failing test**

```javascript
// test/email-builders.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { paidEmail, connectNudgeEmail, sendEmail } from '../supabase/functions/_shared/email.mjs';

const noExternal = (html) => assert.ok(!/https?:\/\/(?!c\.lumaline|feed\.lumaline)/i.test(html.replace(/mailto:[^"'\s]+/g,'')) || !/<img|src=/.test(html), 'no external image/src');

test('paidEmail: subject + amount + plaintext fallback, no external images', () => {
  const e = paidEmail({ handle: 'degen', amountEur: '1.10' });
  assert.match(e.subject, /paid|payout/i);
  assert.match(e.html, /1\.10/);
  assert.match(e.html, /degen/);
  assert.ok(e.text && e.text.includes('1.10'), 'plaintext fallback present with amount');
  assert.ok(!/<img/i.test(e.html), 'no external images');
});

test('connectNudgeEmail: has a CTA mentioning lumaline connect + amount + plaintext', () => {
  const e = connectNudgeEmail({ handle: 'pat', amountEur: '3.00' });
  assert.match(e.subject, /waiting|connect/i);
  assert.match(e.html, /lumaline connect/);
  assert.match(e.html, /3\.00/);
  assert.ok(e.text.includes('lumaline connect'));
});

test('escapes handle to prevent HTML injection', () => {
  const e = paidEmail({ handle: '<script>x</script>', amountEur: '1.00' });
  assert.ok(!e.html.includes('<script>x</script>'), 'handle is escaped');
});

test('sendEmail: posts to Resend with from/to/subject; returns sent on 200', async () => {
  let body = null;
  const fetchImpl = async (url, opts) => { body = JSON.parse(opts.body); return { ok: true, status: 200 }; };
  const r = await sendEmail({ to: 'a@b.c', subject: 's', html: '<b>h</b>', text: 't', apiKey: 'k', from: 'LumaLine <x@y.z>', fetchImpl });
  assert.equal(r, 'sent');
  assert.equal(body.from, 'LumaLine <x@y.z>');
  assert.deepEqual(body.to, ['a@b.c']);
  assert.equal(body.html, '<b>h</b>');
});

test('sendEmail: missing apiKey/to → failed:not_configured, no throw', async () => {
  const r = await sendEmail({ to: '', subject: 's', html: 'h', text: 't', apiKey: '', from: 'f' });
  assert.equal(r, 'failed:not_configured');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/email-builders.test.mjs`
Expected: FAIL — module `_shared/email.mjs` not found.

- [ ] **Step 3: Create `supabase/functions/_shared/email.mjs`**

```javascript
// Branded, self-contained payout emails + a best-effort Resend sender. Zero deps; importable by
// the Deno edge fn and `node --test`. NO external asset fetches (all inline), plain-text fallback.
const GREEN = "#16A34A";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function shell(innerHtml) {
  return `<!doctype html><html><body style="margin:0;background:#0b0f0a;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0b0f0a;padding:32px 0;"><tr><td align="center">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#111813;border:1px solid #1e2a20;border-radius:14px;overflow:hidden;">
<tr><td style="padding:24px 28px 8px;">
<span style="font-size:20px;font-weight:700;color:#e8f5e9;letter-spacing:.3px;">Luma<span style="color:${GREEN};">Line</span></span>
</td></tr>
${innerHtml}
<tr><td style="padding:18px 28px 26px;color:#5c6b60;font-size:12px;line-height:1.5;border-top:1px solid #1e2a20;">
Transparent, signed, honest billing. You can audit every impression with <code style="color:#8fbf9a;">lumaline earnings</code>.
</td></tr>
</table></td></tr></table></body></html>`;
}

function cta(url, label) {
  return `<a href="${esc(url)}" style="display:inline-block;background:${GREEN};color:#06210f;font-weight:700;text-decoration:none;padding:11px 20px;border-radius:9px;font-size:14px;">${esc(label)}</a>`;
}

export function paidEmail({ handle, amountEur }) {
  const subject = `💸 You just got paid €${amountEur}`;
  const html = shell(`<tr><td style="padding:8px 28px 24px;color:#cfe9d4;">
<p style="font-size:26px;font-weight:700;color:#e8f5e9;margin:14px 0 6px;">💸 €${esc(amountEur)} is on its way</p>
<p style="font-size:15px;line-height:1.6;color:#b7cbbb;margin:0 0 14px;">Nice work, <b style="color:#e8f5e9;">${esc(handle)}</b>. Your LumaLine earnings just transferred to your connected bank — it lands in a couple of business days.</p>
<p style="font-size:13px;color:#7f948a;margin:0;">No action needed. Payouts run automatically every week.</p>
</td></tr>`);
  const text = `You just got paid €${amountEur}\n\nNice work, ${handle}. Your LumaLine earnings transferred to your connected bank and land in a couple of business days. No action needed — payouts run automatically each week.`;
  return { subject, html, text };
}

export function connectNudgeEmail({ handle, amountEur }) {
  const subject = `You've got €${amountEur} waiting — connect your bank`;
  const html = shell(`<tr><td style="padding:8px 28px 24px;color:#cfe9d4;">
<p style="font-size:26px;font-weight:700;color:#e8f5e9;margin:14px 0 6px;">You've earned €${esc(amountEur)} 🎉</p>
<p style="font-size:15px;line-height:1.6;color:#b7cbbb;margin:0 0 18px;">Hi <b style="color:#e8f5e9;">${esc(handle)}</b> — your earnings are ready, but we don't have anywhere to send them yet. Connect your bank once and weekly payouts turn on automatically.</p>
<p style="margin:0 0 18px;">${cta("https://feed.lumaline.dev", "Run: lumaline connect")}</p>
<p style="font-size:13px;color:#7f948a;margin:0;">In your terminal: <code style="color:#8fbf9a;">lumaline connect</code> — you'll enter your IBAN on Stripe's secure page.</p>
</td></tr>`);
  const text = `You've earned €${amountEur} 🎉\n\nHi ${handle} — your earnings are ready but we have nowhere to send them yet. Run \`lumaline connect\` in your terminal to add your bank (IBAN on Stripe's secure page). Weekly payouts then turn on automatically.`;
  return { subject, html, text };
}

// Best-effort: NEVER throws. Returns 'sent' or 'failed:<reason>'.
export async function sendEmail({ to, subject, html, text, apiKey, from, fetchImpl = fetch }) {
  if (!apiKey || !to) return "failed:not_configured";
  try {
    const resp = await fetchImpl("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({ from, to: [to], subject, html, text }),
    });
    return resp.ok ? "sent" : `failed:${resp.status}`;
  } catch (err) {
    return `failed:${(err && err.message) ? "network" : "unknown"}`;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/email-builders.test.mjs`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add supabase/functions/_shared/email.mjs test/email-builders.test.mjs
git commit -m "feat(payout): branded HTML payout emails (paid + connect-nudge) + best-effort Resend sender"
```

---

### Task 3: Pure payout helpers — constant-time cron-secret compare + min parse

**Files:**
- Modify: `supabase/functions/_shared/payout-logic.mjs` (append two pure helpers)
- Test: `test/payout-logic.test.mjs` (append; if absent, create)

**Interfaces:**
- Produces: `constantTimeEqual(a: string, b: string) : boolean`; `payoutMinMicros(envVal: unknown) : number`.

- [ ] **Step 1: Write the failing test**

```javascript
// test/payout-logic.test.mjs  (append these)
import test from 'node:test';
import assert from 'node:assert/strict';
import { constantTimeEqual, payoutMinMicros } from '../supabase/functions/_shared/payout-logic.mjs';

test('constantTimeEqual: equal strings true, any diff false, length-mismatch false', () => {
  assert.equal(constantTimeEqual('abc123', 'abc123'), true);
  assert.equal(constantTimeEqual('abc123', 'abc124'), false);
  assert.equal(constantTimeEqual('abc', 'abcd'), false);
  assert.equal(constantTimeEqual('', ''), false);   // empty never authorizes
});

test('payoutMinMicros: default €1 on absent/garbage/negative, honors valid', () => {
  assert.equal(payoutMinMicros(undefined), 1000000);
  assert.equal(payoutMinMicros(''), 1000000);
  assert.equal(payoutMinMicros('nope'), 1000000);
  assert.equal(payoutMinMicros('-5'), 1000000);
  assert.equal(payoutMinMicros('0'), 1000000);      // 0 would pay dust → clamp to default
  assert.equal(payoutMinMicros('5000000'), 5000000);
  assert.equal(payoutMinMicros(2500000), 2500000);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/payout-logic.test.mjs`
Expected: FAIL — `constantTimeEqual` / `payoutMinMicros` not exported.

- [ ] **Step 3: Append the helpers to `_shared/payout-logic.mjs`**

```javascript
/** Constant-time string compare (no early-exit on mismatch). Empty strings never authorize. */
export function constantTimeEqual(a, b) {
  const sa = String(a ?? ""), sb = String(b ?? "");
  if (sa.length === 0 || sb.length === 0 || sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
}

/** Payout minimum in micro-EUR from env; default €1 (1_000_000). Garbage/≤0 → default. */
export function payoutMinMicros(envVal) {
  const n = Number(envVal);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 1000000;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/payout-logic.test.mjs`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add supabase/functions/_shared/payout-logic.mjs test/payout-logic.test.mjs
git commit -m "feat(payout): pure cron-secret constant-time compare + env min-micros parse"
```

---

### Task 4: Migration — nudge column + contact/nudge RPCs + `app.run_payout()`

**Files:**
- Create: `supabase/migrations/20260704150000_auto_payout.sql`
- Test: `test/auto-payout-sql.integration.mjs` (create — self-skips without local stack)

**Interfaces:**
- Produces (all `SECURITY DEFINER`, service_role-only):
  - `public.publishers.connect_nudge_at timestamptz`
  - `app.publisher_contact(p_publisher_id uuid) → TABLE(email text, handle text)`
  - `app.payout_nudge_candidates(p_min_micros bigint, p_hold interval) → TABLE(publisher_id uuid, email text, handle text, payable_micros bigint)`
  - `app.mark_connect_nudged(p_ids uuid[]) → void`
  - `app.run_payout() → void` (pg_cron target)

- [ ] **Step 1: Write the failing test**

```javascript
// test/auto-payout-sql.integration.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

const DB = process.env.SUPABASE_DB_URL || 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
let pg; try { pg = (await import('node:child_process')); } catch { /* */ }
const psql = (sql) => {
  const r = pg.spawnSync('psql', [DB, '-Atc', sql], { encoding: 'utf8' });
  return { ok: r.status === 0, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
};
const up = psql("select 1");
const SKIP = !up.ok ? 'local DB unreachable — SKIPPING' : false;
if (SKIP) console.log(`[auto-payout-sql] ${SKIP}`);

test('migration objects exist', { skip: SKIP }, () => {
  assert.equal(psql("select count(*) from information_schema.columns where table_schema='public' and table_name='publishers' and column_name='connect_nudge_at'").out, '1');
  for (const fn of ['publisher_contact', 'payout_nudge_candidates', 'mark_connect_nudged', 'run_payout']) {
    assert.equal(psql(`select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='app' and p.proname='${fn}'`).out, '1', `app.${fn} exists`);
  }
});

test('run_payout no-ops cleanly when Vault secret absent (fresh stack)', { skip: SKIP }, () => {
  const r = psql("select app.run_payout()");
  assert.ok(r.ok, `run_payout ran without error: ${r.err}`);
});

test('anon/authenticated cannot execute the new money RPCs', { skip: SKIP }, () => {
  for (const sig of ['app.publisher_contact(uuid)', 'app.payout_nudge_candidates(bigint,interval)', 'app.mark_connect_nudged(uuid[])', 'app.run_payout()']) {
    assert.equal(psql(`select has_function_privilege('anon','${sig}','execute')`).out, 'f', `anon cannot ${sig}`);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/auto-payout-sql.integration.mjs`
Expected: FAIL (objects missing) — or SKIP if the stack is down. Bring the stack up (`supabase start`) if needed to get a real FAIL.

- [ ] **Step 3: Write the migration**

```sql
-- supabase/migrations/20260704150000_auto_payout.sql
-- M5-T4 auto-payout: a connect-nudge dedup column, publisher-contact + nudge-candidate RPCs, and a
-- pg_cron target (twin of app.run_monitor) that POSTs the payout batch with the Vault cron secret.
-- All money RPCs are SECURITY DEFINER + service_role-only. run_payout degrades to NOTICE+no-op when
-- Vault/pg_net/secret is absent, so a fresh `supabase db reset` applies and runs cleanly.
set local lock_timeout = '2s';
set local statement_timeout = '15s';

alter table public.publishers add column if not exists connect_nudge_at timestamptz;

-- Contact for a publisher (email + handle) from auth.users. SECDEF: crosses into the auth schema.
create or replace function app.publisher_contact(p_publisher_id uuid)
returns table(email text, handle text)
language sql security definer set search_path = '' as $$
  select u.email::text, p.handle
    from public.publishers p
    join auth.users u on u.id = p.auth_user_id
   where p.id = p_publisher_id
   limit 1;
$$;
revoke all on function app.publisher_contact(uuid) from public, anon, authenticated;
grant execute on function app.publisher_contact(uuid) to service_role;

-- Publishers who have earned >= the minimum but have NOT onboarded a bank, not nudged in ~a week.
create or replace function app.payout_nudge_candidates(p_min_micros bigint, p_hold interval default interval '7 days')
returns table(publisher_id uuid, email text, handle text, payable_micros bigint)
language plpgsql security definer set search_path = '' as $$
begin
  return query
    select p.id, u.email::text, p.handle, app.publisher_payable_micros(p.id, p_hold)
      from public.publishers p
      join auth.users u on u.id = p.auth_user_id
     where p.stripe_account_id is null
       and (p.connect_nudge_at is null or p.connect_nudge_at < now() - interval '6 days')
       and app.publisher_payable_micros(p.id, p_hold) >= p_min_micros;
end;
$$;
revoke all on function app.payout_nudge_candidates(bigint, interval) from public, anon, authenticated;
grant execute on function app.payout_nudge_candidates(bigint, interval) to service_role;

create or replace function app.mark_connect_nudged(p_ids uuid[])
returns void language sql security definer set search_path = '' as $$
  update public.publishers set connect_nudge_at = now() where id = any(p_ids);
$$;
revoke all on function app.mark_connect_nudged(uuid[]) from public, anon, authenticated;
grant execute on function app.mark_connect_nudged(uuid[]) to service_role;

-- pg_cron target. Reads 'lumaline_cron_secret' from Vault and POSTs /payout/batch with the
-- x-lumaline-cron-secret header via pg_net. Vault/secret/pg_net absent -> NOTICE + no-op.
create or replace function app.run_payout()
returns void language plpgsql security definer set search_path = '' as $$
declare v_secret text; v_request_id bigint;
begin
  if to_regclass('vault.decrypted_secrets') is null then
    raise notice 'run_payout: vault.decrypted_secrets missing (fresh local stack?) — no-op'; return;
  end if;
  begin
    execute 'select decrypted_secret from vault.decrypted_secrets where name = $1 limit 1'
       into v_secret using 'lumaline_cron_secret';
  exception when others then raise notice 'run_payout: cannot read vault (%) — no-op', sqlerrm; return; end;
  if v_secret is null or v_secret = '' then
    raise notice 'run_payout: vault secret lumaline_cron_secret absent — no-op'; return;
  end if;
  begin
    execute $q$
      select net.http_post(
        url     := 'https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/stripe-connect/payout/batch',
        body    := '{}'::jsonb,
        headers := jsonb_build_object('Content-Type','application/json','x-lumaline-cron-secret',$1),
        timeout_milliseconds := 120000)
    $q$ into v_request_id using v_secret;
  exception when others then raise notice 'run_payout: net.http_post unavailable/failed (%) — no-op', sqlerrm; return; end;
end;
$$;
revoke all on function app.run_payout() from public, anon, authenticated;
comment on function app.run_payout is
  'pg_cron target: POST the payout batch with the Vault cron secret. Vault/secret/pg_net absent -> NOTICE + no-op. Controller cron.schedule''s this weekly at deploy.';
```

- [ ] **Step 4: Apply locally + run the test**

Run: `psql "$SUPABASE_DB_URL" -v ON_ERROR_STOP=1 -f supabase/migrations/20260704150000_auto_payout.sql` (or `supabase db reset` to apply the whole chain).
Then: `node --test test/auto-payout-sql.integration.mjs`
Expected: PASS (objects exist, run_payout no-ops, anon revoked).

- [ ] **Step 5: Commit**

```bash
git add supabase/migrations/20260704150000_auto_payout.sql test/auto-payout-sql.integration.mjs
git commit -m "feat(payout): auto-payout migration — nudge column + contact/nudge RPCs + run_payout cron target"
```

---

### Task 5: Wire the `stripe-connect` fn — cron auth + €1 min + post-loop emails

**Files:**
- Modify: `supabase/functions/stripe-connect/index.ts` (import helpers; add `hasValidCronSecret`/`requirePrivileged`; swap the admin gate; pass `p_min_micros`; add a post-loop notify pass)
- Test: `test/auto-payout.integration.mjs` (create — self-skips without the local stack + served fn)

**Interfaces:**
- Consumes: `constantTimeEqual`, `payoutMinMicros` (Task 3); `paidEmail`, `connectNudgeEmail`, `sendEmail` (Task 2); `app.publisher_contact`, `app.payout_nudge_candidates`, `app.mark_connect_nudged` (Task 4).
- Produces: `/payout/batch` accepts the cron secret; charges the €1 min; emails paid + un-onboarded publishers.

- [ ] **Step 1: Write the failing integration test**

```javascript
// test/auto-payout.integration.mjs — needs local stack + `supabase functions serve stripe-connect`.
import test from 'node:test';
import assert from 'node:assert/strict';

const FN = process.env.STRIPE_CONNECT_URL || 'http://127.0.0.1:54321/functions/v1/stripe-connect';
async function up() { try { const r = await fetch(`${FN}/payout/batch`, { method: 'OPTIONS', signal: AbortSignal.timeout(2000) }); return r.status === 200; } catch { return false; } }
const SKIP = !(await up()) ? 'stripe-connect fn not served — SKIPPING' : false;
if (SKIP) console.log(`[auto-payout.integration] ${SKIP}`);

test('payout/batch: bad cron secret is rejected (403)', { skip: SKIP }, async () => {
  const r = await fetch(`${FN}/payout/batch?dry_run=true`, { method: 'POST', headers: { 'x-lumaline-cron-secret': 'wrong', 'content-type': 'application/json' }, body: '{}' });
  assert.equal(r.status, 403);
});

test('payout/batch: valid cron secret authorizes the dry-run', { skip: SKIP || !process.env.LUMALINE_CRON_SECRET }, async () => {
  const r = await fetch(`${FN}/payout/batch?dry_run=true`, { method: 'POST', headers: { 'x-lumaline-cron-secret': process.env.LUMALINE_CRON_SECRET, 'content-type': 'application/json' }, body: '{}' });
  assert.equal(r.status, 200);
  const b = await r.json();
  assert.equal(b.ok, true); assert.equal(b.dry_run, true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/auto-payout.integration.mjs`
Expected: FAIL on the bad-secret test (currently `/payout/batch` requires an admin JWT and returns 403 for a cron header — so actually it already 403s; the meaningful new assertion is the *valid* secret authorizing, which fails until wired). Serve the fn with `LUMALINE_CRON_SECRET` set to get a real FAIL on the second test.

- [ ] **Step 3: Add imports + auth helpers to `stripe-connect/index.ts`**

Extend the existing `_shared/payout-logic.mjs` import to include `constantTimeEqual, payoutMinMicros`, and add:

```typescript
import { paidEmail, connectNudgeEmail, sendEmail } from "../_shared/email.mjs";

function hasValidCronSecret(req: Request): boolean {
  const got = req.headers.get("x-lumaline-cron-secret") ?? "";
  const want = Deno.env.get("LUMALINE_CRON_SECRET") ?? "";
  return constantTimeEqual(got, want);
}
```

- [ ] **Step 4: Swap the shared admin gate to accept the cron secret**

At the shared admin gate (~line 293), replace:

```typescript
  const adminAuth = await requireAdmin(req);
  if (!adminAuth) return jsonErr("Forbidden", 403);
```

with:

```typescript
  // Privileged routes: an admin JWT OR the pg_cron secret (weekly auto-payout). Both are trusted;
  // the cron only ever calls /payout/batch, and /reconcile is read-only.
  const cron = hasValidCronSecret(req);
  const adminAuth = cron ? "cron" : await requireAdmin(req);
  if (!adminAuth) return jsonErr("Forbidden", 403);
```

- [ ] **Step 5: Pass the €1 min into the reserve**

In the `/payout/batch` handler, replace:
`const reserve = await serviceRpc("payout_batch_reserve", {});`
with:

```typescript
    const minMicros = payoutMinMicros(Deno.env.get("LUMALINE_PAYOUT_MIN_MICROS"));
    const reserve = await serviceRpc("payout_batch_reserve", { p_min_micros: minMicros });
```

- [ ] **Step 6: Add the post-loop notify pass (best-effort, never blocks a payout)**

Immediately BEFORE the final `const paid = results.filter(...)` line in `/payout/batch`, insert:

```typescript
    // ---- Notifications (best-effort; a failure here never affects a payout) ------------
    try {
      const apiKey = Deno.env.get("RESEND_API_KEY") ?? "";
      const from = Deno.env.get("LUMALINE_EMAIL_FROM") ?? "LumaLine <payouts@send.lumaline.dev>";
      const eur = (c: number) => (c / 100).toFixed(2);

      // Paid confirmations
      for (const r of results.filter((x) => x.status === "paid")) {
        const po = pending.find((p) => p.id === r.payout_id);
        if (!po) continue;
        const c = await serviceRpc("publisher_contact", { p_publisher_id: po.publisher_id });
        const contact = (c.ok ? c.data : null) as { email?: string; handle?: string } | null;
        if (!contact?.email) continue;
        const { subject, html, text } = paidEmail({ handle: contact.handle ?? "there", amountEur: eur(microsToCents(po.amount_micros)) });
        await sendEmail({ to: contact.email, subject, html, text, apiKey, from });
      }

      // Connect-nudges (over-min, not onboarded, not nudged in ~a week)
      const nudge = await serviceRpc("payout_nudge_candidates", { p_min_micros: minMicros });
      const cands = (nudge.ok && Array.isArray(nudge.data) ? nudge.data : []) as Array<{ publisher_id: string; email: string; handle: string; payable_micros: number }>;
      const nudged: string[] = [];
      for (const cnd of cands) {
        if (!cnd.email) continue;
        const { subject, html, text } = connectNudgeEmail({ handle: cnd.handle ?? "there", amountEur: eur(microsToCents(cnd.payable_micros)) });
        const res = await sendEmail({ to: cnd.email, subject, html, text, apiKey, from });
        if (res === "sent") nudged.push(cnd.publisher_id);
      }
      if (nudged.length > 0) await serviceRpc("mark_connect_nudged", { p_ids: nudged });
    } catch (err) {
      console.error(`payout: notify pass failed (non-fatal): ${(err as { message?: string }).message ?? "unknown"}`);
    }
```

Note: `serviceRpc` unwraps single-row results, so `publisher_contact` returns `{email, handle}` directly; `payout_nudge_candidates` returns an array. `mark_connect_nudged` is only called for publishers whose email actually sent, so a transient email outage re-nudges next week (no lost signal).

- [ ] **Step 7: Run the integration test + full suite**

Serve: `SUPABASE_… supabase functions serve stripe-connect --no-verify-jwt --env-file supabase/functions/.env` (set `LUMALINE_CRON_SECRET`, `LUMALINE_PAYOUT_MIN_MICROS=1000000`, `RESEND_API_KEY` in that env file).
Run: `node --test test/auto-payout.integration.mjs`
Expected: PASS (bad secret 403; valid secret 200 dry-run).
Then the pure suite: `node --test test/*.test.mjs` — Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add supabase/functions/stripe-connect/index.ts test/auto-payout.integration.mjs
git commit -m "feat(payout): stripe-connect cron-secret auth + €1 min + best-effort paid/nudge emails"
```

---

### Task 6: End-to-end local proof + adversarial review + owner-gated deploy runbook

**Files:**
- Create: `docs/ops/m5-t4-deploy.md` (deploy checklist)
- Modify: `package.json` (client version bump)

- [ ] **Step 1: Local end-to-end proof (reuse the payout harness)**

On the local stack, seed a publisher with a connected `stripe_account_id` + matured earnings ≥ €1 (reuse the existing payout integration seed), plus a second publisher with earnings ≥ €1 and `stripe_account_id IS NULL`. Trigger `POST /payout/batch` with the cron secret. Assert: first publisher → `paid` (test-mode transfer) + a paid email attempt logged; second → appears in `payout_nudge_candidates`, gets a nudge, `connect_nudge_at` stamped; a second immediate run does NOT re-nudge (dedup). Record the output in the PR description.

- [ ] **Step 2: Bump the client version**

Edit `package.json` `version` (e.g. `0.1.2` → `0.1.3`). Commit:
```bash
git add package.json && git commit -m "chore(client): bump version for lumaline connect"
```

- [ ] **Step 3: Adversarial review**

Run a money/trust adversarial review (workflow, same bar as the charge fix) over the whole branch. Lenses: (a) can the cron path double-pay or bypass a money-safety invariant; (b) can an email failure or a malformed publisher_contact/nudge row block, reverse, or crash a payout; (c) constant-time-compare + secret handling (never logged); (d) nudge dedup correctness (no spam, no lost signal); (e) migration grants (anon/authenticated revoked). Fix any Critical/High before deploy.

- [ ] **Step 4: Write `docs/ops/m5-t4-deploy.md` (owner-gated sequence)**

Document, each step ref-guarded to `prmsonskzrubqsazmpwd` + owner GO:
1. Apply migration `20260704150000_auto_payout.sql` (ref-guarded runner) + stamp `schema_migrations`.
2. Set fn env on `stripe-connect`: `LUMALINE_CRON_SECRET` (= Vault `lumaline_cron_secret`), `LUMALINE_PAYOUT_MIN_MICROS=1000000`, `LUMALINE_EMAIL_FROM`, confirm `RESEND_API_KEY`. Confirm the Resend `from` domain (`send.lumaline.dev`) is verified for API sends; else fall back to `onboarding@resend.dev`.
3. Redeploy `stripe-connect` (`supabase functions deploy stripe-connect --project-ref prmsonskzrubqsazmpwd --use-api`).
4. `select cron.schedule('lumaline-payout-weekly','0 9 * * 1','select app.run_payout()')`.
5. Smoke: admin `POST /payout/batch?dry_run=true` → the €1-min plan; verify **no** transfer.
6. Publish the client: tag `vX.Y.Z` → `release.yml` (`npm publish --provenance`).
7. Announce `lumaline connect` to the publisher(s).

- [ ] **Step 5: Push branch + open PR**

```bash
git push -u origin feat/m5-t4-auto-payout
gh pr create --base main --title "feat(payout): M5-T4 auto weekly payouts + lumaline connect + branded emails" --body "<summary + local e2e evidence + review verdict>"
```

- [ ] **Step 6: Owner-gated deploy** — execute `docs/ops/m5-t4-deploy.md` step-by-step, each with explicit owner GO. Then M5-T4 = the first real auto-payout once a publisher's matured payable crosses €1.

---

## Self-Review

**Spec coverage:** `lumaline connect` (T1) ✓ · config base (T1) ✓ · stale copy fix (T1) ✓ · version bump (T6) ✓ · `app.run_payout` cron twin (T4) ✓ · cron-secret auth (T3+T5) ✓ · €1 env min (T3+T5) ✓ · branded paid+nudge emails (T2) ✓ · publisher_contact/nudge_candidates/mark_nudged + `connect_nudge_at` (T4) ✓ · best-effort sends (T5) ✓ · money core untouched (T5 only adds auth/min/post-loop) ✓ · unit tests cron-compare/min/email (T2,T3) + integration (T4,T5) ✓ · owner-gated deploy (T6) ✓. Future portals/dashboard/withdraw are non-goals (documented in spec).

**Placeholder scan:** deploy PR body `<summary…>` is an intentional author fill at push time; all code steps carry full code. No TBD/TODO in code.

**Type consistency:** `connect({file, connectBase, fetchImpl, now, timeoutMs, out})`, `paidEmail({handle, amountEur})`, `connectNudgeEmail({handle, amountEur})`, `sendEmail({to,subject,html,text,apiKey,from,fetchImpl})`, `constantTimeEqual(a,b)`, `payoutMinMicros(envVal)`, `publisher_contact→{email,handle}`, `payout_nudge_candidates→[{publisher_id,email,handle,payable_micros}]` — used identically in T5. `microsToCents`/`serviceRpc`/`svc`/`PAYOUT_CURRENCY` are pre-existing in `stripe-connect/index.ts`.
