# M5-T4 Auto-Payout — owner-gated deploy runbook

Deploys the auto-payout system (branch `feat/m5-t4-auto-payout`): `lumaline connect`, weekly
`pg_cron → /payout/batch`, €1 minimum, branded paid + connect-nudge emails.

**Every remote step is ref-guarded to `prmsonskzrubqsazmpwd` (NEVER the CRM `kvlfpwzmjxuapjheknnj`)
and requires explicit per-step owner GO.** The money core (reserve→transfer→confirm) is unchanged;
this deploy adds a cron trigger, a cron-secret auth path, the €1 min, and best-effort emails.

## Pre-flight (read-only)
- Confirm `main` has merged this branch's PR (or you are deploying from the branch intentionally).
- Confirm the local suite is green: `node --test` (unit) + the integration files pass against the local stack.
- Confirm the Vault secret `lumaline_cron_secret` already exists on prod (the monitor cron uses it) —
  the payout cron reuses the SAME secret. `select name from vault.secrets where name='lumaline_cron_secret';`

## Step 1 — Apply the migration (owner GO)
Apply `supabase/migrations/20260704150000_auto_payout.sql` to prod via the ref-guarded runner, then
stamp `schema_migrations`:
```
node <scratchpad>/sql.mjs @supabase/migrations/20260704150000_auto_payout.sql
node <scratchpad>/sql.mjs "insert into supabase_migrations.schema_migrations (version,name) values ('20260704150000','auto_payout') on conflict (version) do nothing returning version;"
```
Verify: `connect_nudge_at` column exists; the 4 `app.*` functions exist; `anon`/`authenticated`
cannot execute them; `app.run_payout()` runs without error (no-ops or posts).

## Step 2 — Set fn env on `stripe-connect` (owner GO)
Ensure these are set for the `stripe-connect` function (via `supabase secrets set` / dashboard):
- `LUMALINE_CRON_SECRET` = the SAME value as Vault `lumaline_cron_secret` (so the fn's constant-time
  compare matches what `app.run_payout()` sends).
- `LUMALINE_PAYOUT_MIN_MICROS=1000000` (€1).
- `LUMALINE_EMAIL_FROM` (optional; default `LumaLine <payouts@send.lumaline.dev>`).
- Confirm `RESEND_API_KEY` is present, AND that the `from` domain (`send.lumaline.dev`) is verified in
  Resend for API sends. If it is NOT verified, set `LUMALINE_EMAIL_FROM="LumaLine <onboarding@resend.dev>"`
  as a fallback so paid/nudge emails still deliver.

## Step 3 — Redeploy the fn (owner GO)
```
SUPABASE_ACCESS_TOKEN=<PAT> supabase functions deploy stripe-connect --project-ref prmsonskzrubqsazmpwd --use-api
```
This bundles the new `_shared/email.mjs` + `_shared/payout-logic.mjs` helpers via the import graph.

## Step 4 — Schedule the weekly cron (owner GO)
```
node <scratchpad>/sql.mjs "select cron.schedule('lumaline-payout-weekly','0 9 * * 1','select app.run_payout()');"
```
Verify: `select jobname, schedule, active from cron.job where jobname='lumaline-payout-weekly';`

## Step 5 — Smoke test (no money moves)
Admin dry-run (uses an admin JWT, NOT the cron secret) — confirms the €1-min plan and that NO transfer
is attempted:
```
# GET/POST /payout/batch?dry_run=true with an admin bearer → {ok:true, dry_run:true, reserved, would_transfer}
```
Optionally verify the cron path: `select app.run_payout();` on prod → it POSTs `/payout/batch`; since
nothing is over-min-and-onboarded yet, `paid:0`. Check `net._http_response` / fn logs for a 200.

## Step 6 — Publish the client (owner GO)
The `lumaline connect` command ships via npm. Bump is already in `package.json` (0.1.4). Tag + release:
```
git tag v0.1.4 && git push origin v0.1.4     # release.yml → npm publish --provenance
```
(Installed clients do not self-update — 0.1.4 reaches new installs + `npm update -g lumaline`.)

## Step 7 — Announce
Tell publisher(s) to run `lumaline connect` to add their bank. Once a publisher's matured (7-day-held)
payable crosses €1, the Monday 09:00 UTC cron pays them automatically and emails a confirmation.
Un-onboarded publishers with ≥ €1 waiting get a weekly connect-nudge email (deduped to ~weekly).

## Rollback
- Unschedule: `select cron.unschedule('lumaline-payout-weekly');` — stops auto-payouts (the manual
  admin `/payout/batch` still works).
- The migration is additive; no data is destroyed. To fully revert the fn, redeploy the prior
  `stripe-connect` build. The cron-secret auth + €1 min + emails are inert without the cron schedule.

## Money-safety notes
- The transfer/confirm core is unchanged and remains double-pay-safe (idempotency key per payout +
  `UNIQUE(stripe_transfer_id)` + ambiguous-error self-heal).
- Emails are best-effort (bounded timeout, never throw) and run AFTER the money loop — a Resend outage
  never blocks, reverses, or fails a payout.
- `LUMALINE_CRON_SECRET` unset/empty → the cron auth path fails closed (no one is authorized by an
  empty secret); the admin JWT path is unaffected.
