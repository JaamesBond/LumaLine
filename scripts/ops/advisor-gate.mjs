#!/usr/bin/env node
// scripts/ops/advisor-gate.mjs — BLOCKING get_advisors deploy gate for the LumaLine remote
// (prmsonskzrubqsazmpwd). Promotes "run get_advisors after deploy" from a forgettable manual note
// to a scripted gate that exits NON-ZERO on any exposed-SECDEF / anon-executable / RLS-off security
// advisor — the exact bug class that already reached prod (M3 20260629120000_secdef_grant_hardening.sql).
//
// Run it in the owner-gated deploy runbook AFTER every migration apply:
//   node scripts/ops/advisor-gate.mjs           # security advisors (default) — BLOCKS on findings
//   node scripts/ops/advisor-gate.mjs --all     # also print performance advisors (never blocking)
// A non-zero exit must ABORT the deploy. The hermetic test/migration-secdef-lint.test.mjs catches the
// same class in the required `node --test` gate BEFORE merge; this catches whatever actually landed on
// the live database AFTER apply (e.g. a default-privilege grant the migration text did not anticipate).
//
// Reads creds from the repo-root .env (gitignored; _REMOTE = production). Ref-guarded exactly like
// scripts/ops/sql.mjs: it refuses to run against anything but prmsonskzrubqsazmpwd (never the CRM
// project kvlfpwzmjxuapjheknnj). Not shipped to npm (package.json#files is bin/src/README only).
import { readFileSync } from 'node:fs';

const ENV = readFileSync(new URL('../../.env', import.meta.url), 'utf8');
const get = (k) => (ENV.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1]?.trim();
const REF = get('SUPABASE_PROJECTID_REMOTE');
const PAT = get('SUPABASE_ACCESS_TOKEN_REMOTE');

if (REF !== 'prmsonskzrubqsazmpwd') { console.error(`FATAL: ref mismatch (refusing to run): ${REF}`); process.exit(2); }
if (!PAT) { console.error('FATAL: no SUPABASE_ACCESS_TOKEN_REMOTE in .env'); process.exit(2); }

const showAll = process.argv.includes('--all');

// The Management API advisors endpoint mirrors the Supabase MCP get_advisors tool.
async function advisors(kind) {
  const res = await fetch(`https://api.supabase.com/v1/projects/${REF}/advisors/${kind}`, {
    headers: { Authorization: `Bearer ${PAT}` },
  });
  const text = await res.text();
  if (!res.ok) { console.error(`FATAL: advisors/${kind} HTTP ${res.status}: ${text}`); process.exit(2); }
  try { return JSON.parse(text).lints ?? []; } catch { console.error(`FATAL: unparseable advisors/${kind} body`); process.exit(2); }
}

// The bug CLASS this gate exists to stop: what an errant migration can regress into a REAL exposure —
// anon-reachable SECDEF, RLS turned off, a SECDEF view, a mutable search_path — plus any ERROR-level
// security lint (fail closed on the unknown). Match by the advisor's stable `name` (Supabase slugs).
const BLOCKING_NAME = /rls_disabled|rls_references_user_metadata|policy_exists_rls_disabled|security_definer_view|function_search_path|(^|_)anon(_|$)/i;
// Deliberately NOT blocking (the gate's original bare `security_definer` term matched this and aborted
// every deploy on a non-bug): `authenticated_security_definer_function_executable` is the INTENTIONAL
// self-gating-RPC pattern this codebase is built on — every such function re-checks
// is_admin / is_money_admin / current_advertiser_id / RLS in-body, and anon EXECUTE is separately
// REVOKEd (0 anon-executable findings on prod). Verified gated: approve_clawback,
// gdpr_delete_publisher, admin_open_clawback, advertiser_set_line_item_status, resolve_dispute,
// advertiser_submit_creative, … A gate that cries wolf on the intended pattern gets muted, which is
// how the REAL anon footgun would slip through. Baseline placement/config advisories
// (extension_in_public, rls_enabled_no_policy = deny-by-default, auth_leaked_password_protection) are
// a hardening backlog, not a deploy-regressible exposure — printed as non-blocking so they stay visible.
const INTENTIONAL = new Set(['authenticated_security_definer_function_executable']);
const isBlocking = (l) => {
  const name = String(l?.name ?? '');
  if (INTENTIONAL.has(name)) return false;
  return String(l?.level).toUpperCase() === 'ERROR' || BLOCKING_NAME.test(name);
};

const security = await advisors('security');
const blocking = security.filter(isBlocking);
const other = security.filter((l) => !isBlocking(l));

const fmt = (l) =>
  `  [${String(l?.level ?? '?').toUpperCase()}] ${l?.name ?? '?'}` +
  `${l?.detail ? ` — ${String(l.detail).replace(/\s+/g, ' ').slice(0, 240)}` : ''}` +
  `${l?.metadata?.name ? ` (${l.metadata.entity ?? ''} ${l.metadata.name})` : ''}`;

if (other.length) {
  console.log(`security advisors — ${other.length} non-blocking:`);
  for (const l of other) console.log(fmt(l));
}

if (showAll) {
  const perf = await advisors('performance');
  console.log(`\nperformance advisors — ${perf.length} (never blocking):`);
  for (const l of perf) console.log(fmt(l));
}

if (blocking.length > 0) {
  console.error(`\n✗ DEPLOY GATE FAILED — ${blocking.length} blocking security advisor(s):`);
  for (const l of blocking) console.error(fmt(l));
  console.error('\nAbort the deploy and fix (e.g. REVOKE anon EXECUTE / enable RLS) before proceeding.');
  process.exit(1);
}

console.log(`\n✓ advisor-gate: no blocking security advisors on ${REF}.`);
process.exit(0);
