// test/migration-secdef-lint.test.mjs — HERMETIC static lint for the SECURITY DEFINER footgun.
//
// This is the #1 must-fix across every adversarial lens and the ONLY enforcement of the trust
// invariant "anon EXECUTE REVOKED + a first-line is_admin()/is_money_admin() gate on every new
// public SECDEF" that runs in the REQUIRED `node --test` gate. Every admin-*.integration.mjs suite
// self-skips without a local Supabase stack, so in the protected-`main` CI (which runs only
// `node --test`, no DB) they assert nothing. This pure lint DOES run there.
//
// The exact bug class it guards is the one that already reached prod (M3
// 20260629120000_secdef_grant_hardening.sql): Supabase's default privileges auto-grant
// anon+authenticated EXECUTE on every NEW public function, so a public SECURITY DEFINER function
// (or a CREATE OR REPLACE that drops its REVOKE line) is anon-reachable unless the migration
// explicitly REVOKEs it. A definer read with a weak/absent in-body gate then leaks platform-wide
// data on the public anon key.
//
// WHAT IT ASSERTS (pure — reads supabase/migrations/*.sql, no DB):
//   1. Every file that CREATEs a `public.*` SECURITY DEFINER function contains, IN THE SAME FILE,
//      a `REVOKE ... ON FUNCTION public.<name>(...) FROM ... (PUBLIC|anon)` for that function.
//   2. Every definition of a NEW admin RPC (allow-list) carries an in-body
//      app.is_admin()/app.is_money_admin() gate — a dropped gate is caught even if the REVOKE
//      survives (a copy-paste of the skeleton missing the RAISE).
//   3. The M8 money migrations reference app.is_money_admin() (NOT app.is_admin()) in their gate
//      and source the payout hold from app.payout_hold_interval() with no hardcoded '7 days' literal.
//   4. GOLDEN NEGATIVES: hand-built bad fixtures (missing REVOKE / missing gate) DO trip the lint,
//      proving it bites; a well-formed fixture does not.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'supabase', 'migrations');

// The NEW admin RPCs whose bodies MUST carry a first-line app.is_admin()/is_money_admin() gate.
// (money_admin_check/admin_check are thin Data-API wrappers whose body IS the predicate.)
const ADMIN_RPCS = new Set([
  'admin_ledger_health',
  'admin_open_clawback',
  'approve_clawback',
  'reject_clawback',
  'resolve_dispute',
  'gdpr_delete_publisher',
  'money_admin_check',
]);

// ---------------------------------------------------------------------------
// Pure parser: extract each `CREATE [OR REPLACE] FUNCTION public.<name>(...)` block — its header
// (up to the opening dollar-quote) and its body (between the matching $tag$ … $tag$). Header-only
// dollar-quote handling avoids any nested-quote confusion: SECURITY DEFINER always sits in the
// header, before `AS $$`.
// ---------------------------------------------------------------------------
export function publicFunctionBlocks(content) {
  const blocks = [];
  const re = /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+public\.([a-z0-9_]+)\s*\(/gi;
  let m;
  while ((m = re.exec(content)) !== null) {
    const rest = content.slice(m.index);
    const dq = rest.match(/AS\s+(\$[a-zA-Z0-9_]*\$)/i);
    let header, body, whole;
    if (dq) {
      const tag = dq[1];
      const bodyStart = dq.index + dq[0].length;
      const close = rest.indexOf(tag, bodyStart);
      const bodyEnd = close >= 0 ? close : rest.length;
      header = rest.slice(0, dq.index);
      body = rest.slice(bodyStart, bodyEnd);
      whole = rest.slice(0, close >= 0 ? close + tag.length : rest.length);
    } else {
      // SQL function without dollar quotes (rare here) — header up to first ';'.
      const semi = rest.indexOf(';');
      header = rest.slice(0, semi >= 0 ? semi : rest.length);
      body = header;
      whole = header;
    }
    blocks.push({ name: m[1], header, body, whole });
  }
  return blocks;
}

function isSecdef(header) {
  return /\bSECURITY\s+DEFINER\b/i.test(header);
}

// Strip SQL comments (line `-- …` and block `/* … */`) so a gate that survives ONLY inside a
// comment — e.g. a leftover `-- the app.is_admin() RAISE was dropped in a refactor` note — is NOT
// mistaken for a real in-body gate. Without this, a copy-paste that deletes the RAISE but keeps a
// comment referencing app.is_admin() slips past the admin-gate check (the golden-negative bug).
function stripSqlComments(sql) {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')  // block comments
    .replace(/--[^\n]*/g, ' ');          // line comments
}

// Does the file contain a REVOKE of PUBLIC or anon for public.<name>(...)? Supabase's default
// privileges grant anon EXECUTE via an EXPLICIT role grant (not via PUBLIC), so a REVOKE that names
// `anon` (or `PUBLIC, anon`) is what actually closes it — but the established repo convention is
// `REVOKE ALL ON FUNCTION public.x(...) FROM PUBLIC, anon;` which satisfies either token. We accept
// a REVOKE that mentions PUBLIC or anon for that exact function signature.
function hasRevokeAnon(content, name) {
  const re = new RegExp(
    `REVOKE\\s+(?:ALL|EXECUTE)[^;]*ON\\s+FUNCTION\\s+public\\.${name}\\s*\\([^)]*\\)[^;]*FROM[^;]*(?:PUBLIC|anon)`,
    'i',
  );
  return re.test(content);
}

/**
 * Lint one migration file. Returns an array of violation strings (empty = clean).
 * @param {string} filename
 * @param {string} content
 */
export function lintMigrationSql(filename, content) {
  const violations = [];
  for (const b of publicFunctionBlocks(content)) {
    if (!isSecdef(b.header)) continue;

    // Rule 1: same-file anon/PUBLIC REVOKE.
    if (!hasRevokeAnon(content, b.name)) {
      violations.push(
        `${filename}: public.${b.name} is SECURITY DEFINER but has NO same-file ` +
          `REVOKE ... FROM (PUBLIC|anon) — Supabase auto-grants anon EXECUTE (secdef_grant_hardening footgun).`,
      );
    }

    // Rule 2: admin RPCs must carry an in-body gate.
    if (ADMIN_RPCS.has(b.name)) {
      const hasGate = /app\.is_admin\s*\(\s*\)|app\.is_money_admin\s*\(\s*\)/.test(stripSqlComments(b.body));
      if (!hasGate) {
        violations.push(
          `${filename}: public.${b.name} is an admin RPC but its body has NO ` +
            `app.is_admin()/app.is_money_admin() gate — a copy-paste dropped the first-line RAISE.`,
        );
      }
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql')).sort();

test('every migration passes the SECDEF anon-REVOKE + admin-gate lint', () => {
  assert.ok(files.length > 0, 'expected to find migration files');
  const all = [];
  for (const f of files) {
    const content = readFileSync(join(MIGRATIONS_DIR, f), 'utf8');
    all.push(...lintMigrationSql(f, content));
  }
  assert.deepEqual(all, [], `SECDEF lint violations:\n${all.join('\n')}`);
});

test('sanity: the lint actually SEES the M8 admin SECDEF functions (not vacuously green)', () => {
  const seen = new Set();
  for (const f of files) {
    const content = readFileSync(join(MIGRATIONS_DIR, f), 'utf8');
    for (const b of publicFunctionBlocks(content)) {
      if (isSecdef(b.header)) seen.add(b.name);
    }
  }
  for (const name of ['admin_ledger_health', 'admin_open_clawback', 'money_admin_check', 'approve_clawback']) {
    assert.ok(seen.has(name), `lint must detect public.${name} as a SECDEF function`);
  }
});

test('M8 money migrations gate on is_money_admin (not is_admin) and source the hold constant', () => {
  const harden = readFileSync(join(MIGRATIONS_DIR, '20260716120000_harden_money_rpc_gates.sql'), 'utf8');
  const clawback = readFileSync(join(MIGRATIONS_DIR, '20260716140000_admin_open_clawback.sql'), 'utf8');

  // The re-gated functions must use the aal2 money predicate in their ACTUAL gate, never is_admin.
  const moneyGate = /IF\s+NOT\s*\(\s*SELECT\s+app\.is_money_admin\s*\(\s*\)\s*\)/gi;
  const adminGate = /IF\s+NOT\s*\(\s*SELECT\s+app\.is_admin\s*\(\s*\)\s*\)/i;
  assert.ok((harden.match(moneyGate) || []).length >= 2, 'harden-gates must gate BOTH RPCs on is_money_admin()');
  assert.ok(!adminGate.test(harden), 'harden-gates must NOT keep an is_admin() gate on the money RPCs');
  assert.ok(moneyGate.test(clawback), 'admin_open_clawback must gate on is_money_admin()');
  assert.ok(!adminGate.test(clawback), 'admin_open_clawback must NOT gate on is_admin()');

  // The payout-hold must come from the single-source function, never a hardcoded interval literal.
  assert.ok(/app\.payout_hold_interval\s*\(\s*\)/.test(clawback), 'the guard must use app.payout_hold_interval()');
  assert.ok(!/interval\s+'7\s*days'/i.test(clawback), 'the guard must NOT hardcode an interval \'7 days\' literal');
});

// ---------------------------------------------------------------------------
// GOLDEN NEGATIVES — prove the lint bites (would go green if the checks were no-ops).
// ---------------------------------------------------------------------------
test('golden-negative: a public SECDEF fn missing its REVOKE is FLAGGED', () => {
  const bad = `
    CREATE OR REPLACE FUNCTION public.leaky_read()
    RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path='' AS $$
      SELECT jsonb_build_object('secret', (SELECT count(*) FROM public.ledger_entries));
    $$;
    GRANT EXECUTE ON FUNCTION public.leaky_read() TO authenticated;
  `;
  const v = lintMigrationSql('99999999_bad.sql', bad);
  assert.ok(v.some((x) => /NO same-file\s+REVOKE/i.test(x)), `expected a missing-REVOKE violation, got: ${JSON.stringify(v)}`);
});

test('golden-negative: an admin RPC missing its in-body gate is FLAGGED', () => {
  const bad = `
    CREATE OR REPLACE FUNCTION public.admin_ledger_health()
    RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path='' AS $$
    DECLARE v jsonb; BEGIN
      -- OOPS: the first-line app.is_admin() RAISE gate was dropped in a refactor.
      SELECT jsonb_build_object('ok', true) INTO v; RETURN v;
    END;$$;
    REVOKE ALL ON FUNCTION public.admin_ledger_health() FROM PUBLIC, anon;
    GRANT EXECUTE ON FUNCTION public.admin_ledger_health() TO authenticated;
  `;
  const v = lintMigrationSql('99999999_bad.sql', bad);
  assert.ok(v.some((x) => /NO\s+app\.is_admin/i.test(x)), `expected a missing-gate violation, got: ${JSON.stringify(v)}`);
});

test('golden-positive: a well-formed public SECDEF fn passes clean', () => {
  const good = `
    CREATE OR REPLACE FUNCTION public.admin_ledger_health()
    RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path='' AS $$
    DECLARE v jsonb; BEGIN
      IF NOT (SELECT app.is_admin()) THEN RAISE EXCEPTION 'unauthorized' USING errcode='28000'; END IF;
      SELECT jsonb_build_object('ok', true) INTO v; RETURN v;
    END;$$;
    REVOKE ALL ON FUNCTION public.admin_ledger_health() FROM PUBLIC, anon;
    GRANT EXECUTE ON FUNCTION public.admin_ledger_health() TO authenticated;
  `;
  assert.deepEqual(lintMigrationSql('99999999_good.sql', good), []);
});

test('golden-negative: SECURITY INVOKER (or default) function is NOT required to REVOKE (only DEFINER)', () => {
  // A non-definer function runs as the caller — the anon-EXECUTE footgun does not apply, so the
  // lint must not flag it. (Guards against the lint over-reaching and being disabled as noisy.)
  const invoker = `
    CREATE OR REPLACE FUNCTION public.plain_helper()
    RETURNS int LANGUAGE sql STABLE AS $$ SELECT 1 $$;
  `;
  assert.deepEqual(lintMigrationSql('99999999_invoker.sql', invoker), []);
});
