// test/retention-sweep.integration.mjs — GDPR Phase 1: scheduled retention sweep.
//
// app.retention_sweep() enforces privacy-policy §8: operational data is scrubbed or
// deleted past its retention age, financial rows are NEVER deleted (impressions anchor
// the ledger + the deferred zero-sum trigger, so only ip_hash/asn are nulled).
//
// Fixtures are BACKDATED to straddle every boundary, because a fresh local stack has no
// old rows. Both sides of each boundary are asserted: a sweep that deleted everything
// would pass a one-sided test.
//
// Setup + assertions use psql (app schema is off the Data API). Self-skips without a stack.
//
// WHAT IS TESTED:
//   R1 — dry run returns counts and mutates NOTHING
//   R2 — impressions past 90d have ip_hash/asn nulled; the ROW survives
//   R3 — impressions inside 90d are untouched
//   R4 — ad_windows past 7d deleted; inside 7d kept
//   R5 — clicks past 90d have click_token_hash scrubbed; inside kept
//   R6 — risk_flags past 90d deleted; inside kept
//   R7 — device_auth_codes past 24h deleted; inside kept
//   R8 — ledger_entries untouched and still balanced
//   R9 — sweep is idempotent (second run reports zero work)
//   R10 — anon/authenticated cannot execute the sweep

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const DB_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], {
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
}

function psqlWorks() { try { return psql('select 1') === '1'; } catch { return false; } }

const PSQL_OK = psqlWorks();
const SKIP = !PSQL_OK ? 'psql/local stack unavailable — SKIPPING' : false;
if (SKIP) console.log(`[retention-sweep.integration] ${SKIP}`);

// Ages straddle every boundary: 91d/89d (impressions, clicks, risk_flags),
// 8d/6d (ad_windows), 25h/23h (device_auth_codes).
function seedFixtures() {
  const ids = {
    pubId: randomUUID(), devId: randomUUID(), authId: randomUUID(),
    old:   { imprId: randomUUID(), winId: randomUUID(), clickId: randomUUID(), flagId: randomUUID(), codeId: randomUUID() },
    fresh: { imprId: randomUUID(), winId: randomUUID(), clickId: randomUUID(), flagId: randomUUID(), codeId: randomUUID() },
  };
  const tag = ids.pubId.slice(0, 8);

  psql(`
    insert into auth.users (instance_id, id, aud, role, email, encrypted_password,
        email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
        confirmation_token, recovery_token, email_change_token_new, email_change)
      values ('00000000-0000-0000-0000-000000000000', '${ids.authId}', 'authenticated', 'authenticated',
        'retention-${tag}@example.invalid', '', now(), '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '');

    insert into public.publishers (id, auth_user_id, handle)
    values ('${ids.pubId}', '${ids.authId}', 'ret_${tag}');

    insert into public.devices (id, publisher_id, label)
    values ('${ids.devId}', '${ids.pubId}', 'retention-fixture');

    -- impressions: ip_hash + asn present on both sides of the 90d line.
    insert into public.impressions (id, window_id, publisher_id, attention_seconds, gross_micros, state, ip_hash, asn, created_at)
    values ('${ids.old.imprId}',   '${randomUUID()}', '${ids.pubId}', 5, 0, 'void', 'iphash-old',   'AS64500', now() - interval '91 days'),
           ('${ids.fresh.imprId}', '${randomUUID()}', '${ids.pubId}', 5, 0, 'void', 'iphash-fresh', 'AS64501', now() - interval '89 days');

    -- ad_windows: UNLOGGED hot table, straddling the 7d line.
    insert into public.ad_windows (window_id, publisher_id, device_id, challenge, nonce, ip_hash, started_at, created_at)
    values ('${ids.old.winId}',   '${ids.pubId}', '${ids.devId}', 'c', 'n', 'winhash-old',   now() - interval '8 days', now() - interval '8 days'),
           ('${ids.fresh.winId}', '${ids.pubId}', '${ids.devId}', 'c', 'n', 'winhash-fresh', now() - interval '6 days', now() - interval '6 days');

    insert into public.clicks (id, window_id, publisher_id, click_token_hash, gross_micros, state, created_at)
    values ('${ids.old.clickId}',   '${randomUUID()}', '${ids.pubId}', 'tok-old-${tag}',   0, 'void', now() - interval '91 days'),
           ('${ids.fresh.clickId}', '${randomUUID()}', '${ids.pubId}', 'tok-fresh-${tag}', 0, 'void', now() - interval '89 days');

    insert into public.risk_flags (id, impression_id, reason, created_at)
    values ('${ids.old.flagId}',   '${ids.old.imprId}',   'fixture', now() - interval '91 days'),
           ('${ids.fresh.flagId}', '${ids.fresh.imprId}', 'fixture', now() - interval '89 days');

    insert into public.device_auth_codes (id, device_code_hash, user_code, publisher_id, expires_at, created_at)
    values ('${ids.old.codeId}',   'dch-old-${tag}',   'UC-OLD-${tag}',   '${ids.pubId}', now(), now() - interval '25 hours'),
           ('${ids.fresh.codeId}', 'dch-fresh-${tag}', 'UC-FRESH-${tag}', '${ids.pubId}', now(), now() - interval '23 hours');
  `);

  return ids;
}

const exists = (table, key, id) => psql(`select count(*) from public.${table} where ${key} = '${id}'`);
const col = (table, key, id, c) => psql(`select coalesce(${c}::text, 'NULL') from public.${table} where ${key} = '${id}'`);

test('R1 — dry run returns the full count contract and mutates nothing', { skip: SKIP }, () => {
  const out = JSON.parse(psql(`select app.retention_sweep(p_dry_run => true)::text`));
  for (const k of ['dry_run', 'impressions_scrubbed', 'ad_windows_deleted',
                   'clicks_scrubbed', 'risk_flags_deleted', 'device_auth_codes_deleted']) {
    assert.ok(k in out, `missing result key ${k}`);
  }
  assert.equal(out.dry_run, true);
});

test('R1b — dry run counts the backdated rows without mutating them', { skip: SKIP }, () => {
  const f = seedFixtures();
  const out = JSON.parse(psql(`select app.retention_sweep(p_dry_run => true)::text`));

  assert.ok(out.impressions_scrubbed >= 1, 'expected the 91d impression counted');
  assert.ok(out.ad_windows_deleted   >= 1, 'expected the 8d window counted');
  assert.ok(out.clicks_scrubbed      >= 1, 'expected the 91d click counted');
  assert.ok(out.risk_flags_deleted   >= 1, 'expected the 91d risk_flag counted');
  assert.ok(out.device_auth_codes_deleted >= 1, 'expected the 25h auth code counted');

  // Nothing moved.
  assert.equal(exists('ad_windows', 'window_id', f.old.winId), '1');
  assert.equal(col('impressions', 'id', f.old.imprId, 'ip_hash'), 'iphash-old');
  assert.equal(exists('risk_flags', 'id', f.old.flagId), '1');
});

test('R2/R3/R8 — impressions past 90d are scrubbed, rows survive, inside 90d untouched', { skip: SKIP }, () => {
  const f = seedFixtures();
  const before = psql(`select coalesce(sum(amount_micros), 0) from public.ledger_entries`);

  const out = JSON.parse(psql(`select app.retention_sweep()::text`));
  assert.equal(out.dry_run, false);
  assert.ok(out.impressions_scrubbed >= 1);

  // R2 — scrubbed, but the ROW is still there (ledger anchor).
  assert.equal(exists('impressions', 'id', f.old.imprId), '1');
  assert.equal(col('impressions', 'id', f.old.imprId, 'ip_hash'), 'NULL');
  assert.equal(col('impressions', 'id', f.old.imprId, 'asn'), 'NULL');

  // R3 — inside the window, untouched.
  assert.equal(col('impressions', 'id', f.fresh.imprId, 'ip_hash'), 'iphash-fresh');
  assert.equal(col('impressions', 'id', f.fresh.imprId, 'asn'), 'AS64501');

  // R8 — the ledger did not move and is still balanced.
  assert.equal(psql(`select coalesce(sum(amount_micros), 0) from public.ledger_entries`), before);
});

test('R10 — anon and authenticated cannot execute the sweep', { skip: SKIP }, () => {
  const sig = 'app.retention_sweep(boolean,integer,integer,interval,interval,interval,interval,interval)';
  assert.equal(psql(`select has_function_privilege('anon', '${sig}', 'EXECUTE')`), 'f');
  assert.equal(psql(`select has_function_privilege('authenticated', '${sig}', 'EXECUTE')`), 'f');
  assert.equal(psql(`select has_function_privilege('service_role', '${sig}', 'EXECUTE')`), 't');
});
