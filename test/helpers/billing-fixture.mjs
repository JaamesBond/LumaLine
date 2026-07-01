// test/helpers/billing-fixture.mjs — shared stack-detection + fixture helpers for
// billing integration tests (M4-T3: CPC billing).
//
// This module is the DRY home for NEW billing integration tests (currently just
// cpc-billing.integration.mjs). test/billing.integration.mjs predates this module and
// keeps its own inline copies of the same pattern (stack-detection, svc, JWT minting) —
// out of scope to touch here (see the M4 Task 3/4 brief's explicit file list). If a
// future refactor consolidates both, this module is where that should land.
//
// Conventions mirrored from the existing suite:
//   - REST reads/writes go through the service-role key (test/billing.integration.mjs).
//   - Raw SQL (seeding impressions/clicks/ledger rows, calling app.* SECURITY DEFINER
//     functions that live outside the `public` schema PostgREST exposes) goes through
//     psql as the `postgres` superuser (test/payout-rails.integration.mjs).
//   - Admin-gated edge-fn calls use a locally-minted HS256 JWT for the seeded dev-admin
//     (app.admins row in supabase/seed.sql), same secret PostgREST trusts locally.

import { createHmac, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const BASE = 'http://127.0.0.1:54321';

export const REST_BASE    = `${BASE}/rest/v1`;
export const BILLING_BASE = `${BASE}/functions/v1/billing`;

const DB_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';

export const ANON =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';
export const SERVICE =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU';

const JWT_SECRET = 'super-secret-jwt-token-with-at-least-32-characters-long';

// dev-admin (app.admins row) + dev-a publisher — both from supabase/seed.sql, present on
// every `supabase db reset`. Reusing them avoids minting fresh auth.users/publishers rows
// for every test, matching test/billing.integration.mjs's own convention.
const ADMIN_USER_ID = 'a0000000-0000-4000-8000-000000000001';
export const PUB_A_PUBLISHER_ID = 'a1a1a1a1-0000-0000-0000-000000000001';

/** Mint a Supabase Auth–style HS256 JWT (same secret PostgREST trusts locally). */
function mintJwt(sub) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const head    = enc({ alg: 'HS256', typ: 'JWT' });
  const payload = enc({ role: 'authenticated', aud: 'authenticated', sub, iat: 1700000000, exp: 2000000000 });
  const sig = createHmac('sha256', JWT_SECRET).update(`${head}.${payload}`).digest('base64url');
  return `${head}.${payload}.${sig}`;
}
export const ADMIN_JWT = mintJwt(ADMIN_USER_ID);

/** Raw psql — synchronous, tuples-only/unaligned (`-tAqc`), trimmed. Throws if psql is
 * unavailable or the query errors; callers doing readiness checks should catch. */
export function psql(sql) {
  return execFileSync('psql', [DB_URL, '-tAqc', sql], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

/**
 * Service-role fetch. `resource` is either a rest/v1 path ("table?query=...", "rpc/fn")
 * or a functions/v1 path ("functions/v1/billing/charge?dry_run=true"). REST calls carry
 * the service-role key; functions/v1 calls carry the admin JWT (the billing fn's own
 * auth gate forwards the bearer to PostgREST's admin_check() RPC — a service-role JWT
 * has no app.admins row and would be rejected 403, same as test/billing.integration.mjs).
 * Returns the parsed JSON body directly; throws on a non-2xx response.
 */
export async function svc(method, resource, body) {
  const isFn = resource.startsWith('functions/v1/');
  const url  = isFn ? `${BASE}/${resource}` : `${REST_BASE}/${resource}`;
  const headers = {
    Authorization: `Bearer ${isFn ? ADMIN_JWT : SERVICE}`,
    'content-type': 'application/json',
  };
  if (!isFn) {
    headers.apikey = SERVICE;
    headers.Prefer = 'return=representation';
  }
  const resp = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let data = null;
  try { data = await resp.json(); } catch { /* empty body */ }
  if (!resp.ok) {
    throw new Error(`svc ${method} ${resource} -> HTTP ${resp.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

/** Check if the local Supabase REST API is up. */
async function isStackUp() {
  try {
    const res = await fetch(`${REST_BASE}/`, { headers: { apikey: ANON }, signal: AbortSignal.timeout(2000) });
    return res.status >= 200 && res.status < 500;
  } catch { return false; }
}
function psqlWorks() {
  try { return psql('select 1') === '1'; } catch { return false; }
}
/** Check if the billing edge function is deployed (needed for the charge tests). */
async function isBillingFnUp() {
  try {
    const res = await fetch(`${BILLING_BASE}/charge`, { method: 'OPTIONS', signal: AbortSignal.timeout(2000) });
    return res.status === 200;
  } catch { return false; }
}

const restUp = await isStackUp();
const psqlUp = restUp ? psqlWorks() : false;
const fnUp   = restUp ? await isBillingFnUp() : false;

/** True when REST + psql + the billing edge fn are all reachable — the full readiness
 * bar for the CPC billing integration suite (seeding needs psql; charging needs the fn). */
export const STACK_UP = restUp && psqlUp && fnUp;

/**
 * Seed a fresh advertiser + campaign + line_item (status active, real cpc_bid_micros) via
 * psql, and reuse the seed.sql dev-a publisher (PUB_A_PUBLISHER_ID) as the earning
 * publisher. Returns { advertiserId, campaignId, lineItemId, publisherId }. Caller owns
 * cleanup — deleting the advertiser cascades campaigns/line_items/creatives
 * (ON DELETE CASCADE), but NOT impressions/clicks/ledger_entries (see cleanupCpcFixture).
 */
export function seedAdvertiserCampaignLineItem({ is_house = false } = {}) {
  const advertiserId = randomUUID();
  const campaignId   = randomUUID();
  const lineItemId   = randomUUID();

  psql(`insert into public.advertisers (id, name, status, is_house) values
    ('${advertiserId}','cpc-test-advertiser-${advertiserId.slice(0, 8)}','active',${is_house});`);
  psql(`insert into public.campaigns (id, advertiser_id, name, status) values
    ('${campaignId}','${advertiserId}','cpc-test-campaign','active');`);
  psql(`insert into public.line_items
      (id, campaign_id, cpva_bid_micros, cpc_bid_micros, weight, status, start_at, end_at) values
    ('${lineItemId}','${campaignId}',2000,50000,1,'active', now() - interval '1 hour', now() + interval '30 days');`);

  return { advertiserId, campaignId, lineItemId, publisherId: PUB_A_PUBLISHER_ID };
}

/** Best-effort cleanup for a seedAdvertiserCampaignLineItem() + click/impression fixture. */
export function cleanupCpcFixture({ advertiserId, impressionId, clickId } = {}) {
  try {
    if (clickId) {
      psql(`delete from public.advertiser_charges where entry_group_id in
        (select entry_group_id from public.ledger_entries where source_type='click' and source_id='${clickId}');`);
      psql(`delete from public.ledger_entries where source_type='click' and source_id='${clickId}';`);
      psql(`delete from public.clicks where id='${clickId}';`);
    }
    if (impressionId) {
      psql(`delete from public.ledger_entries where source_type='impression' and source_id='${impressionId}';`);
      psql(`delete from public.impressions where id='${impressionId}';`);
    }
    if (advertiserId) {
      psql(`delete from public.advertisers where id='${advertiserId}';`); // cascades campaigns/line_items/creatives
    }
  } catch { /* best-effort */ }
}
