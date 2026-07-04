#!/usr/bin/env node
// LumaLine window-protocol load harness (M6-T2) — measures the write ceiling of the hot path
// (window_open -> window_beat×N -> close_window) under concurrency, plus latency percentiles and an
// error taxonomy. Drives PostgREST RPCs as authenticated synthetic devices, honest cadence.
//
// ⚠️ LOCAL-ONLY BY HARD GUARD. Running load against prod would pollute M5's live windows/impressions
// and confound the first-charge reconcile — so this REFUSES any target that looks like prod
// (ref prmsonskzrubqsazmpwd) or any non-localhost host unless LOAD_ALLOW_NONLOCAL=1 is set for a
// non-prod remote you explicitly own. Default target is the local Supabase stack.
//
// PREREQUISITE (run step, not build step): `supabase start`, then export the local keys from
// `supabase status` (LOAD_SERVICE_KEY / LOAD_ANON_KEY / LOAD_JWT_SECRET) or accept the well-known
// local demo defaults below. This file is an ops tool; it is NOT shipped to npm.
//
//   node scripts/load/harness.mjs --users 200 --duration 30 --beats 3
//   node scripts/load/harness.mjs --users 2000 --duration 60          # push toward the ceiling
import { createHmac } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { buildChain } from './lib/hmac-chain.mjs';
import { summarize, renderSummary } from './lib/metrics.mjs';

const PROD_REF = 'prmsonskzrubqsazmpwd';
const env = process.env;

// ---- config (local defaults; override via env) ----------------------------------------------
const BASE = env.LOAD_BASE || 'http://127.0.0.1:54321';
// Well-known local Supabase demo credentials (safe: they only work against a local stack).
const ANON_KEY = env.LOAD_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlLWRlbW8iLCJpYXQiOjE2NDE3NjkyMDAsImV4cCI6MTc5OTUzNTYwMH0.dc_X5iR_VP_qT0zsiyj_I_OZ2T9FtRU2BBNWN8Bu4GE';
const SERVICE_KEY = env.LOAD_SERVICE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UtZGVtbyIsImlhdCI6MTY0MTc2OTIwMCwiZXhwIjoxNzk5NTM1NjAwfQ.DaYlNEoUrrEn2Ig7tqibS-PHK5vgusbcbo7X36XVt4Q';
const JWT_SECRET = env.LOAD_JWT_SECRET || 'super-secret-jwt-token-with-at-least-32-characters-long';

const args = process.argv.slice(2);
const flag = (name, def) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : def; };
const USERS = parseInt(flag('users', '50'), 10);       // concurrent virtual devices
const DURATION_S = parseInt(flag('duration', '20'), 10);
const BEATS = Math.max(3, parseInt(flag('beats', '3'), 10)); // >=3 to credit
const BEAT_SPACING_MS = 600;   // > 500ms server anti-batch minimum
const DWELL_MS = 5000;         // server requires elapsed >= dwell_ms to credit

// ---- hard safety guard ------------------------------------------------------------------------
function assertSafeTarget(base) {
  if (base.includes(PROD_REF)) {
    console.error(`FATAL: target ${base} is the PROD project (${PROD_REF}). Load against prod is forbidden.`);
    process.exit(3);
  }
  let host;
  try { host = new URL(base).hostname; } catch { console.error(`FATAL: bad LOAD_BASE ${base}`); process.exit(3); }
  const isLocal = host === '127.0.0.1' || host === 'localhost' || host === '::1';
  if (!isLocal && env.LOAD_ALLOW_NONLOCAL !== '1') {
    console.error(`FATAL: ${host} is not local. Set LOAD_ALLOW_NONLOCAL=1 ONLY for a non-prod remote you own.`);
    process.exit(3);
  }
}

// ---- helpers ----------------------------------------------------------------------------------
const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function mintDeviceJWT({ sub, publisher_id, device_id }) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify({ sub, role: 'authenticated', publisher_id, device_id, iat: now, exp: now + 3600 }));
  const sig = b64url(createHmac('sha256', JWT_SECRET).update(`${header}.${payload}`).digest());
  return `${header}.${payload}.${sig}`;
}

async function rpc(fn, body, jwt) {
  const t0 = performance.now();
  try {
    const r = await fetch(`${BASE}/rest/v1/rpc/${fn}`, {
      method: 'POST',
      headers: { apikey: ANON_KEY, Authorization: `Bearer ${jwt}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    const ms = performance.now() - t0;
    if (!r.ok) {
      let code = `http_${r.status}`;
      try { const j = await r.json(); if (j.code || j.message) code = j.code || j.message.slice(0, 40); } catch {}
      return { ok: false, ms, code };
    }
    return { ok: true, ms, body: await r.json() };
  } catch (e) {
    return { ok: false, ms: performance.now() - t0, code: `net:${(e.message || 'err').slice(0, 30)}` };
  }
}

async function svcInsert(table, row) {
  const r = await fetch(`${BASE}/rest/v1/${table}`, {
    method: 'POST',
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
    body: JSON.stringify(row),
  });
  if (!r.ok) throw new Error(`insert ${table}: ${r.status} ${(await r.text()).slice(0, 160)}`);
  return (await r.json())[0];
}

// Create auth user -> publisher -> device (publishers.auth_user_id is NOT NULL). Returns a device
// descriptor with a ready-to-use device JWT. Uses the GoTrue admin API for the auth user.
async function seedDevice(i) {
  const email = `load-${i}-${Date.now()}@lumaline.invalid`;
  const ur = await fetch(`${BASE}/auth/v1/admin/users`, {
    method: 'POST',
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, email_confirm: true, password: `Load!${i}!${Math.floor(performance.now())}` }),
  });
  if (!ur.ok) throw new Error(`create auth user: ${ur.status} ${(await ur.text()).slice(0, 160)}`);
  const authUser = await ur.json();
  const pub = await svcInsert('publishers', { auth_user_id: authUser.id, handle: `load_${i}_${authUser.id.slice(0, 8)}`, status: 'active' });
  const dev = await svcInsert('devices', { publisher_id: pub.id, label: `load-${i}`, attested: true });
  return { publisher_id: pub.id, device_id: dev.id, jwt: mintDeviceJWT({ sub: authUser.id, publisher_id: pub.id, device_id: dev.id }) };
}

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

// One virtual user: open -> honest beats -> close, repeatedly until the deadline. Records samples.
async function runVU(device, deadline, samples) {
  while (performance.now() < deadline) {
    const open = await rpc('window_open', { p_activity_snapshot: null }, device.jwt);
    samples.push({ op: 'open', ok: open.ok, ms: open.ms, code: open.code });
    if (!open.ok || !open.body?.window_id) { await sleep(50); continue; }
    const { window_id, challenge } = open.body;
    const chain = buildChain({ windowId: window_id, challenge, count: BEATS });
    const openedAt = performance.now();
    for (const beat of chain) {
      await sleep(BEAT_SPACING_MS);
      const res = await rpc('window_beat', { p_window_id: window_id, p_seq: beat.seq, p_hmac: beat.hmac, p_activity_delta: beat.activity }, device.jwt);
      samples.push({ op: 'beat', ok: res.ok, ms: res.ms, code: res.code });
    }
    const remaining = DWELL_MS - (performance.now() - openedAt);
    if (remaining > 0) await sleep(remaining + 20);
    const close = await rpc('close_window', { p_window_id: window_id }, device.jwt);
    samples.push({ op: 'close', ok: close.ok, ms: close.ms, code: close.code });
  }
}

async function main() {
  assertSafeTarget(BASE);
  console.error(`Load harness → ${BASE}  users=${USERS} duration=${DURATION_S}s beats=${BEATS}`);
  console.error('Seeding synthetic devices…');
  const devices = [];
  for (let i = 0; i < USERS; i++) {
    try { devices.push(await seedDevice(i)); }
    catch (e) { console.error(`  seed ${i} failed: ${e.message}`); }
  }
  if (devices.length === 0) { console.error('FATAL: seeded 0 devices — is the local stack up? (supabase start)'); process.exit(4); }
  console.error(`Seeded ${devices.length}/${USERS} devices. Running…`);

  const samples = [];
  const startedAt = performance.now();
  const deadline = startedAt + DURATION_S * 1000;
  await Promise.all(devices.map((d) => runVU(d, deadline, samples)));
  const durationMs = performance.now() - startedAt;

  const report = summarize(samples, durationMs);
  console.log(renderSummary(report));
  const out = `/tmp/lumaline-load-${Math.floor(Date.now() / 1000)}.json`;
  writeFileSync(out, JSON.stringify({ config: { BASE, USERS, DURATION_S, BEATS }, report }, null, 2));
  console.error(`\nfull report → ${out}`);
}

main().catch((e) => { console.error('harness error:', e.message); process.exit(1); });
