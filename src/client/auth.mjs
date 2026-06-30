// src/client/auth.mjs — the publisher credential store + RFC 8628 device-code login client.
//
// ZERO runtime deps, Node built-ins only (the supply-chain invariant). Everything that does
// I/O (fetch, the clock, stdout, sleep) is injected so the whole module is hermetically
// unit-testable without a network or a real keychain (see test/client-auth.test.mjs).
//
// CREDENTIAL AT REST — why a 0600 file, not the OS keychain (yet):
//   The status-line client runs as a FRESH process every Claude Code tick (~1/s). It must read
//   the access token on that hot path, so the store has to be a cheap local read; spawning a
//   keychain helper (`security` / `secret-tool` / `cmdkey`) per tick is not viable. We therefore
//   store the credential as a JSON file under LUMALINE_HOME with mode 0600 (owner-only) — the
//   same pattern gh/npm/aws CLIs use. The token is a SHORT-LIVED bearer (access TTL ~1h) and is
//   instantly revocable server-side (the window RPCs re-check devices.revoked_at every call), so
//   a stolen file is bounded in both time and effect. Hardening the at-rest store with the OS
//   keychain (keeping the hot-path read cheap, e.g. a cached unlock) is a tracked follow-up.
//   The token is NEVER written to the audit log and never echoed.
import { writeFileSync, readFileSync, unlinkSync, mkdirSync, chmodSync, renameSync } from 'node:fs';
import path from 'node:path';
import {
  DEVICE_TOKEN, AUTH_BASE, TOKEN_REFRESH_SKEW_MS, FETCH_TIMEOUT_MS,
} from '../config.mjs';

// --- credential store (0600 file) -----------------------------------------------------
export function saveToken(file = DEVICE_TOKEN, obj) {
  const dir = path.dirname(file);
  mkdirSync(dir, { recursive: true });
  // Atomic write: a sibling temp file then rename over the target. The statusline rewrites this
  // on the per-tick hot path when it rotates the refresh token near expiry, and a refresh can run
  // up to FETCH_TIMEOUT_MS (longer than one ~1s tick) — so an in-place write risks a crash or an
  // overlapping tick leaving a truncated, unparseable file that would silently log the publisher
  // out (and lose the rotated refresh token). rename is atomic on the same filesystem; a reader
  // always sees a complete old-or-new file.
  const tmp = path.join(dir, `.device-token.${process.pid}.tmp`);
  writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
  try { chmodSync(tmp, 0o600); } catch { /* best-effort on platforms without POSIX modes */ }
  renameSync(tmp, file);
}

export function loadToken(file = DEVICE_TOKEN) {
  try { return JSON.parse(readFileSync(file, 'utf8')); } catch { return null; }
}

export function clearToken(file = DEVICE_TOKEN) {
  try { unlinkSync(file); } catch { /* already gone */ }
}

// Read the `exp` claim WITHOUT verifying the signature (the server is the authority; we only
// need to know when to refresh). Returns the exp in seconds, or null.
export function decodeJwtExp(jwt) {
  try {
    const seg = String(jwt).split('.')[1];
    if (!seg) return null;
    const claims = JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));
    return typeof claims.exp === 'number' ? claims.exp : null;
  } catch { return null; }
}

// --- bounded fetch (injectable) -------------------------------------------------------
async function postJson(fetchImpl, url, body, { timeoutMs = FETCH_TIMEOUT_MS, bearer } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
      body: JSON.stringify(body ?? {}),
      signal: ctrl.signal,
    });
    let data = {};
    try { data = await res.json(); } catch { /* non-JSON */ }
    return { ok: res.ok, status: res.status, data };
  } finally { clearTimeout(timer); }
}

// Shape a server token reply (+ optional carry-over from the prior stored token) into the
// stored credential object. exp prefers the JWT's own claim, else now + expires_in.
function shapeToken(data, nowMs, prior = {}) {
  const exp = decodeJwtExp(data.access_token)
    ?? (data.expires_in ? Math.floor(nowMs / 1000) + Number(data.expires_in) : null);
  return {
    access_token: data.access_token,
    refresh_token: data.refresh_token ?? prior.refresh_token ?? null,
    publisher_id: data.publisher_id ?? prior.publisher_id ?? null,
    device_id: data.device_id ?? prior.device_id ?? null,
    handle: data.handle ?? prior.handle ?? null,
    exp,
  };
}

// --- hot path: a valid access token, or null (anonymous) ------------------------------
// Never throws — a logged-out install, an expired token with no usable refresh, or any network
// error all resolve to null so the statusline cleanly falls back to the anonymous sentinel feed
// (gross=0). Refreshes (and rotates the refresh token) only inside the skew window.
export async function getValidAccessToken({
  file = DEVICE_TOKEN, now = Date.now(), fetchImpl = fetch, authBase = AUTH_BASE,
  skewMs = TOKEN_REFRESH_SKEW_MS, timeoutMs = FETCH_TIMEOUT_MS,
} = {}) {
  const t = loadToken(file);
  if (!t || !t.access_token) return null;
  const exp = t.exp ?? decodeJwtExp(t.access_token);
  const msLeft = exp != null ? exp * 1000 - now : -1;

  if (msLeft > skewMs) return t.access_token;          // comfortably valid — no network
  if (!t.refresh_token) return msLeft > 0 ? t.access_token : null; // can't refresh; use if still valid

  try {
    const { ok, data } = await postJson(fetchImpl, `${authBase}/device/refresh`, { refresh_token: t.refresh_token }, { timeoutMs });
    if (!ok || !data?.access_token) return null;
    const next = shapeToken(data, now, t);
    saveToken(file, next);
    return next.access_token;
  } catch { return null; }                              // hot path never throws
}

// --- login (RFC 8628 device-code) -----------------------------------------------------
const RETRYABLE = new Set(['authorization_pending', 'slow_down']);
// Login is interactive (a human is approving in a browser), NOT the per-tick hot path, so it gets a
// far more generous request timeout than FETCH_TIMEOUT_MS (3s, tuned for the statusline). A cold
// edge-function start can exceed 3s; using the hot-path timeout here would abort a poll and, before
// the fix below, crash the whole login on a single transient blip.
const LOGIN_TIMEOUT_MS = 15_000;

export async function login({
  file = DEVICE_TOKEN, authBase = AUTH_BASE, fetchImpl = fetch,
  out = console.log, sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  label, clientVersion, timeoutMs = LOGIN_TIMEOUT_MS,
} = {}) {
  const start = await postJson(fetchImpl, `${authBase}/device/code`, { label, client_version: clientVersion }, { timeoutMs });
  if (!start.ok || !start.data?.device_code) {
    throw new Error(`could not start login (HTTP ${start.status}${start.data?.error ? ': ' + start.data.error : ''})`);
  }
  const { device_code, user_code, verification_uri, verification_uri_complete, expires_in } = start.data;
  let intervalMs = Math.max(Number(start.data.interval ?? 5), 0) * 1000;

  out('');
  out('  To authorize this device, open:');
  out(`    ${verification_uri}`);
  out('  and enter the code:');
  out(`    ${user_code}`);
  if (verification_uri_complete) out(`  (or open directly: ${verification_uri_complete})`);
  // Disclose what leaves the machine: the only identifying value here is the device label, which
  // defaults to the host name (`lumaline login --label <name>` to override). Transparency is the
  // product thesis — the developer should see what their account will store before approving.
  if (label) out(`  This device will be registered on your account as: "${label}".`);
  out('');
  out('  Sign in there, then this will continue automatically. Ctrl-C to cancel.');

  const deadline = Date.now() + (Number(expires_in) > 0 ? Number(expires_in) * 1000 : 600_000);
  while (Date.now() < deadline) {
    await sleep(intervalMs);
    // A transient network error or request timeout during the (potentially minutes-long) poll must
    // NOT crash login — just keep polling until the code's deadline. Only an explicit server error
    // (below) hard-fails. Without this, one slow poll throws AbortError straight out of login().
    let poll;
    try {
      poll = await postJson(fetchImpl, `${authBase}/device/token`, { device_code, label, client_version: clientVersion }, { timeoutMs });
    } catch { continue; }
    if (poll.ok && poll.data?.access_token) {
      const tok = shapeToken(poll.data, Date.now());
      saveToken(file, tok);
      out(`\n  ✓ Logged in as ${tok.handle ?? tok.publisher_id}. Earnings now attribute to you.`);
      out('    (Payouts begin only at the production go-live; until then balances are informational.)');
      return tok;
    }
    const err = poll.data?.error;
    if (err === 'slow_down') { intervalMs += 5_000; continue; }
    if (RETRYABLE.has(err)) continue;
    throw new Error(`login failed: ${err || 'HTTP ' + poll.status}`);
  }
  throw new Error('login failed: expired_token (the code expired before approval)');
}

// --- logout (clear local + best-effort server revoke) ---------------------------------
export async function logout({
  file = DEVICE_TOKEN, authBase = AUTH_BASE, fetchImpl = fetch, out = console.log, timeoutMs = FETCH_TIMEOUT_MS,
} = {}) {
  const t = loadToken(file);
  if (t?.access_token) {
    try { await postJson(fetchImpl, `${authBase}/device/logout`, { device_id: t.device_id }, { bearer: t.access_token, timeoutMs }); }
    catch { /* revoke is best-effort; the local token is cleared regardless */ }
  }
  clearToken(file);
  out('Logged out. This install now runs as the anonymous sentinel (gross=0, never billed).');
}

// --- earnings (transparent read) ------------------------------------------------------
const eur = (micros) => '€' + (Number(micros || 0) / 1_000_000).toFixed(2);

export async function earnings({
  file = DEVICE_TOKEN, authBase = AUTH_BASE, fetchImpl = fetch, out = console.log,
  now = Date.now(), timeoutMs = FETCH_TIMEOUT_MS,
} = {}) {
  const token = await getValidAccessToken({ file, authBase, fetchImpl, now, timeoutMs });
  if (!token) {
    out('Not logged in. Run `lumaline login` to attribute earnings to your account.');
    return null;
  }
  const { ok, status, data } = await postJson(fetchImpl, `${authBase}/earnings`, {}, { bearer: token, timeoutMs });
  if (!ok) { out(`Could not read earnings (HTTP ${status}${data?.error ? ': ' + data.error : ''}).`); return null; }
  const bal = data?.balance ?? {};
  out('Earnings (transparent ledger — all amounts in EUR):');
  out(`  balance   : ${eur(bal.balance_micros)}   (earned ${eur(bal.earned_micros)}, paid ${eur(bal.paid_micros)}, reversed ${eur(bal.reversed_micros)})`);
  const windows = Array.isArray(data?.windows) ? data.windows : [];
  out(`  windows   : ${windows.length} cleared/booked impression-window(s) on record`);
  out('');
  out('  Note: earnings ACCRUE now but real payouts begin only at the production go-live.');
  out('  Until then these balances are informational. Anonymous/revoked devices accrue €0.');
  return data;
}

// --- doctor helper --------------------------------------------------------------------
export function authStatus({ file = DEVICE_TOKEN, now = Date.now() } = {}) {
  const t = loadToken(file);
  if (!t || !t.access_token) return { loggedIn: false };
  const exp = t.exp ?? decodeJwtExp(t.access_token);
  return {
    loggedIn: true,
    handle: t.handle ?? null,
    publisherId: t.publisher_id ?? null,
    deviceId: t.device_id ?? null,
    expiresInS: exp != null ? Math.max(0, Math.round(exp - now / 1000)) : null,
  };
}
