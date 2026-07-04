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
import {
  writeFileSync, readFileSync, unlinkSync, mkdirSync, chmodSync, renameSync,
  openSync, closeSync, statSync,
} from 'node:fs';
import path from 'node:path';
import {
  DEVICE_TOKEN, AUTH_BASE, STRIPE_CONNECT_BASE, TOKEN_REFRESH_SKEW_MS, FETCH_TIMEOUT_MS,
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

// --- single-writer refresh lock -------------------------------------------------------
// The refresh token is SINGLE-USE (the server rotates its stored hash on every redeem). But the
// statusline runs as a FRESH process every ~1s tick (refreshInterval:1), across every Claude Code
// session sharing this one token file. Near expiry, multiple overlapping ticks would each read the
// SAME refresh token and redeem it in parallel — one wins, the rest get invalid_grant, and if their
// writes interleave the file is left holding a dead token → the client silently falls to the
// anonymous sentinel feed FOREVER (house-only, never earns) until a manual re-login. An OS-atomic
// O_EXCL lockfile guarantees only ONE process refreshes at a time; the others keep using the
// still-valid access token (it does not actually expire until msLeft <= 0). A crashed holder can't
// wedge us shut: a lock older than LOCK_STALE_MS is reclaimed. Real wall-clock (Date.now) is used
// for staleness — it tracks the lockfile's real mtime, independent of the injectable token clock.
const LOCK_STALE_MS = 15_000; // > FETCH_TIMEOUT_MS (3s); reclaim a lock abandoned by a dead tick

function acquireRefreshLock(lockFile) {
  try { closeSync(openSync(lockFile, 'wx')); return true; } // atomic create-if-absent
  catch {
    try {
      if (Date.now() - statSync(lockFile).mtimeMs > LOCK_STALE_MS) {
        try { unlinkSync(lockFile); } catch { /* someone else reclaimed it first */ }
        try { closeSync(openSync(lockFile, 'wx')); return true; } catch { return false; }
      }
    } catch { /* lock vanished between calls — treat as still-held; caller skips this tick */ }
    return false;
  }
}
function releaseRefreshLock(lockFile) { try { unlinkSync(lockFile); } catch { /* already gone */ } }

// --- hot path: a valid access token, or null (anonymous) ------------------------------
// Never throws. Resolves to null ONLY when there is genuinely no usable credential (logged out, or
// an expired access token with no working refresh) — then the statusline cleanly runs the anonymous
// sentinel feed (gross=0). A still-valid access token is ALWAYS returned rather than dropped to
// anonymous, even if a refresh attempt fails, so a transient refresh error never spuriously logs the
// publisher out mid-session. Refreshes (rotating the single-use refresh token) happen under a lock so
// concurrent ticks/sessions cannot burn the token in a race (see acquireRefreshLock).
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

  // Needs a refresh. Serialize so only one process redeems the single-use token.
  const lockFile = `${file}.lock`;
  if (!acquireRefreshLock(lockFile)) {
    return msLeft > 0 ? t.access_token : null;          // another tick is refreshing — don't race it
  }
  try {
    // Re-read under the lock: a process that held it just before us may have already refreshed.
    const cur = loadToken(file) ?? t;
    const curExp = cur.exp ?? decodeJwtExp(cur.access_token);
    const curLeft = curExp != null ? curExp * 1000 - now : -1;
    if (curLeft > skewMs) return cur.access_token;      // someone already refreshed — use the new token
    if (!cur.refresh_token) return curLeft > 0 ? cur.access_token : null;

    const { ok, data } = await postJson(fetchImpl, `${authBase}/device/refresh`, { refresh_token: cur.refresh_token }, { timeoutMs });
    if (!ok || !data?.access_token) return curLeft > 0 ? cur.access_token : null; // rejected; use current if still valid
    const next = shapeToken(data, now, cur);
    saveToken(file, next);
    return next.access_token;
  } catch {
    return msLeft > 0 ? t.access_token : null;          // hot path never throws; keep using a valid token
  } finally {
    releaseRefreshLock(lockFile);
  }
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
      out('    (Run `lumaline connect` to receive weekly automatic payouts, €1 minimum.)');
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
  out('  Paid out automatically each week once you `lumaline connect` your bank (€1 minimum).');
  out('  Until then these balances are informational. Anonymous/revoked devices accrue €0.');
  return data;
}

// --- connect (self-serve bank onboarding) ----------------------------------------------
export async function connect({
  file = DEVICE_TOKEN, connectBase = STRIPE_CONNECT_BASE, fetchImpl = fetch,
  now = Date.now(), timeoutMs = FETCH_TIMEOUT_MS, out = console.log,
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
