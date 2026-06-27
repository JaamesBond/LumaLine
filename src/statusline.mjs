#!/usr/bin/env node
// lumaline status-line client (canonical). Invoked by Claude Code each tick and on
// the refreshInterval timer: reads Claude's JSON on stdin, advances the server-verified
// window protocol by one step (open/beat/close), writes one labeled line to stdout, and
// mirrors every server call to the local audit log. Thin glue over src/client/window.mjs.
//
// Trust enforcement (restored/added after the Phase 0 gate):
//   - SIGNED CONTENT ONLY: the ad served by /window/open is ed25519-signed; we verify it
//     against the bundled/trusted public key and refuse (audit verify_fail, show base) on
//     failure — the client never displays or makes clickable any unverified content.
//   - the clickable URL is sanitized (absolute http(s), no control chars) before being
//     embedded in an OSC-8 escape, so a feed cannot inject terminal control sequences.
//   - only a coarse activity bucket leaves the machine (see client/window.mjs); raw
//     cost/token values stay local.
import { readFileSync, writeFileSync, appendFileSync, mkdirSync } from 'node:fs';
import {
  LUMALINE_HOME, PUB, STATE, AUDIT, FEED_BASE,
  FETCH_TIMEOUT_MS, COOLDOWN_MS, HYPERLINKS, SHOW_URL,
} from './config.mjs';
import { step } from './client/window.mjs';
import { verifyData } from './lib/crypto.mjs';

mkdirSync(LUMALINE_HOME, { recursive: true });
const now = Date.now();

const loadJson = (p, def) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return def; } };
const saveJson = (p, o) => writeFileSync(p, JSON.stringify(o));
const audit = (evt) => appendFileSync(AUDIT, JSON.stringify({ ts: now, ...evt }) + '\n');

// OSC 8 hyperlink: makes the wrapped text clickable in supporting terminals.
const osc8 = (url, text) => `\x1b]8;;${url}\x07${text}\x1b]8;;\x07`;

// A control char in the URL could break out of the OSC-8 sequence and inject terminal
// codes. Detect via char codes (keeps this source file ASCII-only).
function hasControlChars(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}
// Only ever emit a hyperlink for a validated absolute http(s) URL with no control chars.
function safeClickUrl(u) {
  if (typeof u !== 'string' || hasControlChars(u)) return null;
  try { const x = new URL(u); return (x.protocol === 'http:' || x.protocol === 'https:') ? u : null; }
  catch { return null; }
}

// Trusted verify key (bundled in prod, dev key under LUMALINE_HOME). Read once.
const pubPem = (() => { try { return readFileSync(PUB); } catch { return null; } })();
const verifyAd = (adData, sig) =>
  (pubPem && typeof adData === 'string' && typeof sig === 'string') ? verifyData(adData, sig, pubPem) : false;

function readClaudeStdin() {
  let raw = '';
  try { raw = readFileSync(0, 'utf8'); } catch { /* no stdin (tty) */ }
  try { return JSON.parse(raw); } catch { return {}; }
}

// Coarse "real work happening" value. Kept as a raw number for LOCAL delta detection only;
// the client never sends it (only the bucketed delta leaves the machine). null => idle.
function activitySignal(claude) {
  const x = claude?.cost?.total_cost_usd ?? claude?.context_window?.total_input_tokens;
  return typeof x === 'number' ? x : null;
}

function baseStatus(claude) {
  const model = claude?.model?.display_name ?? 'Claude';
  const dir = (claude?.workspace?.current_dir ?? '').replace(process.env.HOME ?? '\0', '~');
  return (dir ? `${model} · ${dir}` : model) || 'lumaline: idle';
}

async function post(p, body) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(`${FEED_BASE}${p}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body), signal: ctrl.signal,
    });
    let out = {};
    try { out = await res.json(); } catch { /* non-JSON */ }
    // Mirror the real outcome to the audit log (the local trust mirror).
    audit({ event: 'post', path: p, seq: body.seq, ok: res.ok, credited: out?.credited, reason: out?.reason });
    return out;
  } finally { clearTimeout(timer); }
}

async function main() {
  const claude = readClaudeStdin();
  const base = baseStatus(claude);
  const activity = activitySignal(claude);
  const state = loadJson(STATE, null);
  let r;
  try {
    r = await step({ state, now, activity, post, cfg: { cooldownMs: COOLDOWN_MS, verifyAd } });
  } catch (e) {
    audit({ event: 'step_error', message: e && e.message });
    return base;   // backend unreachable / error -> graceful base status, nothing billed
  }
  if (r.verifyFail) { audit({ event: 'verify_fail' }); saveJson(STATE, null); return base; }
  saveJson(STATE, r.state);
  if (!r.status) return base;
  // The labeled line is the hyperlink (clean text, no raw URL by default; "sponsored" stays —
  // honest-disclosure invariant). OSC-8 makes the whole line clickable where Claude Code forwards
  // it (IDE terminals). On a standalone terminal that passthrough is broken upstream (#26356), so
  // LUMALINE_SHOW_URL=1 appends the plain dest URL as text — the terminal's own URL detection
  // (kitty ctrl+click / foot url-mode) can then open it.
  const url = r.clickUrl ? safeClickUrl(r.clickUrl) : null;
  const line = (url && SHOW_URL) ? `${r.status}  ${url}` : r.status;
  return (url && HYPERLINKS) ? osc8(url, line) : line;
}

main()
  .then((line) => process.stdout.write(line + '\n'))
  .catch(() => process.stdout.write('lumaline: idle\n'));
