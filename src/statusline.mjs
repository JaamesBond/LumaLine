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
  LUMALINE_HOME, PUB, KEYS_DIR, STATE, AUDIT, FEED_BASE,
  FETCH_TIMEOUT_MS, COOLDOWN_MS, HYPERLINKS, SHOW_URL, COLOR, COLOR_RESET,
} from './config.mjs';
import { step } from './client/window.mjs';
import { loadKeyring } from './lib/keyring.mjs';
import { safeClickUrl } from './lib/url.mjs';

mkdirSync(LUMALINE_HOME, { recursive: true });
const now = Date.now();

const loadJson = (p, def) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return def; } };
const saveJson = (p, o) => writeFileSync(p, JSON.stringify(o));
const audit = (evt) => appendFileSync(AUDIT, JSON.stringify({ ts: now, ...evt }) + '\n');

// OSC 8 hyperlink: makes the wrapped text clickable in supporting terminals. URL safety
// (absolute http(s), no control chars) lives in ./lib/url.mjs — used for both the visible
// inline URL (built in client/window.mjs) and this OSC-8 click target.
const osc8 = (url, text) => `\x1b]8;;${url}\x07${text}\x1b]8;;\x07`;

// Trusted verify ring: the bundled CURRENT + NEXT public keys (selected by `keyid`), plus
// the legacy/default key (PUB) for envelopes that predate keyid. Built once per tick. An
// unknown keyid — or a sig that doesn't verify under its keyid's key — is refused, so a key
// rotation never blacks out clients that already bundle the next key (signed-content-only).
const keyring = loadKeyring({ keysDir: KEYS_DIR, legacyPubPath: PUB });
const verifyAd = (adData, sig, keyid) => keyring.verify(adData, sig, keyid);

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
    r = await step({ state, now, activity, post, cfg: { cooldownMs: COOLDOWN_MS, verifyAd, showUrl: SHOW_URL } });
  } catch (e) {
    audit({ event: 'step_error', message: e && e.message });
    return base;   // backend unreachable / error -> graceful base status, nothing billed
  }
  if (r.verifyFail) { audit({ event: 'verify_fail' }); saveJson(STATE, null); return base; }
  saveJson(STATE, r.state);
  if (!r.status) return base;
  // r.status already carries the inline URL + "sponsored" disclosure (built in client/window.mjs,
  // gated by SHOW_URL). OSC-8 makes the WHOLE line clickable where Claude Code forwards it (IDE
  // terminals); on standalone terminals that passthrough is broken upstream (#26356), but the
  // inline URL is visible text so the terminal's own detection (kitty ctrl+click / foot url-mode)
  // or copy/paste still reaches it.
  const url = r.clickUrl ? safeClickUrl(r.clickUrl) : null;
  // Color the sponsored line (brand green by default) so it reads as a deliberate element instead
  // of dim status-bar chrome. Base status stays unstyled (returned earlier). The SGR reset sits
  // INSIDE the OSC-8 text span so it cannot break the hyperlink terminator.
  const line = COLOR ? `${COLOR}${r.status}${COLOR_RESET}` : r.status;
  return (url && HYPERLINKS) ? osc8(url, line) : line;
}

main()
  .then((line) => process.stdout.write(line + '\n'))
  .catch(() => process.stdout.write('lumaline: idle\n'));
