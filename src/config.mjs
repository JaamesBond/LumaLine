// Cross-platform, env-driven config. Works wherever Node + Claude Code run
// (Linux, macOS, Windows) — all paths derive from os.homedir() and env overrides.
import path from 'node:path';
import os from 'node:os';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const home = os.homedir();
const env = process.env;

// Runtime data (keys for local dev, cache, state, audit log).
export const LUMALINE_HOME = env.LUMALINE_HOME || path.join(home, '.lumaline');
export const KEYS = path.join(LUMALINE_HOME, 'keys');
export const PRIV = path.join(KEYS, 'private.pem');                 // backend/dev only
export const AD_CACHE = path.join(LUMALINE_HOME, 'ad-cache.json');
export const STATE = path.join(LUMALINE_HOME, 'impression-state.json');
export const AUDIT = path.join(LUMALINE_HOME, 'audit.log');
export const BACKEND_LOG = path.join(LUMALINE_HOME, 'backend-impressions.log');

// Trusted verify key: a bundled key ships with the package in prod; fall back to
// the locally generated dev key under LUMALINE_HOME. PUB is the LEGACY/DEFAULT key —
// used to verify any signed envelope that arrives WITHOUT a `keyid` (backward compat).
const bundledPub = fileURLToPath(new URL('./keys/public.pem', import.meta.url));
export const PUB = env.LUMALINE_PUBKEY || (existsSync(bundledPub) ? bundledPub : path.join(KEYS, 'public.pem'));

// Bundled key DIRECTORY — holds the CURRENT + NEXT trusted public keys, selected at verify
// time by `keyid` (content-addressed fingerprint). This is what makes the client
// key-rotation-safe: it already trusts the next key before the feed ever signs with it, so a
// rotation (or compromise response) never blacks out installed clients. See src/lib/keyring.mjs.
export const KEYS_DIR = env.LUMALINE_KEYS_DIR || fileURLToPath(new URL('./keys', import.meta.url));

// Feed endpoint. Defaults to the live remote signed self-promo feed (the lumaline-feed
// edge function on the prod Supabase project); override with LUMALINE_FEED for local dev
// (e.g. http://127.0.0.1:8787 against poc/backend, or a Supabase preview branch URL).
export const PORT = Number(env.LUMALINE_PORT || 8787);
export const FEED_BASE = env.LUMALINE_FEED ||
  'https://prmsonskzrubqsazmpwd.supabase.co/functions/v1/lumaline-feed';

// Claude Code settings file. Honors CLAUDE_CONFIG_DIR; otherwise ~/.claude on
// every OS (Claude Code uses the same user-scope location cross-platform).
export const CLAUDE_SETTINGS = env.CLAUDE_CONFIG_DIR
  ? path.join(env.CLAUDE_CONFIG_DIR, 'settings.json')
  : path.join(home, '.claude', 'settings.json');

export const CACHE_TTL_MS = 30_000;
// Remote edge cold-start + Ed25519 signing measured ~1.6s on a cold tick; 800ms (the old
// localhost-tuned value) would abort the first tick after idle and show nothing even when
// wired right. 3s gives margin; still env-tunable for fast localhost dev.
export const FETCH_TIMEOUT_MS = Number(env.LUMALINE_FETCH_TIMEOUT_MS || 3000);
export const COOLDOWN_MS = 15_000;
export const REFRESH_SECONDS = Number(env.LUMALINE_REFRESH || 1);   // statusLine.refreshInterval
export const HYPERLINKS = env.LUMALINE_HYPERLINKS !== '0';          // OSC 8 clickable links (on by default)
// Show the dest URL inline in the sponsored line (`★ <line>  ·  <url>  ·  sponsored (Ns)`). ON by
// default: it's transparent AND reachable everywhere — Claude Code's status-bar OSC-8 passthrough
// is broken on standalone terminals (upstream regression #26356), but a visible https:// URL can
// still be opened by the terminal's own url detection (kitty ctrl+click / foot url-mode) or just
// copy/paste. Set LUMALINE_SHOW_URL=0 (or off/false) to hide it and keep the line clickable via
// the OSC-8 hyperlink only.
export const SHOW_URL = !['0', 'off', 'false'].includes((env.LUMALINE_SHOW_URL || '').toLowerCase());

// Color for the sponsored line. Claude Code renders the status bar dim by default, so the
// sponsored line otherwise reads as faded gray; emitting an explicit SGR makes it the brand
// green (oklch(72% .16 160) -> sRGB ~ #11C281) instead. Only the sponsored line is colored —
// the normal base status stays unstyled. Honors the NO_COLOR standard (https://no-color.org)
// and a LUMALINE_COLOR override: a 6-digit hex ('#11c281' / '11c281'), a raw SGR sequence
// ('1;92'), or 'off'/'0' to disable. The disclosure ("sponsored") text is unchanged — this
// restyles, it never hides the label.
function buildColor() {
  if (env.NO_COLOR != null) return '';
  const v = env.LUMALINE_COLOR;
  if (v === 'off' || v === '0') return '';
  if (v && /^#?[0-9a-fA-F]{6}$/.test(v)) {
    const h = v.replace('#', '');
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
    return `\x1b[38;2;${r};${g};${b}m`;
  }
  if (v && /^[0-9;]+$/.test(v)) return `\x1b[${v}m`;     // raw SGR (e.g. '92' bright green)
  return '\x1b[38;2;17;194;129m';                         // default brand green (#11C281)
}
export const COLOR = buildColor();
export const COLOR_RESET = COLOR ? '\x1b[0m' : '';
// NB: the click-token HMAC secret is a SERVER-ONLY concern — the client never holds or
// needs it. The dev backend supplies it explicitly (random if unset); see poc/backend.
