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
// the locally generated dev key under LUMALINE_HOME.
const bundledPub = fileURLToPath(new URL('./keys/public.pem', import.meta.url));
export const PUB = env.LUMALINE_PUBKEY || (existsSync(bundledPub) ? bundledPub : path.join(KEYS, 'public.pem'));

// Feed endpoint.
export const PORT = Number(env.LUMALINE_PORT || 8787);
export const FEED_BASE = env.LUMALINE_FEED || `http://127.0.0.1:${PORT}`;

// Claude Code settings file. Honors CLAUDE_CONFIG_DIR; otherwise ~/.claude on
// every OS (Claude Code uses the same user-scope location cross-platform).
export const CLAUDE_SETTINGS = env.CLAUDE_CONFIG_DIR
  ? path.join(env.CLAUDE_CONFIG_DIR, 'settings.json')
  : path.join(home, '.claude', 'settings.json');

export const CACHE_TTL_MS = 30_000;
export const FETCH_TIMEOUT_MS = 800;
export const COOLDOWN_MS = 15_000;
export const REFRESH_SECONDS = Number(env.LUMALINE_REFRESH || 1);   // statusLine.refreshInterval
export const HYPERLINKS = env.LUMALINE_HYPERLINKS !== '0';          // OSC 8 clickable links (on by default)
// NB: the click-token HMAC secret is a SERVER-ONLY concern — the client never holds or
// needs it. The dev backend supplies it explicitly (random if unset); see poc/backend.
