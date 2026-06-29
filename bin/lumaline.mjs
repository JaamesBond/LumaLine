#!/usr/bin/env node
// lumaline CLI. Subcommands:
//   install     wire the sponsored status line into Claude Code (explicit, reversible)
//   uninstall   remove it, restoring any prior statusLine
//   statusline  the status-line command itself (used by Claude Code, not by hand)
//   doctor      check environment / where Claude Code config lives
//   version     print version
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';

const [cmd] = process.argv.slice(2);
const rest = process.argv.slice(3);
const opt = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
const pkgVersion = () =>
  JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8')).version;

async function main() {
  switch (cmd) {
    case 'statusline':
      await import('../src/statusline.mjs');
      break;
    case 'install':
      (await import('../src/install.mjs')).install();
      break;
    case 'uninstall':
      (await import('../src/uninstall.mjs')).uninstall();
      break;
    case 'login':
      // Explicit, opt-in (like install): never runs automatically. Attributes future
      // impressions to the developer's account via a short-lived, revocable device token.
      await (await import('../src/client/auth.mjs')).login({
        label: opt('--label') || os.hostname(), clientVersion: pkgVersion(),
      });
      break;
    case 'logout':
      await (await import('../src/client/auth.mjs')).logout();
      break;
    case 'earnings':
      await (await import('../src/client/auth.mjs')).earnings();
      break;
    case 'doctor':
      await doctor();
      break;
    case 'version':
    case '--version':
    case '-v': {
      const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));
      console.log('lumaline ' + pkg.version);
      break;
    }
    default:
      help();
  }
}

async function doctor() {
  const cfg = await import('../src/config.mjs');
  const crypto = await import('node:crypto');
  console.log('node            : ' + process.version + ' (' + process.platform + '/' + process.arch + ')');
  console.log('claude settings : ' + cfg.CLAUDE_SETTINGS + (existsSync(cfg.CLAUDE_SETTINGS) ? ' ✓' : ' (missing — is Claude Code installed?)'));
  console.log('lumaline home   : ' + cfg.LUMALINE_HOME);
  console.log('feed            : ' + cfg.FEED_BASE);

  // Bundled verify key + a stable fingerprint of its SPKI DER. The fingerprint lets a user
  // confirm the key shipped in their install matches the one the feed signs with (publish it).
  let fp = '(no key)';
  if (existsSync(cfg.PUB)) {
    try {
      const der = crypto.createPublicKey(readFileSync(cfg.PUB)).export({ type: 'spki', format: 'der' });
      fp = 'sha256:' + crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
    } catch { fp = '(unreadable)'; }
  }
  console.log('verify key      : ' + cfg.PUB + (existsSync(cfg.PUB) ? ' ✓' : ' (missing)'));
  console.log('  fingerprint   : ' + fp);

  // Reachability probe — OPTIONS is side-effect-free (never opens a billable window).
  let reach = 'skipped';
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 2500);
    const res = await fetch(cfg.FEED_BASE + '/window/open', { method: 'OPTIONS', signal: ctrl.signal });
    clearTimeout(t);
    reach = (res.status >= 200 && res.status < 500) ? ('reachable (HTTP ' + res.status + ')') : ('HTTP ' + res.status);
  } catch (e) { reach = 'unreachable (' + (e && e.name === 'AbortError' ? 'timeout' : 'offline?') + ')'; }
  console.log('feed reachable  : ' + reach);

  console.log('refreshInterval : ' + cfg.REFRESH_SECONDS + 's');
  console.log('hyperlinks      : ' + (cfg.HYPERLINKS ? 'on (OSC 8)' : 'off'));
  console.log('auth endpoint   : ' + cfg.AUTH_BASE);
  const a = (await import('../src/client/auth.mjs')).authStatus({});
  console.log('login           : ' + (a.loggedIn
    ? 'as ' + (a.handle ?? a.publisherId) + ' (device ' + String(a.deviceId ?? '').slice(0, 8) + '…, token '
      + (a.expiresInS != null ? a.expiresInS + 's left' : 'no exp') + ')'
    : 'anonymous — signed self-promo sentinel feed (gross=0, never billed). Run `lumaline login` to attribute earnings.'));
  if (existsSync(cfg.CLAUDE_SETTINGS)) {
    try {
      const s = JSON.parse(readFileSync(cfg.CLAUDE_SETTINGS, 'utf8'));
      console.log('current statusLine: ' + JSON.stringify(s.statusLine ?? null));
    } catch { /* ignore */ }
  }
  console.log("\nwhat's next     : `lumaline install` wires the signed line into Claude Code (reversible); `lumaline uninstall` restores your prior statusLine.");
}

function help() {
  console.log(`lumaline — trust-first sponsored status line for Claude Code

Usage:
  lumaline install      Wire the status line into Claude Code (explicit, reversible)
  lumaline uninstall    Remove it, restoring any prior statusLine
  lumaline login        Log in (device-code) so earnings attribute to your account
  lumaline logout       Log out: revoke this device, revert to the anonymous sentinel
  lumaline earnings     Show your accrued earnings (transparent ledger)
  lumaline doctor       Show environment + where Claude Code config lives
  lumaline version      Print version

Notes:
  - Uses only the official statusLine mechanism. No bundle patching.
  - Wiring happens ONLY when you run \`install\` — never automatically on npm install.
  - Login is opt-in: before it, the line runs anonymously and is never billed.
    Earnings accrue after login but real payouts begin only at the production go-live.
  - \`login\` registers a device label (defaults to your machine hostname; \`--label <name>\` to override).
  - Disable clickable links: LUMALINE_HYPERLINKS=0`);
}

main();
