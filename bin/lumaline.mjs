#!/usr/bin/env node
// lumaline CLI. Subcommands:
//   install     wire the sponsored status line into Claude Code (explicit, reversible)
//   uninstall   remove it, restoring any prior statusLine
//   statusline  the status-line command itself (used by Claude Code, not by hand)
//   doctor      check environment / where Claude Code config lives
//   version     print version
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const [cmd] = process.argv.slice(2);

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
  console.log('node            : ' + process.version + ' (' + process.platform + '/' + process.arch + ')');
  console.log('claude settings : ' + cfg.CLAUDE_SETTINGS + (existsSync(cfg.CLAUDE_SETTINGS) ? ' ✓' : ' (missing — is Claude Code installed?)'));
  console.log('lumaline home  : ' + cfg.LUMALINE_HOME);
  console.log('feed            : ' + cfg.FEED_BASE);
  console.log('verify key      : ' + cfg.PUB + (existsSync(cfg.PUB) ? ' ✓' : ' (missing)'));
  console.log('refreshInterval : ' + cfg.REFRESH_SECONDS + 's');
  console.log('hyperlinks      : ' + (cfg.HYPERLINKS ? 'on (OSC 8)' : 'off'));
  if (existsSync(cfg.CLAUDE_SETTINGS)) {
    try {
      const s = JSON.parse(readFileSync(cfg.CLAUDE_SETTINGS, 'utf8'));
      console.log('current statusLine: ' + JSON.stringify(s.statusLine ?? null));
    } catch { /* ignore */ }
  }
}

function help() {
  console.log(`lumaline — trust-first sponsored status line for Claude Code

Usage:
  lumaline install      Wire the status line into Claude Code (explicit, reversible)
  lumaline uninstall    Remove it, restoring any prior statusLine
  lumaline doctor       Show environment + where Claude Code config lives
  lumaline version      Print version

Notes:
  - Uses only the official statusLine mechanism. No bundle patching.
  - Wiring happens ONLY when you run \`install\` — never automatically on npm install.
  - Disable clickable links: LUMALINE_HYPERLINKS=0`);
}

main();
