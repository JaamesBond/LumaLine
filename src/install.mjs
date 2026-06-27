// Wire lumaline into Claude Code's settings.json. Cross-platform and reversible.
// This runs ONLY when the user explicitly invokes `lumaline install` — never as
// an npm postinstall side effect. Consent is explicit.
import { readFileSync, writeFileSync, copyFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CLAUDE_SETTINGS, LUMALINE_HOME, REFRESH_SECONDS } from './config.mjs';

export function install() {
  const statuslinePath = fileURLToPath(new URL('./statusline.mjs', import.meta.url));
  // Absolute node path + absolute script path, both quoted -> no PATH/shell surprises on any OS.
  const command = `"${process.execPath}" "${statuslinePath}"`;

  mkdirSync(LUMALINE_HOME, { recursive: true });

  const claudeDir = path.dirname(CLAUDE_SETTINGS);
  if (!existsSync(claudeDir)) {
    console.error(`Claude Code config dir not found: ${claudeDir}`);
    console.error('Is Claude Code installed for this user? (looked at ' + CLAUDE_SETTINGS + ')');
    process.exit(1);
  }

  const raw = existsSync(CLAUDE_SETTINGS) ? readFileSync(CLAUDE_SETTINGS, 'utf8') : '{}';
  let settings;
  try { settings = JSON.parse(raw); }
  catch (e) { console.error('settings.json is not valid JSON — aborting:', e.message); process.exit(1); }

  // Back up the whole file once, and remember any prior statusLine for clean restore.
  const fullBackup = CLAUDE_SETTINGS + '.lumaline-bak';
  if (existsSync(CLAUDE_SETTINGS) && !existsSync(fullBackup)) copyFileSync(CLAUDE_SETTINGS, fullBackup);
  const existing = settings.statusLine ?? null;
  const isOurs = !!(existing && String(existing.command || '').includes('statusline.mjs'));
  const sidecar = path.join(LUMALINE_HOME, 'prior-statusline.json');
  if (!existsSync(sidecar)) {
    // Record the user's genuine prior statusLine (null if it was already ours).
    writeFileSync(sidecar, JSON.stringify({ savedAt: Date.now(), statusLine: isOurs ? null : existing }, null, 2));
  }

  if (existing && !isOurs) {
    console.warn('Replacing an existing statusLine (saved to ' + sidecar + ').');
    console.warn('Run `lumaline uninstall` to restore it.');
  }

  settings.statusLine = { type: 'command', command, padding: 0, refreshInterval: REFRESH_SECONDS };
  writeFileSync(CLAUDE_SETTINGS, JSON.stringify(settings, null, 2) + '\n');

  console.log('✓ lumaline wired into ' + CLAUDE_SETTINGS);
  console.log('  command        : ' + command);
  console.log('  refreshInterval: ' + REFRESH_SECONDS + 's');
  console.log('  full backup    : ' + fullBackup);
  console.log('\nUndo any time:  lumaline uninstall');
}
