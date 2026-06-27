// Remove lumaline's statusLine, restoring any prior one. Reversible by design.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { CLAUDE_SETTINGS, LUMALINE_HOME } from './config.mjs';

export function uninstall() {
  if (!existsSync(CLAUDE_SETTINGS)) { console.log('No settings.json — nothing to do.'); return; }
  const settings = JSON.parse(readFileSync(CLAUDE_SETTINGS, 'utf8'));

  const sidecar = path.join(LUMALINE_HOME, 'prior-statusline.json');
  let prior = null;
  if (existsSync(sidecar)) prior = JSON.parse(readFileSync(sidecar, 'utf8')).statusLine ?? null;

  if (prior) { settings.statusLine = prior; console.log('Restored previous statusLine.'); }
  else { delete settings.statusLine; console.log('Removed lumaline statusLine.'); }

  writeFileSync(CLAUDE_SETTINGS, JSON.stringify(settings, null, 2) + '\n');
  console.log('✓ ' + CLAUDE_SETTINGS);
}
