// Remove lumaline's statusLine, restoring any prior one. Reversible by design.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { CLAUDE_SETTINGS, LUMALINE_HOME } from './config.mjs';

export function uninstall() {
  if (!existsSync(CLAUDE_SETTINGS)) { console.log('No settings.json — nothing to do.'); return; }
  let settings;
  try {
    settings = JSON.parse(readFileSync(CLAUDE_SETTINGS, 'utf8'));
  } catch (err) {
    // Don't clobber a file we can't parse — degrade instead of throwing a stack trace.
    console.error(`Could not parse ${CLAUDE_SETTINGS} (${err.message}). Left untouched — remove the statusLine entry by hand.`);
    return;
  }

  const sidecar = path.join(LUMALINE_HOME, 'prior-statusline.json');
  let prior = null;
  if (existsSync(sidecar)) {
    try {
      prior = JSON.parse(readFileSync(sidecar, 'utf8')).statusLine ?? null;
    } catch (err) {
      // A corrupt sidecar shouldn't block uninstall — fall back to plain removal.
      console.error(`Ignoring unreadable sidecar ${sidecar} (${err.message}); removing statusLine instead of restoring.`);
    }
  }

  if (prior) { settings.statusLine = prior; console.log('Restored previous statusLine.'); }
  else { delete settings.statusLine; console.log('Removed lumaline statusLine.'); }

  writeFileSync(CLAUDE_SETTINGS, JSON.stringify(settings, null, 2) + '\n');
  console.log('✓ ' + CLAUDE_SETTINGS);
}
