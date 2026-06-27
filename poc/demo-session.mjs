// Cinematic PoC: a simulated Claude Code session so the sponsored status line
// looks like the real thing. The status text comes from the real signed backend +
// src/statusline.mjs underneath; only the session chrome is mocked.
//
//   node poc/demo-session.mjs          # animated (in a real terminal)
//   node poc/demo-session.mjs --plain  # plain frames (also used when piped)
import { spawn, spawnSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));   // poc/
const root = path.resolve(here, '..');
const RUNTIME = path.join(here, '.runtime');
// Hyperlinks off here so the mock can re-style the line; clickability is shown live.
const env = { ...process.env, LUMALINE_HOME: RUNTIME, LUMALINE_PORT: '8787', LUMALINE_FEED: 'http://127.0.0.1:8787', LUMALINE_HYPERLINKS: '0' };

const keygen = path.join(here, 'backend', 'keygen.mjs');
const server = path.join(here, 'backend', 'server.mjs');
const statusline = path.join(root, 'src', 'statusline.mjs');
const PRIV = path.join(RUNTIME, 'keys', 'private.pem');

const TTY = process.stdout.isTTY && !process.argv.includes('--plain');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sgr = (code, s) => (TTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const dim = (s) => sgr('2', s), bold = (s) => sgr('1', s), ital = (s) => sgr('3', s);
const yellow = (s) => sgr('33', s), cyan = (s) => sgr('36', s), green = (s) => sgr('32', s), magenta = (s) => sgr('35', s);
const out = (s) => process.stdout.write(s);

const SPINNER = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏';
const VERBS = ['Percolating', 'Forging', 'Baking', 'Schlepping', 'Conjuring'];
const PROMPT = 'refactor the auth middleware to use the new token check';
const claudeStdin = JSON.stringify({ model: { display_name: 'Opus 4.8' }, workspace: { current_dir: here } });

function fetchStatus() {
  const r = spawnSync('node', [statusline], { input: claudeStdin, encoding: 'utf8', env });
  return (r.stdout || '').trim();
}

function styleBar(status) {
  const rule = dim('─'.repeat(64));
  let body;
  if (status.startsWith('★')) {
    const m = status.match(/^★\s+(.*?)\s+·\s+sponsored\s+\((\d+)s\)$/);
    body = m ? `${yellow('★')} ${bold(m[1])}  ${dim(`· sponsored (${m[2]}s)`)}` : yellow(status);
  } else {
    body = dim(status);
  }
  return [rule, ` ${body}`];
}

function workingLine(thinking, frame) {
  if (!thinking) return `  ${green('●')} ${bold('Updated')} auth/middleware.ts ${dim('(+12 −5) · used checkToken()')}`;
  const spin = SPINNER[frame % SPINNER.length];
  const verb = VERBS[Math.floor(frame / 14) % VERBS.length];
  return `  ${cyan(spin)} ${ital(dim(verb + '…'))}   ${dim('(esc to interrupt)')}`;
}

function frameLines(thinking, frame, status) {
  return [
    `  ${magenta('✻')} ${dim('Claude Code')}`, '',
    `${cyan('›')} ${PROMPT}`, '',
    workingLine(thinking, frame), '',
    ...styleBar(status),
  ];
}

let painted = 0;
function paintTTY(lines) {
  if (painted) out(`\x1b[${painted}A`);
  for (const ln of lines) out(`\x1b[2K${ln}\n`);
  painted = lines.length;
}
let lastSnap = '';
let T0 = 0;
function paintPlain(thinking, frame, status) {
  const work = thinking ? `⠿ ${VERBS[Math.floor(frame / 14) % VERBS.length]}…` : '● done';
  const snap = `${work} | ${status}`;
  if (snap === lastSnap) return;
  lastSnap = snap;
  const t = ((Date.now() - T0) / 1000).toFixed(1).padStart(4);
  console.log(`[t=${t}s] ${work.padEnd(16)} | ${status}`);
}

async function waitForBackend() {
  for (let i = 0; i < 50; i++) { try { const r = await fetch(env.LUMALINE_FEED + '/feed'); if (r.ok) return; } catch {} await sleep(100); }
  throw new Error('backend did not come up');
}

let backend;
function cleanup() { if (TTY) out('\x1b[?25h\n'); if (backend) backend.kill('SIGINT'); }
process.on('SIGINT', () => { cleanup(); process.exit(0); });

(async () => {
  if (!existsSync(PRIV)) spawnSync('node', [keygen], { stdio: 'inherit', env });
  for (const f of ['impression-state.json', 'ad-cache.json', 'audit.log', 'backend-impressions.log']) {
    try { rmSync(path.join(RUNTIME, f)); } catch {}
  }
  backend = spawn('node', [server], { stdio: 'ignore', env });
  await waitForBackend();

  if (TTY) out('\x1b[2J\x1b[H\x1b[?25l');
  T0 = Date.now();
  let status = '', lastFetch = -1e9, frame = 0;
  const interval = TTY ? 90 : 120;
  for (;;) {
    const t = Date.now() - T0;
    if (t - lastFetch >= 300) { status = fetchStatus(); lastFetch = t; }
    const thinking = t < 6000;
    if (TTY) paintTTY(frameLines(thinking, frame, status));
    else paintPlain(thinking, frame, status);
    if (t > 7500) break;
    frame++;
    await sleep(interval);
  }
  cleanup();
  process.exit(0);
})();
