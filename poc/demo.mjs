// Plumbing proof: simulates Claude Code calling the canonical src/statusline.mjs
// ~4x/sec, against the local signed backend. Shows the audit log + the single
// verified backend impression.
import { spawn, spawnSync } from 'node:child_process';
import { rmSync, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));   // poc/
const root = path.resolve(here, '..');
const RUNTIME = path.join(here, '.runtime');
const env = { ...process.env, LUMALINE_HOME: RUNTIME, LUMALINE_PORT: '8787', LUMALINE_FEED: 'http://127.0.0.1:8787' };

const keygen = path.join(here, 'backend', 'keygen.mjs');
const server = path.join(here, 'backend', 'server.mjs');
const statusline = path.join(root, 'src', 'statusline.mjs');

const STATE = path.join(RUNTIME, 'impression-state.json');
const AD_CACHE = path.join(RUNTIME, 'ad-cache.json');
const AUDIT = path.join(RUNTIME, 'audit.log');
const BACKEND_LOG = path.join(RUNTIME, 'backend-impressions.log');
const PRIV = path.join(RUNTIME, 'keys', 'private.pem');

// Vary the activity signal each tick (rising token count) so the server-verified
// window registers real activity progress and credits the impression.
const claudeStdin = (i) => JSON.stringify({ model: { display_name: 'Opus 4.8' }, workspace: { current_dir: root }, context_window: { total_input_tokens: 1000 + i * 137 } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const safeRead = (p) => { try { return readFileSync(p, 'utf8'); } catch { return ''; } };
async function waitForBackend() {
  for (let i = 0; i < 50; i++) { try { const r = await fetch(env.LUMALINE_FEED + '/feed'); if (r.ok) return; } catch {} await sleep(100); }
  throw new Error('backend did not come up');
}

(async () => {
  if (!existsSync(PRIV)) spawnSync('node', [keygen], { stdio: 'inherit', env });
  for (const f of [STATE, AD_CACHE, AUDIT, BACKEND_LOG]) { try { rmSync(f); } catch {} }
  const backend = spawn('node', [server], { stdio: 'inherit', env });
  await waitForBackend();

  // Ticks are ~600ms apart: the server enforces anti-batch heartbeat spacing
  // (>=500ms), so honest beats must be wall-clock-separated to be credited.
  console.log('\n--- simulating Claude Code status ticks (~1.6/sec, ~11s) ---\n');
  const start = Date.now();
  for (let i = 0; i < 18; i++) {
    const r = spawnSync('node', [statusline], { input: claudeStdin(i), encoding: 'utf8', env });
    const t = ((Date.now() - start) / 1000).toFixed(1).padStart(4);
    console.log(`[t=${t}s] ${(r.stdout || '').trim()}`);
    await sleep(600);
  }

  console.log('\n--- client audit log (local, every render counted) ---');
  process.stdout.write(safeRead(AUDIT));
  console.log('--- backend verified impressions (what would be billed/paid) ---');
  process.stdout.write(safeRead(BACKEND_LOG) || '(none)\n');

  backend.kill('SIGINT');
  process.exit(0);
})();
