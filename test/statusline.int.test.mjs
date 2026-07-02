// test/statusline.int.test.mjs — integration: spawn the real status-line client
// against the canonical server, assert it shows the sponsored line + mirrors to audit.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { startServer } from '../src/server/server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATUSLINE = path.resolve(HERE, '../src/statusline.mjs');
let ctx, home;

before(async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  home = mkdtempSync(path.join(os.tmpdir(), 'lumaline-'));
  mkdirSync(path.join(home, 'keys'), { recursive: true });
  writeFileSync(path.join(home, 'keys', 'public.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  ctx = await startServer({ port: 0, privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), clickSecret: 'dev-click-secret', log: () => {} });
});
after(() => { ctx.server.close(); rmSync(home, { recursive: true, force: true }); });

// Async spawn (not spawnSync): the server runs in THIS process, and spawnSync would
// block the event loop so the in-process HTTP server could never answer the child.
function tick(tokens, sessionId) {
  const payload = { model: { display_name: 'Opus 4.8' }, context_window: { total_input_tokens: tokens } };
  if (sessionId) payload.session_id = sessionId;
  const stdin = JSON.stringify(payload);
  // A prod public key now ships at src/keys/public.pem, so config prefers the bundled key
  // unless LUMALINE_PUBKEY is set. Point the client at THIS test's dev key explicitly.
  const env = {
    ...process.env, LUMALINE_HOME: home, LUMALINE_FEED: `http://127.0.0.1:${ctx.port}`,
    LUMALINE_PUBKEY: path.join(home, 'keys', 'public.pem'), LUMALINE_HYPERLINKS: '0',
  };
  return new Promise((resolve) => {
    const child = spawn('node', [STATUSLINE], { env });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('close', () => resolve(out.trim()));
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

test('shows the sponsored line on first tick and writes an audit log', async () => {
  const out = await tick(100);
  assert.match(out, /Matei is the best/);
  const auditFilePath = path.join(home, 'audit-default.log');
  assert.ok(existsSync(auditFilePath));
  assert.match(readFileSync(auditFilePath, 'utf8'), /window\/open/);
});

test('two sessions get independent state files (no collision)', async () => {
  await tick(100, 'sess-A');
  await tick(100, 'sess-B');
  assert.ok(existsSync(path.join(home, 'impression-state-sess-A.json')), 'session A state file');
  assert.ok(existsSync(path.join(home, 'impression-state-sess-B.json')), 'session B state file');
});
