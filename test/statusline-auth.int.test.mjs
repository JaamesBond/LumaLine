// test/statusline-auth.int.test.mjs — integration: the real status-line client must attach a
// logged-in publisher's device token as `Authorization: Bearer …` (so lumaline-feed can bind
// credit to the real publisher), and must send NO auth header when logged out (anonymous →
// sentinel). A tiny signed server captures the header; the client still enforces signed-content.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { signData } from '../src/lib/crypto.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATUSLINE = path.resolve(HERE, '../src/statusline.mjs');

let server, port, pubPath, captured;

// A far-future, syntactically valid (unsigned-content) access token. getValidAccessToken reads
// only its `exp` (no verify), sees it's far from expiry, and returns it without any network call.
function fakeAccessToken() {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ exp: 4102444800, publisher_id: 'pub-real', device_id: 'dev-1' })}.sig`;
}
const TOKEN = fakeAccessToken();

before(async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
  pubPath = path.join(mkdtempSync(path.join(os.tmpdir(), 'lumaline-akey-')), 'public.pem');
  writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
  captured = [];
  server = createServer((req, res) => {
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => {
      captured.push({ path: req.url, auth: req.headers.authorization ?? null });
      res.setHeader('content-type', 'application/json');
      if (req.url.endsWith('/window/open')) {
        const adData = JSON.stringify({ windowId: 'w1', line: 'Matei is the best', label: 'sponsored', clickUrl: 'https://example.com/x' });
        res.end(JSON.stringify({ windowId: 'w1', challenge: 'ch', dwellMs: 5000, hbIntervalMs: 1000, adData, sig: signData(adData, priv) }));
      } else { res.end(JSON.stringify({ ok: true })); }
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});
after(() => server.close());

// Spawn the real client with its own LUMALINE_HOME. If `token` is given, pre-seed the device
// credential file the client reads; otherwise leave it logged out.
function tick({ token } = {}) {
  const home = mkdtempSync(path.join(os.tmpdir(), 'lumaline-ah-'));
  if (token) {
    mkdirSync(home, { recursive: true });
    writeFileSync(path.join(home, 'device-token.json'), JSON.stringify({ access_token: token, refresh_token: null, exp: 4102444800, publisher_id: 'pub-real', device_id: 'dev-1', handle: 'dev-a' }), { mode: 0o600 });
  }
  const env = {
    ...process.env, LUMALINE_HOME: home, LUMALINE_FEED: `http://127.0.0.1:${port}`,
    LUMALINE_PUBKEY: pubPath, LUMALINE_HYPERLINKS: '0',
  };
  const stdin = JSON.stringify({ model: { display_name: 'Opus 4.8' }, context_window: { total_input_tokens: 100 } });
  return new Promise((resolve) => {
    const child = spawn('node', [STATUSLINE], { env });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.on('close', () => resolve({ out: out.trim(), home }));
    child.stdin.write(stdin);
    child.stdin.end();
  });
}

test('logged-in: statusline attaches the device token as a Bearer header on /window/open', async () => {
  captured = [];
  const { out } = await tick({ token: TOKEN });
  assert.match(out, /Matei is the best/, 'still renders the signed ad');
  const open = captured.find((c) => c.path.endsWith('/window/open'));
  assert.ok(open, '/window/open was called');
  assert.equal(open.auth, `Bearer ${TOKEN}`, 'the device token rides as Authorization: Bearer');
});

test('logged-out: statusline sends NO Authorization header (anonymous sentinel path)', async () => {
  captured = [];
  const { out } = await tick();
  assert.match(out, /Matei is the best/);
  const open = captured.find((c) => c.path.endsWith('/window/open'));
  assert.equal(open.auth, null, 'no auth header when there is no stored credential');
});
