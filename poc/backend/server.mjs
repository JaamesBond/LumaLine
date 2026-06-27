// poc/backend/server.mjs — dev/PoC backend. Thin launcher around the canonical
// reference server (src/server/server.mjs): signed feed + window protocol + click redirect.
import { randomBytes } from 'node:crypto';
import { readFileSync, appendFileSync } from 'node:fs';
import { PRIV, PORT, BACKEND_LOG } from '../../src/config.mjs';
import { startServer } from '../../src/server/server.mjs';

const ad = { adId: 'matei-001', line: 'Matei is the best', label: 'sponsored', dest: 'https://example.com/matei', durationMs: 5000 };

// No hardcoded secret: use the env-provided one or a fresh random per run (the client
// never needs it). A real deployment supplies a Vault-held secret here.
startServer({
  port: PORT,
  privateKeyPem: readFileSync(PRIV),
  clickSecret: process.env.LUMALINE_CLICK_SECRET || randomBytes(32).toString('hex'),
  ad,
  log: (m) => { appendFileSync(BACKEND_LOG, `${new Date().toISOString()} ${m}\n`); console.log('[backend] ' + m); },
}).then(({ port }) => console.log(`[backend] lumaline feed listening on http://127.0.0.1:${port}`));
