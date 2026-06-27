// Generate the ed25519 keypair used to sign the dev ad feed.
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { KEYS, PRIV } from '../../src/config.mjs';

const PUB = path.join(KEYS, 'public.pem');
if (existsSync(PRIV) && existsSync(PUB)) {
  console.log('[keygen] keys already exist, leaving them as-is');
  process.exit(0);
}

mkdirSync(KEYS, { recursive: true });
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
writeFileSync(PRIV, privateKey.export({ type: 'pkcs8', format: 'pem' }));
writeFileSync(PUB, publicKey.export({ type: 'spki', format: 'pem' }));
console.log('[keygen] generated ed25519 keypair in ' + KEYS);
