// test/keys-bundle.test.mjs — NON-HERMETIC guard on the REAL shipped key bundle.
//
// The keyring unit tests use in-test keys, so they prove the MECHANISM but say nothing about
// what actually ships in src/keys/ (and therefore in the npm tarball / `npm i -g github:...`
// clone). This test fails CI if the committed bundle ever stops trusting a keyid the feed may
// sign with — the failure mode that would otherwise black out installed clients at rotation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keyFingerprint } from '../src/lib/crypto.mjs';
import { loadKeyring } from '../src/lib/keyring.mjs';

const KEYS_DIR = fileURLToPath(new URL('../src/keys', import.meta.url));

// The keyids the client must trust to stay rotation-safe: CURRENT (public.pem) + NEXT (next.pem).
// If you rotate, ADD the new keyid here and ship the bundle BEFORE flipping the feed.
const CURRENT = '8720926064dfdf50';
const NEXT = '31433cdee001fc81';

test('the shipped src/keys bundle contains only PUBLIC keys', () => {
  for (const f of readdirSync(KEYS_DIR).filter((x) => x.endsWith('.pem'))) {
    const pem = readFileSync(path.join(KEYS_DIR, f), 'utf8');
    assert.ok(/-----BEGIN PUBLIC KEY-----/.test(pem), `${f} must be an SPKI public key`);
    assert.ok(!/PRIVATE KEY/.test(pem), `${f} must NOT contain a private key`);
  }
});

test('the shipped bundle trusts the CURRENT and NEXT keyids (rotation-safe)', () => {
  const ring = loadKeyring({ keysDir: KEYS_DIR });
  assert.equal(ring.has(CURRENT), true, `bundle missing CURRENT keyid ${CURRENT}`);
  assert.equal(ring.has(NEXT), true, `bundle missing NEXT keyid ${NEXT} — clients would blackout at rotation`);
});

test('bundled file fingerprints match the expected keyids exactly', () => {
  assert.equal(keyFingerprint(readFileSync(path.join(KEYS_DIR, 'public.pem'), 'utf8')), CURRENT);
  assert.equal(keyFingerprint(readFileSync(path.join(KEYS_DIR, 'next.pem'), 'utf8')), NEXT);
});

test('keyid lookup is normalized (whitespace / case cannot cause a spurious refusal)', () => {
  const ring = loadKeyring({ keysDir: KEYS_DIR });
  assert.equal(ring.has(`  ${CURRENT.toUpperCase()}  `), true);
});
