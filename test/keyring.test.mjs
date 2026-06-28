// test/keyring.test.mjs — key-rotation-safe trust: the client selects the trusted
// verify key by `keyid` from a bundle holding the CURRENT + NEXT public keys, so a future
// key rotation (or a compromise response) can never black out installed clients under the
// signed-content-only invariant. Hermetic: every key here is generated in-test, so the
// MECHANISM is proven without depending on the real bundled keys.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { signData, keyFingerprint } from '../src/lib/crypto.mjs';
import { loadKeyring } from '../src/lib/keyring.mjs';

function kp() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    pub: publicKey.export({ type: 'spki', format: 'pem' }),
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function fixture() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'lumaline-keys-'));
  const active = kp();
  const next = kp();
  // Filenames are deliberately NOT the keyid — the ring is content-addressed by fingerprint,
  // so a human-friendly (or even wrong) filename can never mis-map a key.
  writeFileSync(path.join(dir, 'public.pem'), active.pub);
  writeFileSync(path.join(dir, 'next.pem'), next.pub);
  return { dir, active, next };
}

test('keyFingerprint is deterministic, key-specific, and PEM-format-insensitive', () => {
  const { active, next } = fixture();
  assert.equal(keyFingerprint(active.pub), keyFingerprint(active.pub));
  assert.notEqual(keyFingerprint(active.pub), keyFingerprint(next.pub));
  // Reformatting whitespace/line endings must not change the id (it hashes canonical DER).
  const reflowed = active.pub.replace(/\n/g, '\r\n') + '\n';
  assert.equal(keyFingerprint(reflowed), keyFingerprint(active.pub));
  assert.match(keyFingerprint(active.pub), /^[0-9a-f]{16}$/);
});

test('verifies a payload signed under the ACTIVE keyid', () => {
  const { dir, active } = fixture();
  const ring = loadKeyring({ keysDir: dir });
  const data = JSON.stringify({ windowId: 'w1', line: 'hi' });
  const sig = signData(data, active.priv);
  assert.equal(ring.verify(data, sig, keyFingerprint(active.pub)), true);
});

test('accepts a payload signed under the NEXT bundled key (rotation-safe)', () => {
  const { dir, next } = fixture();
  const ring = loadKeyring({ keysDir: dir });
  const data = JSON.stringify({ windowId: 'w1', line: 'hi' });
  const sig = signData(data, next.priv);
  // The whole point: clients already trust the next key BEFORE the feed flips to it.
  assert.equal(ring.verify(data, sig, keyFingerprint(next.pub)), true);
});

test('refuses an UNKNOWN keyid', () => {
  const { dir, active } = fixture();
  const ring = loadKeyring({ keysDir: dir });
  const data = JSON.stringify({ windowId: 'w1', line: 'hi' });
  const sig = signData(data, active.priv);
  assert.equal(ring.verify(data, sig, 'deadbeefdeadbeef'), false);
});

test('keyid selection is REAL: a valid sig presented under the wrong keyid is refused', () => {
  const { dir, active, next } = fixture();
  const ring = loadKeyring({ keysDir: dir });
  const data = JSON.stringify({ windowId: 'w1', line: 'hi' });
  const sigActive = signData(data, active.priv);
  // Signed by active, but the envelope claims the next keyid -> verify under next key fails.
  assert.equal(ring.verify(data, sigActive, keyFingerprint(next.pub)), false);
});

test('tampered payload is refused even under the correct keyid', () => {
  const { dir, active } = fixture();
  const ring = loadKeyring({ keysDir: dir });
  const data = JSON.stringify({ windowId: 'w1', line: 'hi' });
  const sig = signData(data, active.priv);
  assert.equal(ring.verify(data + ' ', sig, keyFingerprint(active.pub)), false);
});

test('absent keyid falls back to the legacy default key (backward compat)', () => {
  const { dir, active, next } = fixture();
  const legacy = path.join(dir, 'public.pem');   // == active key
  const ring = loadKeyring({ keysDir: dir, legacyPubPath: legacy });
  const data = JSON.stringify({ windowId: 'w1', line: 'hi' });
  // A legacy signer (no keyid in the envelope) signed with the active/legacy key -> accepted.
  assert.equal(ring.verify(data, signData(data, active.priv), undefined), true);
  // But an absent keyid does NOT silently accept just any bundled key: a payload signed by
  // the next key with no keyid must NOT verify against the legacy default.
  assert.equal(ring.verify(data, signData(data, next.priv), undefined), false);
});

test('non-string adData/sig are refused (defensive)', () => {
  const { dir } = fixture();
  const ring = loadKeyring({ keysDir: dir });
  assert.equal(ring.verify(null, 'sig', 'id'), false);
  assert.equal(ring.verify('data', null, 'id'), false);
});

test('verify() normalizes the keyid (whitespace + upper-case hex still selects the key)', () => {
  const { dir, active } = fixture();
  const ring = loadKeyring({ keysDir: dir });
  const data = JSON.stringify({ windowId: 'w1', line: 'hi' });
  const sig = signData(data, active.priv);
  const id = keyFingerprint(active.pub);
  assert.equal(ring.verify(data, sig, `  ${id.toUpperCase()}  `), true);
});
