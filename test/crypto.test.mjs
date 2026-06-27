// test/crypto.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { signData, verifyData, hmacHex, randomId } from '../src/lib/crypto.mjs';

test('sign/verify round-trips and rejects tampering', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const priv = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pub = publicKey.export({ type: 'spki', format: 'pem' });
  const sig = signData('hello', priv);
  assert.equal(verifyData('hello', sig, pub), true);
  assert.equal(verifyData('hello!', sig, pub), false);
});

test('hmacHex is deterministic and key-sensitive', () => {
  assert.equal(hmacHex('k', 'm'), hmacHex('k', 'm'));
  assert.notEqual(hmacHex('k', 'm'), hmacHex('k2', 'm'));
});

test('randomId is unique-ish', () => {
  assert.notEqual(randomId(), randomId());
});
