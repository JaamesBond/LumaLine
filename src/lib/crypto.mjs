// src/lib/crypto.mjs — pure crypto helpers (ed25519 + HMAC). Node built-ins only.
import crypto from 'node:crypto';

export const signData = (dataStr, privateKeyPem) =>
  crypto.sign(null, Buffer.from(dataStr), crypto.createPrivateKey(privateKeyPem)).toString('base64');

export const verifyData = (dataStr, sigB64, publicKeyPem) => {
  try {
    return crypto.verify(null, Buffer.from(dataStr), crypto.createPublicKey(publicKeyPem), Buffer.from(sigB64, 'base64'));
  } catch { return false; }
};

export const hmacHex = (key, msg) =>
  crypto.createHmac('sha256', key).update(msg).digest('hex');

export const randomId = () => crypto.randomUUID();

// Content-addressed key id: the first 16 hex chars of SHA-256 over the key's CANONICAL
// SPKI DER bytes. Hashing the DER (not the PEM text) makes the id insensitive to PEM
// whitespace/line endings, and binds the keyid cryptographically to the key — a mislabeled
// or swapped key file simply maps to a different id, so it can never be mis-trusted. The id
// is NOT a security control (the Ed25519 signature is); it only selects WHICH trusted key to
// verify against, enabling rotation without a flag day. See src/lib/keyring.mjs.
export const keyFingerprint = (publicKeyPem) =>
  crypto.createHash('sha256')
    .update(crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' }))
    .digest('hex').slice(0, 16);
