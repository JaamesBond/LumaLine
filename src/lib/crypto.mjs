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
