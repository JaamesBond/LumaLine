// src/server/clicks.mjs — tokenized click tracker: mint a signed token, resolve it
// once (dedupe), require its window to exist, enforce TTL + a safe destination.
// Pure (secret/clock injected). Hardened after the Phase 0 trust gate:
//   - strict 2-part token shape (so `token + '.junk'` cannot dodge dedupe);
//   - dedupe keyed on the canonical windowId (one CPC credit per impression window);
//   - constant-time signature compare;
//   - destination must be an absolute http(s) URL (no open-redirect / javascript:/data:).
import crypto from 'node:crypto';
import { hmacHex } from '../lib/crypto.mjs';

const b64url = (s) => Buffer.from(s).toString('base64url');
const unb64url = (s) => Buffer.from(s, 'base64url').toString('utf8');

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function isSafeHttpUrl(u) {
  try { const x = new URL(u); return x.protocol === 'http:' || x.protocol === 'https:'; }
  catch { return false; }
}

export function createClickTracker({ secret, isWindowKnown, now = () => Date.now(), ttlMs = 600000 }) {
  if (!secret) throw new Error('click tracker requires a secret');
  const seen = new Set();   // dedupe keyed on windowId (Phase 1: a UNIQUE column in Postgres)

  function mint({ windowId, adId, dest }) {
    if (!isSafeHttpUrl(dest)) throw new Error('unsafe dest url');
    const payload = b64url(JSON.stringify({ windowId, adId, dest, ts: now() }));
    return `${payload}.${hmacHex(secret, payload)}`;
  }

  function resolve(token) {
    const parts = String(token).split('.');
    if (parts.length !== 2) return { ok: false, reason: 'malformed' };
    const [payload, sig] = parts;
    if (!payload || !sig) return { ok: false, reason: 'malformed' };
    if (!safeEqual(sig, hmacHex(secret, payload))) return { ok: false, reason: 'bad signature' };
    let data;
    try { data = JSON.parse(unb64url(payload)); } catch { return { ok: false, reason: 'malformed' }; }
    if (now() - data.ts > ttlMs) return { ok: false, reason: 'expired' };
    if (!isWindowKnown(data.windowId)) return { ok: false, reason: 'unknown window' };
    if (!isSafeHttpUrl(data.dest)) return { ok: false, reason: 'unsafe dest' };
    if (seen.has(data.windowId)) return { ok: false, reason: 'duplicate' };
    seen.add(data.windowId);
    return { ok: true, dest: data.dest };
  }

  return { mint, resolve };
}
