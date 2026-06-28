// src/lib/keyring.mjs — key-rotation-safe trust ring for the signed-content-only invariant.
// Node built-ins only (zero runtime deps).
//
// WHY THIS EXISTS
//   Installed clients never self-update. With a single bundled verify key and no `keyid`,
//   the first Ed25519 key rotation would black out EVERY installed client: the feed would
//   sign with the new key, every client would fail to verify, and under "signed content only"
//   they would all show nothing. The fix is to ship a BUNDLE holding the CURRENT + NEXT public
//   keys and select the verify key by `keyid`, so clients already trust the next key before
//   the feed ever flips to it — a PROACTIVE rotation away from a healthy key with no flag day.
//
// WHAT THIS DOES *NOT* DO (be honest about the threat model)
//   keyid is NOT revocation. Because installed clients never self-update, a key that is already
//   in a shipped bundle stays trusted by that installed base until the user reinstalls / `npm
//   update`s to a bundle that drops it. In particular the legacy/no-keyid fallback keeps the
//   CURRENT key trusted indefinitely for envelopes that omit a keyid. So if the current private
//   key is COMPROMISED, the remedy for the installed base is a new release that removes the key
//   (a reinstall), NOT a feed-side flip — the flip only protects NEW installs and lets the feed
//   start signing with a clean key. The bounded blast radius: an attacker holding a compromised
//   bundled key can forge content only for clients that already trust it, and only until they
//   update. Rotating to the pre-bundled next key is the fast path to a clean signer; true
//   revocation for the installed base is a reinstall. See docs/ops/key-rotation.md.
//
// MODEL
//   keyid = keyFingerprint(publicKey) (see crypto.mjs) — content-addressed, so the ring is
//   keyed by the key's own fingerprint and a file's NAME is just a human hint (never trusted
//   for mapping). A signed envelope carries the keyid alongside the signature; the client
//   selects the matching trusted key and verifies. Selection failures are safe failures:
//     - unknown keyid            -> refuse (no key to verify against)
//     - keyid maps to wrong key  -> signature verify fails -> refuse
//     - absent keyid (legacy)    -> verify against the legacy/default key only
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { keyFingerprint, verifyData } from './crypto.mjs';

// Normalize a keyid the same way on both ends so a stray space or upper-case hex (a likely
// human error when the owner sets LUMALINE_ED25519_KEY_ID) can never cause a spurious
// unknown-keyid refusal -> blackout. Fingerprints are lower-case hex.
const normId = (id) => (id == null || id === '') ? null : String(id).trim().toLowerCase();

/**
 * Build a trusted-key ring.
 * @param {object} o
 * @param {string} [o.keysDir]      directory of bundled `*.pem` public keys (current + next).
 * @param {string} [o.legacyPubPath] path to the default key used when an envelope has NO keyid.
 * @param {string} [o.legacyPubPem]  inline default key PEM (takes precedence over legacyPubPath).
 * @returns {{ verify:(adData:string,sig:string,keyid?:string)=>boolean, keyids:string[], has:(id:string)=>boolean }}
 */
export function loadKeyring({ keysDir, legacyPubPath, legacyPubPem } = {}) {
  const ring = new Map();                 // keyid (fingerprint) -> public key PEM
  // FIRST-WINS: never let a later file silently overwrite an already-trusted keyid (a content
  // fingerprint collision among the owner-controlled bundle would otherwise drop a key). Returns
  // the computed keyid (or null if the PEM is unparseable, so it is skipped).
  const add = (pem) => {
    let id;
    try { id = keyFingerprint(pem); } catch { return null; }
    if (!ring.has(id)) ring.set(id, pem);
    return id;
  };

  // 1) Bundled keys: content-addressed by fingerprint (filename ignored for mapping).
  if (keysDir) {
    let files = [];
    try { files = readdirSync(keysDir).filter((f) => f.toLowerCase().endsWith('.pem')); } catch { /* no dir */ }
    for (const f of files.sort()) {
      try { add(readFileSync(path.join(keysDir, f), 'utf8')); } catch { /* skip unreadable */ }
    }
  }

  // 2) Legacy/default key — verified ONLY for envelopes that omit a keyid (backward compat
  //    with signers that predate keyid). Also added to the ring so it can be selected by id.
  let legacyPem = legacyPubPem ?? null;
  if (!legacyPem && legacyPubPath) {
    try { legacyPem = readFileSync(legacyPubPath, 'utf8'); } catch { /* none */ }
  }
  const legacyId = legacyPem ? add(legacyPem) : null;

  function verify(adData, sig, keyid) {
    if (typeof adData !== 'string' || typeof sig !== 'string') return false;
    const id = normId(keyid);
    // Absent keyid -> legacy default ONLY (do not blanket-trust every bundled key); a present
    // keyid -> exact selection, unknown id yields undefined -> refuse.
    const pem = id === null ? (legacyId ? ring.get(legacyId) : undefined) : ring.get(id);
    if (!pem) return false;
    return verifyData(adData, sig, pem);
  }

  return { verify, keyids: [...ring.keys()], has: (id) => ring.has(normId(id)) };
}
