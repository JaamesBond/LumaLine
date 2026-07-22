// test/sec2-p1-trusted-ip.test.mjs — SECURITY-AUDIT PASS-2 (Cluster P1: IP-TRUST MED residual).
//
// Residual closed: lumaline-feed / auth-device / click all read the LEFTMOST x-forwarded-for hop
// (`xff.split(",")[0]`), which any caller can set — so the edge memory limiter, the durable salted
// rl_hit key, and ad_windows.ip_hash were keyed on an attacker-chosen value (per-IP DoS + per-IP IVT
// inert against header rotation). The fix routes every edge fn through ONE shared derivation
// (_shared/client-ip.mjs): worker-vouched cf-connecting-ip (cryptographically proven via
// x-lumaline-edge-proof) is preferred and marked `trusted`; the leftmost XFF becomes a last-resort
// local/dev fallback ONLY. This suite exercises that pure resolver directly (node --test, node:
// builtins only, no DB) + an adversarial-trace guard over the three edge fns' wiring.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { pickClientIp, edgeProofOk, saltedIpHash, resolveClientIp }
  from '../supabase/functions/_shared/client-ip.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const H = (o) => new Headers(o);

// ---- The core exploit + its closure -------------------------------------------------------------

test('P1 EXPLOIT CLOSED: attacker-set leftmost XFF is IGNORED when cf-connecting-ip is present', () => {
  // Pre-fix, `xff.split(",")[0]` === '6.6.6.6' (attacker-chosen) drove the DoS key + IVT ip.
  const r = pickClientIp(H({ 'x-forwarded-for': '6.6.6.6, 10.0.0.1', 'cf-connecting-ip': '203.0.113.9' }));
  assert.equal(r.ip, '203.0.113.9');            // the real per-client CF value, NOT the spoofed 6.6.6.6
  assert.notEqual(r.ip, '6.6.6.6');
  assert.equal(r.source, 'cf-connecting-ip');
  assert.equal(r.trusted, false);               // cf header alone is best-effort until the proof verifies
});

test('P1: worker-vouched IP wins and is TRUSTED only when the edge proof verified', () => {
  const hdr = H({ 'x-lumaline-client-ip': '198.51.100.7', 'cf-connecting-ip': '203.0.113.9',
                  'x-forwarded-for': '6.6.6.6' });
  assert.deepEqual(pickClientIp(hdr, { proofOk: true }),
    { ip: '198.51.100.7', trusted: true, source: 'edge-proof' });
  // Without a verified proof the unauthenticated vouch header is IGNORED -> falls through to cf.
  const noProof = pickClientIp(hdr, { proofOk: false });
  assert.equal(noProof.ip, '203.0.113.9');
  assert.notEqual(noProof.source, 'edge-proof');
});

test('P1: precedence chain — edge-proof > cf-connecting-ip > leftmost XFF > x-real-ip > none', () => {
  // Leftmost XFF survives ONLY as a legacy/local fallback when nothing better exists.
  assert.equal(pickClientIp(H({ 'x-forwarded-for': '192.0.2.1, 9.9.9.9' })).source, 'xff-left');
  assert.equal(pickClientIp(H({ 'x-forwarded-for': '192.0.2.1, 9.9.9.9' })).ip, '192.0.2.1');
  assert.equal(pickClientIp(H({ 'x-real-ip': '192.0.2.5' })).source, 'x-real-ip');
  assert.deepEqual(pickClientIp(H({})), { ip: '', trusted: false, source: 'none' });
});

test('P1: the rightmost XFF hop is NEVER chosen (would collapse all clients to CF egress)', () => {
  // Two-hop topology: rightmost is Cloudflare shared egress. Resolver must not pick it.
  const r = pickClientIp(H({ 'x-forwarded-for': '198.51.100.7, 172.16.0.1' }));
  assert.notEqual(r.ip, '172.16.0.1');
  assert.equal(r.ip, '198.51.100.7');
});

test('P1: edgeProofOk is constant-time-style and fails closed on empty/absent secret or header', async () => {
  assert.equal(await edgeProofOk(H({ 'x-lumaline-edge-proof': 's3cret' }), 's3cret'), true);
  assert.equal(await edgeProofOk(H({ 'x-lumaline-edge-proof': 'nope' }), 's3cret'), false);
  assert.equal(await edgeProofOk(H({ 'x-lumaline-edge-proof': 's3cret' }), ''), false); // unset secret
  assert.equal(await edgeProofOk(H({}), 's3cret'), false);                              // no header
});

test('P1: resolveClientIp ties proof+pick together — right secret trusts vouched IP, wrong secret does not', async () => {
  const hdr = H({ 'x-lumaline-client-ip': '198.51.100.7', 'x-lumaline-edge-proof': 'k',
                  'x-forwarded-for': '6.6.6.6' });
  assert.deepEqual(await resolveClientIp(hdr, 'k'),
    { ip: '198.51.100.7', trusted: true, source: 'edge-proof' });
  // Wrong secret => proof fails => vouch ignored => no cf => leftmost XFF fallback, untrusted.
  const wrong = await resolveClientIp(hdr, 'WRONG');
  assert.equal(wrong.ip, '6.6.6.6');
  assert.equal(wrong.trusted, false);
});

test('P1: saltedIpHash is deterministic, standard-base64, salt-sensitive, null on empty salt/ip', async () => {
  // Must be byte-identical window-time vs click-time so the P2 self-click compare works.
  const a = await saltedIpHash('S', '203.0.113.9');
  const b = await saltedIpHash('S', '203.0.113.9');
  assert.equal(a, b);                                    // deterministic
  assert.match(a, /^[A-Za-z0-9+/]+=*$/);                 // STANDARD base64 (not base64url) => matches ad_windows.ip_hash
  assert.notEqual(a, await saltedIpHash('S2', '203.0.113.9')); // salt changes the hash (non-reversible)
  assert.equal(await saltedIpHash('', '203.0.113.9'), null);   // no salt => gate inert (never a false key)
  assert.equal(await saltedIpHash('S', ''), null);
});

// ---- Adversarial-trace guard: the three edge fns are wired to the shared resolver, not xff[0] -----

test('P1 TRACE: lumaline-feed/auth-device/click import the shared resolver + no raw leftmost-XFF read', () => {
  const feed = readFileSync(join(ROOT, 'supabase/functions/lumaline-feed/index.ts'), 'utf8');
  const auth = readFileSync(join(ROOT, 'supabase/functions/auth-device/index.ts'), 'utf8');
  const click = readFileSync(join(ROOT, 'supabase/functions/click/index.ts'), 'utf8');
  for (const [name, src] of [['lumaline-feed', feed], ['auth-device', auth], ['click', click]]) {
    assert.match(src, /_shared\/client-ip\.mjs/, `${name} must import the shared client-ip resolver`);
    // The pre-fix anti-pattern (leftmost XFF hop) must be gone from the edge fn bodies.
    assert.doesNotMatch(src, /x-forwarded-for[^\n]*split\(","\)\[0\]/i,
      `${name} must not re-read the attacker-controllable leftmost x-forwarded-for hop`);
  }
});
