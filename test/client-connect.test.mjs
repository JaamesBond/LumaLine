import test from 'node:test';
import assert from 'node:assert/strict';
import { connect } from '../src/client/auth.mjs';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function tokenFile() {
  const d = mkdtempSync(join(tmpdir(), 'lumaline-connect-'));
  const f = join(d, 'device-token.json');
  writeFileSync(f, JSON.stringify({
    access_token: 'hdr.' + Buffer.from(JSON.stringify({ exp: Math.floor(Date.now()/1000)+3600 })).toString('base64url') + '.sig',
    refresh_token: 'r', publisher_id: 'p1', device_id: 'd1',
  }));
  return f;
}

test('connect: already onboarded → prints connected, does NOT call onboard', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return { ok: true, status: 200, json: async () => ({ ok: true, onboarded: true, payout_status: 'eligible' }) };
  };
  const lines = [];
  await connect({ file: tokenFile(), connectBase: 'https://x/stripe-connect', fetchImpl, out: (s) => lines.push(s) });
  assert.ok(calls.some((u) => u.endsWith('/connect/status')), 'checks status');
  assert.ok(!calls.some((u) => u.endsWith('/connect/onboard')), 'must NOT onboard when already onboarded');
  assert.match(lines.join('\n'), /connected|active/i);
});

test('connect: not onboarded → posts onboard, prints the onboarding_url', async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith('/connect/status')) return { ok: true, status: 200, json: async () => ({ ok: true, onboarded: false, payout_status: 'pending' }) };
    return { ok: true, status: 200, json: async () => ({ ok: true, account_id: 'acct_1', onboarding_url: 'https://connect.stripe.com/setup/abc' }) };
  };
  const lines = [];
  await connect({ file: tokenFile(), connectBase: 'https://x/stripe-connect', fetchImpl, out: (s) => lines.push(s) });
  assert.match(lines.join('\n'), /connect\.stripe\.com\/setup\/abc/);
});
