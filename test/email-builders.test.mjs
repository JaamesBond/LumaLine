import test from 'node:test';
import assert from 'node:assert/strict';
import { paidEmail, connectNudgeEmail, sendEmail } from '../supabase/functions/_shared/email.mjs';

const noExternal = (html) => assert.ok(!/https?:\/\/(?!c\.lumaline|feed\.lumaline)/i.test(html.replace(/mailto:[^"'\s]+/g,'')) || !/<img|src=/.test(html), 'no external image/src');

test('paidEmail: subject + amount + plaintext fallback, no external images', () => {
  const e = paidEmail({ handle: 'degen', amountEur: '1.10' });
  assert.match(e.subject, /paid|payout/i);
  assert.match(e.html, /1\.10/);
  assert.match(e.html, /degen/);
  assert.ok(e.text && e.text.includes('1.10'), 'plaintext fallback present with amount');
  assert.ok(!/<img/i.test(e.html), 'no external images');
});

test('connectNudgeEmail: has a CTA mentioning lumaline connect + amount + plaintext', () => {
  const e = connectNudgeEmail({ handle: 'pat', amountEur: '3.00' });
  assert.match(e.subject, /waiting|connect/i);
  assert.match(e.html, /lumaline connect/);
  assert.match(e.html, /3\.00/);
  assert.ok(e.text.includes('lumaline connect'));
});

test('escapes handle to prevent HTML injection', () => {
  const e = paidEmail({ handle: '<script>x</script>', amountEur: '1.00' });
  assert.ok(!e.html.includes('<script>x</script>'), 'handle is escaped');
});

test('sendEmail: posts to Resend with from/to/subject; returns sent on 200', async () => {
  let body = null;
  const fetchImpl = async (url, opts) => { body = JSON.parse(opts.body); return { ok: true, status: 200 }; };
  const r = await sendEmail({ to: 'a@b.c', subject: 's', html: '<b>h</b>', text: 't', apiKey: 'k', from: 'LumaLine <x@y.z>', fetchImpl });
  assert.equal(r, 'sent');
  assert.equal(body.from, 'LumaLine <x@y.z>');
  assert.deepEqual(body.to, ['a@b.c']);
  assert.equal(body.html, '<b>h</b>');
});

test('sendEmail: missing apiKey/to → failed:not_configured, no throw', async () => {
  const r = await sendEmail({ to: '', subject: 's', html: 'h', text: 't', apiKey: '', from: 'f' });
  assert.equal(r, 'failed:not_configured');
});

test('sendEmail: no arguments → failed:not_configured, no throw', async () => {
  const r = await sendEmail();
  assert.equal(r, 'failed:not_configured');
});
