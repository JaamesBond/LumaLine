// test/sec-dispute-logic.test.mjs — SECURITY-AUDIT HARDENING (D2). Pure validator for the
// publisher /dispute free-text description (supabase/functions/_shared/dispute-logic.mjs).
//
// Hermetic: `node --test`, node: builtins only. Module is NEW, so pre-fix these imports fail to
// resolve — the whole suite fails; post-fix they pass. D2 bounds storage abuse (2KB cap) and
// rejects raw C0 control bytes / DEL (terminal/log injection, NUL tricks) written service_role into
// public.disputes.description. It is NOT the XSS defense (the dashboard must HTML-escape on render).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateDisputeDescription,
  DISPUTE_DESCRIPTION_MAX_BYTES,
} from '../supabase/functions/_shared/dispute-logic.mjs';

test('sec D2: valid multi-line description returns null (newline allowed)', () => {
  assert.equal(validateDisputeDescription('bill was wrong\nplease review'), null);
});

test('sec D2: tab / newline / CR + space are the only allowed whitespace controls', () => {
  assert.equal(validateDisputeDescription('\t\n\r ok'), null);
});

test('sec D2: empty description is rejected', () => {
  assert.equal(validateDisputeDescription(''), 'description_empty');
  assert.equal(validateDisputeDescription(null), 'description_empty');
  assert.equal(validateDisputeDescription(undefined), 'description_empty');
});

test('sec D2: exactly the cap is allowed; one byte over is rejected', () => {
  assert.equal(DISPUTE_DESCRIPTION_MAX_BYTES, 2048);
  const atCap = 'a'.repeat(2048);       // 2048 UTF-8 bytes
  const overCap = 'a'.repeat(2049);     // 2049 UTF-8 bytes
  assert.equal(validateDisputeDescription(atCap), null);
  assert.equal(validateDisputeDescription(overCap), 'description_too_long');
});

test('sec D2: byte length is measured in UTF-8, not JS chars (multibyte counts)', () => {
  // '€' is 3 UTF-8 bytes. 683 * 3 = 2049 bytes > cap, though only 683 chars.
  const multibyte = '€'.repeat(683);
  assert.equal(new TextEncoder().encode(multibyte).length, 2049);
  assert.equal(validateDisputeDescription(multibyte), 'description_too_long');
});

test('sec D2: raw C0 control bytes and DEL are rejected (injection defense)', () => {
  const cc = String.fromCharCode;
  for (const code of [0x00, 0x01, 0x07, 0x08, 0x0b, 0x0c, 0x0e, 0x1b /* ESC */, 0x1f, 0x7f /* DEL */]) {
    assert.equal(
      validateDisputeDescription('hello' + cc(code) + 'world'),
      'description_control_bytes',
      `control byte 0x${code.toString(16)} must be rejected`,
    );
  }
});

test('sec D2: NUL byte embedded anywhere is rejected (no truncation trick)', () => {
  assert.equal(validateDisputeDescription('valid text' + String.fromCharCode(0)), 'description_control_bytes');
});
