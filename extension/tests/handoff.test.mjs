/* The extension -> dashboard hand-off. A message is encoded here and decoded
 * by frontend/app.js, so the two must agree exactly. */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reportUrlFor, esc } from '../lib/panel.js';

// The dashboard's decoder, mirrored so a change on either side breaks a test.
function decodeLikeDashboard(url) {
  const m = /[#&]eml=([A-Za-z0-9\-_]+)/.exec(url);
  if (!m) return null;
  const b64 = m[1].replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='));
  return new TextDecoder('utf-8').decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

test('a message survives the hand-off byte-for-byte', () => {
  const eml = 'From: "Tëst Üser" <a@b.test>\r\nSubject: Unicode ✓ ₹3L\r\n\r\nBody.\r\n';
  assert.equal(decodeLikeDashboard(reportUrlFor('https://x.test', eml)), eml);
});

test('produces a fragment, never a query string', () => {
  // A fragment is not sent to the server, so the message is not logged in
  // transit. A query string would be.
  const url = reportUrlFor('https://x.test', 'From: a@b.test\r\n\r\nx');
  assert.ok(url.includes('#eml='));
  assert.ok(!url.includes('?eml='));
});

test('oversized messages fall back instead of building an unusable URL', () => {
  const url = reportUrlFor('https://x.test', 'A'.repeat(500_000));
  assert.ok(!url.includes('#eml='));
  assert.equal(url, 'https://x.test/');
});

test('tolerates a trailing slash on the base URL', () => {
  for (const base of ['https://x.test', 'https://x.test/', 'https://x.test///']) {
    assert.ok(reportUrlFor(base, 'From: a@b.test\r\n\r\nx').startsWith('https://x.test/#eml='));
  }
});

test('escapes markup so message content cannot inject into the panel', () => {
  const hostile = '<img src=x onerror="alert(1)">';
  const out = esc(hostile);
  assert.ok(!out.includes('<img'));
  assert.ok(out.includes('&lt;img'));
});
