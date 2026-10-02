/* The fidelity experiment's measurements. If these are wrong, the published
 * flip rate is wrong, so each difference class is pinned explicitly. */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  compareRetrievals, messageFeatures, buildRecord, toCsv, COLUMNS, hashMessageId, headerEnd,
} from '../lib/research.js';

const MSG =
  'DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=sel; bh=abc=; b=xyz=\r\n' +
  'From: a@example.test\r\n' +
  'Content-Type: multipart/alternative; boundary="b"\r\n' +
  '\r\n' +
  '--b\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n' +
  '--b\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello =E2=82=B9\r\n--b--\r\n';

test('identical copies are classified identical', () => {
  const d = compareRetrievals(MSG, MSG);
  assert.equal(d.identical, true);
  assert.equal(d.kind, 'identical');
  assert.equal(d.region, 'none');
  assert.equal(d.firstDiffByte, -1);
});

test('a CRLF to LF change is classified as line endings', () => {
  const d = compareRetrievals(MSG, MSG.replace(/\r\n/g, '\n'));
  assert.equal(d.kind, 'line-endings');
  assert.equal(d.region, 'header');          // first CR is on the first line
});

test('reflowed lines are classified as whitespace', () => {
  const rendered = MSG.replace('Hello =E2=82=B9', 'Hello\r\n =E2=82=B9');
  const d = compareRetrievals(MSG, rendered);
  assert.equal(d.kind, 'whitespace');
  assert.equal(d.region, 'body');
});

test('escaped markup left in the copy is classified as entities', () => {
  const withHtml = MSG.replace('SGVsbG8=', '<p>Hi & bye</p>');
  const rendered = withHtml.replace('<p>Hi & bye</p>', '&lt;p&gt;Hi &amp; bye&lt;/p&gt;');
  assert.equal(compareRetrievals(withHtml, rendered).kind, 'entities');
});

test('truncation is classified as content', () => {
  const d = compareRetrievals(MSG, MSG.slice(0, -20));
  assert.equal(d.kind, 'content');
  assert.equal(d.region, 'body');
  assert.equal(d.firstDiffByte, d.bytesRendered);   // differs where the copy stops
});

test('a header change is located in the header region', () => {
  const d = compareRetrievals(MSG, MSG.replace('From: a@', 'From: b@'));
  assert.equal(d.region, 'header');
});

test('byte offsets are counted in UTF-8, not characters', () => {
  const v = 'Subject: ₹ price\r\n\r\nbody';
  const r = 'Subject: ₹ prize\r\n\r\nbody';
  // '₹' is 3 bytes, so "Subject: ₹ pri" is 16 bytes before the difference.
  assert.equal(compareRetrievals(v, r).firstDiffByte, 16);
});

test('features describe structure and never identity', () => {
  const f = messageFeatures(MSG);
  assert.equal(f.dkimSignatures, 1);
  assert.equal(f.topContentType, 'multipart/alternative');
  assert.equal(f.encodings, 'base64|quoted-printable');
  assert.equal(f.nonAscii, false);
  for (const value of Object.values(f)) {
    assert.ok(!String(value).includes('example.test'), 'no domains in features');
  }
});

test('headerEnd finds the blank line in CRLF and LF messages', () => {
  assert.equal(headerEnd('A: 1\r\nB: 2\r\n\r\nbody'), 10);
  assert.equal(headerEnd('A: 1\nB: 2\n\nbody'), 9);
  assert.equal(headerEnd('A: 1'), -1);
});

test('a record flags a DKIM flip and carries no identifying fields', () => {
  const r = buildRecord({
    msgHash: 'abc123', day: '2026-10-02',
    verbatim: MSG, rendered: MSG.replace(/\r\n/g, '\n'),
    authVerbatim: { dkim: { result: 'pass' }, spf: { result: 'pass' }, dmarc: { result: 'pass' } },
    authRendered: { dkim: { result: 'fail' }, spf: { result: 'pass' }, dmarc: { result: 'pass' } },
  });
  assert.equal(r.dkim_flipped, true);
  assert.equal(r.diff_kind, 'line-endings');
  assert.deepEqual(Object.keys(r), COLUMNS);
  const serialised = JSON.stringify(r);
  assert.ok(!serialised.includes('example.test') && !serialised.includes('a@'));
});

test('a failed verification is recorded as an error, not as a pass', () => {
  const r = buildRecord({
    msgHash: 'x', day: '2026-10-02', verbatim: MSG, rendered: MSG,
    authVerbatim: null, authRendered: { dkim: { result: 'pass' } },
  });
  assert.equal(r.dkim_verbatim, 'error');
  assert.equal(r.dkim_flipped, true);
});

test('CSV output quotes awkward cells and keeps column order', () => {
  const csv = toCsv([{ ...Object.fromEntries(COLUMNS.map((c) => [c, ''])), encodings: 'a,b' }]);
  const [header, row] = csv.trim().split('\n');
  assert.equal(header, COLUMNS.join(','));
  assert.ok(row.includes('"a,b"'));
});

test('message ids are hashed with a salt and never stored raw', async () => {
  const a = await hashMessageId('msg-f:1790000000', 'salt-one');
  const b = await hashMessageId('msg-f:1790000000', 'salt-two');
  assert.match(a, /^[0-9a-f]{16}$/);
  assert.notEqual(a, b, 'a different install must not produce the same hash');
  assert.ok(!a.includes('1790000000'));
});
