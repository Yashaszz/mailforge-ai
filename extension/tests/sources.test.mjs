/* Message retrieval: the layer whose correctness decides whether a DKIM
 * verdict means anything. Everything here is byte-level on purpose. */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractRawFromShowOriginal, findDownloadLink, looksLikeMessage,
} from '../lib/sources.js';

const EML =
  'Return-Path: <bounce@env.example>\r\n' +
  'DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=sel;\r\n' +
  '\tbh=AbC+/123=; b=ZZZ+/999=\r\n' +
  'From: "A & B" <sender@example.test>\r\n' +
  'Subject: Offer <50% off>\r\n' +
  '\r\n' +
  '<html><body><p>Hello &amp; welcome</p></body></html>\r\n';

const escape = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

test('round-trips an escaped message byte-for-byte', () => {
  const html = `<html><body><pre class="x">${escape(EML)}</pre></body></html>`;
  assert.equal(extractRawFromShowOriginal(html), EML);
});

test('preserves addresses in angle brackets when not escaped', () => {
  // A naive tag-stripper eats <sender@example.test> and silently empties
  // Return-Path, which is exactly what SPF and DMARC alignment depend on.
  const out = extractRawFromShowOriginal(`<html><pre>${EML}</pre></html>`);
  assert.match(out, /Return-Path: <bounce@env\.example>/);
  assert.match(out, /From: "A & B" <sender@example\.test>/);
});

test('keeps the DKIM signature intact, including base64 padding', () => {
  const html = `<html><pre>${escape(EML)}</pre></html>`;
  const out = extractRawFromShowOriginal(html);
  assert.match(out, /bh=AbC\+\/123=; b=ZZZ\+\/999=/);
});

test('normalises to CRLF, which DKIM canonicalisation assumes', () => {
  const lf = EML.replace(/\r\n/g, '\n');
  const out = extractRawFromShowOriginal(`<html><pre>${escape(lf)}</pre></html>`);
  assert.ok(!/[^\r]\n/.test(out), 'every LF must be preceded by CR');
});

test('reads the raw_message_text container as well as <pre>', () => {
  const html = `<html><div id="raw_message_text">${escape(EML)}</div></html>`;
  assert.equal(extractRawFromShowOriginal(html), EML);
});

test('accepts a bare message with no wrapper', () => {
  assert.equal(extractRawFromShowOriginal(EML), EML);
});

test('refuses a page it does not recognise rather than returning junk', () => {
  assert.throws(() => extractRawFromShowOriginal('<html><body>Sign in</body></html>'));
});

test('finds the download link by shape, not a fixed URL', () => {
  const base = 'https://mail.google.com/mail/u/0/?ik=abc&view=om&permmsgid=msg-f:1';
  const shapes = [
    '<a download="original.txt" href="?ik=abc&amp;view=att&amp;disp=comp&amp;zw">Download</a>',
    '<a href="/mail/u/0/?ik=abc&amp;view=att&amp;disp=comp&amp;zw" download>Download</a>',
    '<a class="z" href="?ik=abc&amp;view=att&amp;th=9&amp;disp=comp&amp;zw">Download</a>',
    '<a href="?ik=abc&amp;view=om&amp;permmsgid=msg-f:1&amp;dmode=txt">Download</a>',
  ];
  for (const html of shapes) {
    const url = findDownloadLink(html, base);
    assert.ok(url?.startsWith('https://mail.google.com/'), html);
    assert.ok(!url.includes('&amp;'), 'entities must be decoded in the URL');
  }
});

test('returns null when there is no download link, so the caller can fall back', () => {
  assert.equal(findDownloadLink('<html><body>nothing</body></html>', 'https://mail.google.com/'), null);
});

test('rejects anything that is not a message before it is trusted', () => {
  assert.equal(looksLikeMessage('From: a@b.test\r\nSubject: x\r\n\r\nbody'), true);
  assert.equal(looksLikeMessage('<!DOCTYPE html><html>Sign in</html>'), false);
  assert.equal(looksLikeMessage('From: a@b.test'), false, 'no header/body separator');
  assert.equal(looksLikeMessage(''), false);
  assert.equal(looksLikeMessage(null), false);
});
