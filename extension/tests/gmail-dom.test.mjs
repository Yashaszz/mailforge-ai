/* Gmail DOM reading. Gmail ships obfuscated markup that changes without
 * notice, so these pin the shapes we rely on. */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

// A minimal DOM, enough for the selectors under test.
function stubDom(html, { pathname = '/mail/u/0/' } = {}) {
  const nodes = [];
  const parse = (h) => {
    const re = /<div([^>]*)>/g;
    let m;
    while ((m = re.exec(h))) {
      const attrs = Object.fromEntries(
        [...m[1].matchAll(/([a-z-]+)="([^"]*)"/g)].map((a) => [a[1], a[2]]));
      nodes.push({
        attrs,
        offsetParent: attrs['data-hidden'] ? null : {},
        getAttribute: (k) => attrs[k] ?? null,
        closest: () => (attrs['aria-expanded'] ? { getAttribute: () => attrs['aria-expanded'] } : null),
        querySelector: () => null,
      });
    }
  };
  parse(html);
  globalThis.location = { pathname };
  globalThis.document = {
    scripts: [],
    querySelectorAll: (sel) => (sel.includes('data-message-id') ? nodes : []),
    querySelector: () => null,
  };
  return nodes;
}

let dom;
beforeEach(async () => { dom = await import('../lib/gmail-dom.js'); });

test('reads the active account index from the path', async () => {
  stubDom('', { pathname: '/mail/u/2/' });
  assert.equal(dom.getUserIndex(), '2');
  stubDom('', { pathname: '/mail/' });
  assert.equal(dom.getUserIndex(), '0');
});

test('picks the expanded message, not a collapsed one', async () => {
  stubDom(
    '<div data-message-id="#msg-f:111" aria-expanded="false"></div>' +
    '<div data-message-id="#msg-f:222" aria-expanded="true"></div>');
  const open = dom.getOpenMessage();
  assert.equal(open.messageId, 'msg-f:222');
  assert.equal(open.strategy, 'expanded');
});

test('falls back to the last message when none are marked expanded', async () => {
  stubDom('<div data-message-id="#msg-f:111"></div><div data-message-id="#msg-f:222"></div>');
  const open = dom.getOpenMessage();
  assert.equal(open.messageId, 'msg-f:222');
});

test('strips the leading hash Gmail puts on the id', async () => {
  stubDom('<div data-message-id="#msg-f:999"></div>');
  assert.equal(dom.getOpenMessage().messageId, 'msg-f:999');
});

test('exposes the legacy id the Gmail API needs', async () => {
  stubDom('<div data-message-id="#msg-f:999" data-legacy-message-id="19a2b"></div>');
  assert.equal(dom.getOpenMessage().legacyMessageId, '19a2b');
});

test('reports no open message on a message list', async () => {
  stubDom('');
  assert.equal(dom.getOpenMessage(), null);
  assert.equal(dom.isThreadOpen(), false);
});
