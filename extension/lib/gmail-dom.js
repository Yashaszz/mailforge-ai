/* Reading Gmail's DOM.
 *
 * Gmail ships obfuscated, frequently-changing markup, so every lookup here
 * has more than one strategy and reports which one worked. When Gmail
 * changes, this is the only file that should need attention — nothing else
 * in the extension touches their DOM.
 */

/** Which account is active: /mail/u/0/, /mail/u/1/ ... */
export function getUserIndex() {
  const m = location.pathname.match(/\/mail\/u\/(\d+)/);
  return m ? m[1] : '0';
}

/**
 * Gmail's per-session request token (`ik`), required to build the
 * "Show original" URL.
 *
 * Gmail keeps it on `window.GLOBALS`, which lives in the page's JavaScript
 * context. Content scripts run in an isolated world and share only the DOM,
 * so that global is not reachable from here — content/page-bridge.js runs in
 * the main world and hands it over. The DOM-only strategies below are
 * fallbacks for builds where that does not work.
 *
 * @returns {Promise<string|null>}
 */
export async function getSessionToken({ timeout = 1500 } = {}) {
  const bridge = await askPageBridge(timeout);
  if (bridge.token) return { token: bridge.token, via: 'page-bridge' };

  const scraped = scrapeTokenFromDom();
  if (scraped) return { token: scraped, via: 'dom' };

  // Report *why* nothing was found: a bridge that never answered is a
  // different failure from one that answered with nothing, and they need
  // different fixes.
  return {
    token: null,
    via: bridge.replied ? 'bridge-answered-empty' : 'bridge-silent',
  };
}

function askPageBridge(timeout) {
  const REQUEST = 'mailforge:get-session-token';
  const REPLY = 'mailforge:session-token';

  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      window.removeEventListener('message', onMessage);
      clearTimeout(timer);
      resolve(value);
    };

    const onMessage = (event) => {
      if (event.source !== window || event.data?.type !== REPLY) return;
      finish({ token: event.data.token || null, replied: true });
    };

    const timer = setTimeout(() => finish({ token: null, replied: false }), timeout);
    window.addEventListener('message', onMessage);
    window.postMessage({ type: REQUEST }, window.location.origin);
  });
}

/** DOM-only fallbacks, usable from the isolated world. */
function scrapeTokenFromDom() {
  // A rendered link that already carries one.
  const link = document.querySelector('a[href*="ik="], link[href*="ik="], form[action*="ik="]');
  if (link) {
    const attr = link.getAttribute('href') || link.getAttribute('action') || '';
    const m = attr.match(/[?&]ik=([^&"'\s]+)/);
    if (m) return decodeURIComponent(m[1]);
  }

  // An inline script carrying one, in either the JSON or the array form.
  for (const script of document.scripts) {
    const text = script.textContent;
    if (!text || text.length > 2_000_000) continue;
    const m = text.match(/["']ik["']\s*:\s*["']([^"']{4,})["']/)
      || text.match(/[?&]ik=([A-Za-z0-9_-]{6,40})/);
    if (m) return m[1];
  }

  return null;
}

/**
 * Identify the message the user is actually looking at.
 *
 * A thread can hold many messages; the one that matters is the expanded one.
 * Collapsed messages are marked aria-expanded="false", so prefer anything not
 * marked that way, and fall back to the last message in the thread, which is
 * the one Gmail opens by default.
 *
 * @returns {{messageId: string, legacyMessageId: string|null,
 *            subject: string|null, strategy: string}|null}
 */
export function getOpenMessage() {
  const nodes = [...document.querySelectorAll('[data-message-id]')]
    .filter((el) => el.offsetParent !== null);
  if (!nodes.length) return null;

  const expanded = nodes.filter((el) => {
    const host = el.closest('[aria-expanded]');
    return !host || host.getAttribute('aria-expanded') !== 'false';
  });

  const pool = expanded.length ? expanded : nodes;
  const el = pool[pool.length - 1];

  const raw = el.getAttribute('data-message-id') || '';
  return {
    messageId: raw.replace(/^#/, ''),               // msg-f:1790…
    legacyMessageId: el.getAttribute('data-legacy-message-id') || null,
    subject: document.querySelector('h2[data-thread-perm-id]')?.textContent?.trim() || null,
    strategy: expanded.length ? 'expanded' : 'last-in-thread',
  };
}

/** True when a thread is open rather than a message list. */
export const isThreadOpen = () => Boolean(getOpenMessage());

/**
 * Gmail is a single-page app: it rewrites the view without navigating, so
 * there is no load event to hook. Watch for DOM changes and the hash, and
 * debounce because Gmail mutates constantly.
 */
export function onViewChange(callback, { delay = 350 } = {}) {
  let timer = null;
  const fire = () => {
    clearTimeout(timer);
    timer = setTimeout(callback, delay);
  };

  const observer = new MutationObserver(fire);
  observer.observe(document.body, { childList: true, subtree: true });
  window.addEventListener('hashchange', fire);

  fire();
  return () => {
    observer.disconnect();
    window.removeEventListener('hashchange', fire);
    clearTimeout(timer);
  };
}

/**
 * Where to put the verdict card.
 *
 * Deliberately *not* next to the button: the button sits in the header row,
 * which is a narrow right-aligned cell, so a card placed there is cramped and
 * clipped. The card belongs in the message's own full-width column, directly
 * above the body.
 */
export function findPanelAnchor() {
  const msg = [...document.querySelectorAll('[data-message-id]')]
    .filter((el) => el.offsetParent !== null).pop();
  if (!msg) return null;

  // .a3s is Gmail's message body. Its container is the full content width.
  const body = msg.querySelector('.a3s');
  if (body?.parentElement) return { parent: body.parentElement, before: body };

  return { parent: msg, before: null };
}

/**
 * Where to put our button. Gmail's toolbars are unlabelled, so anchor on the
 * message header row that holds the reply controls, and fall back to the
 * thread heading.
 */
export function findToolbarAnchor() {
  const msg = [...document.querySelectorAll('[data-message-id]')]
    .filter((el) => el.offsetParent !== null).pop();
  if (!msg) return null;

  return msg.querySelector('[role="toolbar"]')
    || msg.querySelector('td.gH div.gK')
    || msg.querySelector('.gH')
    || document.querySelector('h2[data-thread-perm-id]')?.parentElement
    || null;
}
