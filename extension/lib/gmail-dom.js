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
 * Gmail's per-session request token. Required to build the "Show original"
 * URL. It appears in several places depending on the build, so try each.
 */
export function getSessionToken() {
  // 1. The GLOBALS array Gmail defines inline; index 9 has held `ik` for years.
  try {
    const g = window.GLOBALS;
    if (Array.isArray(g) && typeof g[9] === 'string' && g[9].length > 4) return g[9];
  } catch { /* page context may be isolated */ }

  // 2. Any inline script carrying an "ik" entry.
  for (const script of document.scripts) {
    const text = script.textContent;
    if (!text || text.length > 2_000_000) continue;
    const m = text.match(/["']ik["']\s*:\s*["']([^"']{4,})["']/);
    if (m) return m[1];
  }

  // 3. A rendered link that already carries one.
  const link = document.querySelector('a[href*="ik="], link[href*="ik="]');
  if (link) {
    const m = link.getAttribute('href').match(/[?&]ik=([^&"']+)/);
    if (m) return decodeURIComponent(m[1]);
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
