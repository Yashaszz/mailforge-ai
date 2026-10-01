/* Main-world bridge.
 *
 * Content scripts run in an isolated world: they share the DOM with the page
 * but not its JavaScript globals. Gmail keeps its per-session request token
 * on `window.GLOBALS`, which is therefore invisible to the rest of this
 * extension.
 *
 * This file is declared with "world": "MAIN" so it runs in Gmail's own
 * context, and hands the token back over window.postMessage. It reads one
 * value and sends nothing anywhere else.
 */

(() => {
  const REQUEST = 'mailforge:get-session-token';
  const REPLY = 'mailforge:session-token';

  // GLOBALS is positional and Gmail has kept `ik` at index 9 for years, but
  // the index is not contractual -- so fall back to scanning the array for a
  // value shaped like a token.
  const IK_INDEX = 9;
  const PLAUSIBLE = /^[A-Za-z0-9_-]{6,40}$/;

  function fromGlobals() {
    const g = window.GLOBALS;
    if (!Array.isArray(g)) return null;

    const atIndex = g[IK_INDEX];
    if (typeof atIndex === 'string' && PLAUSIBLE.test(atIndex)) return atIndex;

    // Nothing usable at the usual position: take the first plausible string,
    // skipping entries that are obviously something else.
    for (const value of g) {
      if (typeof value !== 'string' || !PLAUSIBLE.test(value)) continue;
      if (value.includes('@') || value.includes('.') || value.includes('/')) continue;
      return value;
    }
    return null;
  }

  function fromGmailConfig() {
    for (const key of ['GM_ID_KEY', 'GM_IK', '_GM_ik']) {
      const value = window[key];
      if (typeof value === 'string' && PLAUSIBLE.test(value)) return value;
    }
    return null;
  }

  function findToken() {
    try {
      return fromGlobals() || fromGmailConfig() || null;
    } catch {
      return null;
    }
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window || event.data?.type !== REQUEST) return;
    window.postMessage({ type: REPLY, token: findToken() }, window.location.origin);
  });
})();
