/* Content script — the only code that runs inside Gmail.
 *
 * Classic script by necessity (MV3 content_scripts are not modules), so the
 * real logic lives in lib/ and is pulled in with a dynamic import.
 *
 * Responsibilities: notice which message is open, offer a button, fetch the
 * raw source, hand it to the service worker, render the verdict. It never
 * talks to the backend directly.
 */

(async () => {
  const url = (p) => chrome.runtime.getURL(p);
  const [dom, panel, sources] = await Promise.all([
    import(url('lib/gmail-dom.js')),
    import(url('lib/panel.js')),
    import(url('lib/sources.js')),
  ]);

  const BUTTON_ID = 'mailforge-analyse-btn';
  let currentMessageId = null;
  let busy = false;

  const send = (msg) => chrome.runtime.sendMessage(msg);

  async function settings() {
    const res = await send({ type: 'getSettings' });
    return res?.ok ? res : { apiBase: '', source: 'session' };
  }

  /** Obtain the raw message, through whichever source is configured. */
  async function getRaw(message, sourceId) {
    if (sourceId === 'gmail-api') {
      // chrome.identity is unavailable here, so the worker performs this one.
      const res = await send({
        type: 'fetchViaGmailApi',
        messageId: message.messageId,
        legacyMessageId: message.legacyMessageId,
      });
      if (!res?.ok) {
        const err = new Error(res?.error || 'Gmail API request failed.');
        err.hint = res?.hint || '';
        throw err;
      }
      return res.raw;
    }

    // Same-origin here, so the user's Gmail cookies ride along automatically.
    return new sources.SessionSource().getRawMessage({
      messageId: message.messageId,
      userIndex: dom.getUserIndex(),
      ik: dom.getSessionToken(),
    });
  }

  async function analyseOpenMessage() {
    if (busy) return;
    const message = dom.getOpenMessage();
    const anchor = dom.findToolbarAnchor();
    if (!message || !anchor) return;

    busy = true;
    const host = panel.mountPoint(anchor);
    panel.renderLoading(host);

    try {
      const { apiBase, source } = await settings();
      const raw = await getRaw(message, source);

      panel.renderLoading(host, 'Authenticating sender and tracing origin…');
      const res = await send({
        type: 'analyse',
        raw,
        filename: `${(message.subject || 'message').slice(0, 60)}.eml`,
      });

      if (!res?.ok) throw Object.assign(new Error(res?.error || 'Analysis failed.'),
        { hint: res?.hint });

      panel.renderResult(host, res.result, { reportBase: apiBase });
    } catch (err) {
      panel.renderError(host, err.message || String(err), err.hint || '');
      host.querySelector('.mf-retry')?.addEventListener('click', () => {
        busy = false;
        analyseOpenMessage();
      });
    } finally {
      busy = false;
    }
  }

  function injectButton() {
    const message = dom.getOpenMessage();
    if (!message) {
      document.getElementById(BUTTON_ID)?.remove();
      document.getElementById('mailforge-panel')?.remove();
      currentMessageId = null;
      return;
    }

    // Moving to a different message invalidates whatever is on screen.
    if (message.messageId !== currentMessageId) {
      currentMessageId = message.messageId;
      document.getElementById('mailforge-panel')?.remove();
    }

    if (document.getElementById(BUTTON_ID)) return;
    const anchor = dom.findToolbarAnchor();
    if (!anchor) return;

    const button = document.createElement('button');
    button.id = BUTTON_ID;
    button.type = 'button';
    button.className = 'mf-trigger';
    button.title = 'Analyse this message with Mailforge AI';
    button.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
           stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        <path d="M9 12l2 2 4-4"></path>
      </svg><span>Analyse</span>`;
    button.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      analyseOpenMessage();
    });

    anchor.appendChild(button);
  }

  dom.onViewChange(injectButton);
})();
