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

  /* Talking to the service worker.
   *
   * Two things go wrong here in Manifest V3 and both look like "the extension
   * stopped working":
   *
   *  1. The worker is shut down when idle. Chrome restarts it on the next
   *     message, but a message arriving exactly as it terminates is lost with
   *     "Receiving end does not exist" -- so one retry recovers it.
   *  2. Reloading the extension orphans the content scripts already running
   *     in open tabs. Those can never reach the new worker, and the only cure
   *     is reloading the page, so say that instead of failing obscurely.
   */
  const ASLEEP = /Receiving end does not exist|message port closed/i;
  const ORPHANED = /Extension context invalidated/i;

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function send(msg, { retry = true } = {}) {
    try {
      return await chrome.runtime.sendMessage(msg);
    } catch (err) {
      const text = err?.message || String(err);

      if (ORPHANED.test(text)) {
        throw Object.assign(new Error('The extension was reloaded.'), {
          hint: 'Refresh this Gmail tab to reconnect.',
        });
      }

      if (retry && ASLEEP.test(text)) {
        await sleep(250);                       // let the worker finish booting
        return send(msg, { retry: false });
      }

      throw Object.assign(new Error('Could not reach the Mailforge background service.'), {
        hint: 'Reload the extension at chrome://extensions, then refresh this tab.',
      });
    }
  }

  async function settings() {
    const res = await send({ type: 'getSettings' });
    return res?.ok ? res : { apiBase: '', source: 'session' };
  }

  /** Obtain the raw message, through whichever source is configured.
   *  Returns the bytes and how they were obtained, because a signature
   *  verdict is only as trustworthy as the bytes it was computed over. */
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
      return { raw: res.raw, retrieval: 'Gmail API (verbatim)' };
    }

    // Same-origin here, so the user's Gmail cookies ride along automatically.
    const { token, via } = await dom.getSessionToken();
    if (!token) {
      const err = new Error('Could not read the Gmail session token from the page.');
      err.hint = via === 'bridge-silent'
        ? 'The page bridge did not load. Reload the Gmail tab, and reload the '
          + 'extension at chrome://extensions if you just updated it.'
        : 'Gmail did not expose a token this build recognises. Switch the '
          + 'message source to "Gmail API" in the extension popup.';
      err.diagnostic = via;
      throw err;
    }

    const source = new sources.SessionSource();
    const raw = await source.getRawMessage({
      messageId: message.messageId,
      userIndex: dom.getUserIndex(),
      ik: token,
    });
    return {
      raw,
      retrieval: source.lastRetrieval || 'unknown',
      // Kept only so research mode can compare against the rendered copy.
      showOriginalHtml: source.lastShowOriginalHtml || null,
    };
  }

  /* Research mode: compare this message's verbatim bytes with the copy
   * recovered from Gmail's rendered view. Only runs when the verbatim
   * download succeeded -- without it there is no ground truth to compare to.
   * Never blocks or alters the verdict the user is looking at. */
  async function recordFidelity(host, message, fetched) {
    if (!/verbatim/i.test(fetched.retrieval) || !fetched.showOriginalHtml) return;

    let rendered;
    try {
      rendered = sources.extractRawFromShowOriginal(fetched.showOriginalHtml);
    } catch {
      return;                     // page unrecognisable: nothing to measure
    }

    const note = document.createElement('div');
    note.className = 'mf-research';
    note.textContent = 'Research: measuring retrieval fidelity…';
    host.querySelector('.mf-card')?.appendChild(note);

    try {
      const res = await send({
        type: 'research:record',
        messageId: message.messageId,
        verbatim: fetched.raw,
        rendered,
      });
      if (!res?.ok) throw new Error(res?.error || 'failed');
      const r = res.record;
      note.textContent = `Research: recorded #${res.total} · copies `
        + (r.identical ? 'identical' : `differ (${r.diff_kind}, ${r.diff_region})`)
        + ` · DKIM ${r.dkim_verbatim} vs ${r.dkim_rendered}`
        + (r.dkim_flipped ? ' · FLIPPED' : '');
      if (r.dkim_flipped) note.classList.add('mf-research-flip');
    } catch (err) {
      note.textContent = `Research: not recorded (${err.message || err})`;
    }
  }

  async function analyseOpenMessage() {
    if (busy) return;
    const message = dom.getOpenMessage();
    const anchor = dom.findPanelAnchor();
    if (!message || !anchor) return;

    busy = true;
    const host = panel.mountPoint(anchor);
    panel.renderLoading(host);

    try {
      const { apiBase, source, researchMode } = await settings();
      const fetched = await getRaw(message, source);
      const { raw, retrieval } = fetched;

      panel.renderLoading(host, 'Authenticating sender and tracing origin…');
      const res = await send({
        type: 'analyse',
        raw,
        filename: `${(message.subject || 'message').slice(0, 60)}.eml`,
      });

      if (!res?.ok) throw Object.assign(new Error(res?.error || 'Analysis failed.'),
        { hint: res?.hint });

      panel.renderResult(host, res.result, { reportBase: apiBase, raw, retrieval });
      if (researchMode) recordFidelity(host, message, fetched);
    } catch (err) {
      panel.renderError(host, err.message || String(err),
        [err.hint, err.diagnostic && `(${err.diagnostic})`].filter(Boolean).join(' '));
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

  /* Gmail mutates constantly, so the observer fires often. Once the extension
   * is reloaded this script is orphaned and every call throws -- detach
   * rather than spraying errors into the console for the rest of the session,
   * and mark the stale button so the state is visible instead of silent. */
  const stop = dom.onViewChange(() => {
    if (!chrome.runtime?.id) {
      stop();
      const stale = document.getElementById(BUTTON_ID);
      if (stale) {
        stale.title = 'Mailforge was reloaded — refresh this tab to reconnect';
        stale.classList.add('mf-stale');
      }
      return;
    }
    injectButton();
  });
})().catch((err) => {
  // A tab open from before an extension reload cannot load the new modules.
  const orphaned = /Extension context invalidated/i.test(err?.message || '');
  console.warn('[Mailforge]', orphaned
    ? 'This tab predates the current extension build; refresh it to reconnect.'
    : err);
});
