/* Message sources — how the extension obtains a raw RFC 5322 message.
 *
 * Two implementations behind one interface, because the two have very
 * different operational costs:
 *
 *   SessionSource   Reads Gmail's own "Show original" view using the session
 *                   the user is already signed in with. No OAuth, no Google
 *                   verification, works the moment the extension is loaded.
 *                   Depends on Gmail's internal URL shape, so it is the more
 *                   fragile of the two.
 *
 *   GmailApiSource  Calls gmail.users.messages.get with format=raw. Stable,
 *                   documented, and the path a shipped product should use —
 *                   but gmail.readonly is a *restricted* scope, so public
 *                   distribution needs OAuth verification plus an annual CASA
 *                   assessment. Works immediately for up to 100 test users.
 *
 * Everything downstream consumes `getRawMessage()` and does not care which
 * one answered, so switching is a config change rather than a rewrite.
 */

export class MessageSourceError extends Error {
  constructor(message, { recoverable = false, hint = '' } = {}) {
    super(message);
    this.name = 'MessageSourceError';
    this.recoverable = recoverable;
    this.hint = hint;
  }
}

/* ── session-based ──────────────────────────────────────────────────── */

export class SessionSource {
  static id = 'session';
  static label = 'Gmail session';

  /**
   * @param {{messageId: string, userIndex: string|number, ik: string}} ctx
   * @returns {Promise<string>} raw RFC 5322 source
   */
  async getRawMessage({ messageId, userIndex = 0, ik }) {
    if (!messageId) {
      throw new MessageSourceError('No message is open.', { recoverable: true });
    }
    if (!ik) {
      throw new MessageSourceError(
        'Could not read Gmail\'s session token from the page.',
        { hint: 'Reload the Gmail tab and try again.' },
      );
    }

    const url = `https://mail.google.com/mail/u/${userIndex}/`
      + `?ik=${encodeURIComponent(ik)}&view=om&permmsgid=${encodeURIComponent(messageId)}`;

    const res = await fetch(url, { credentials: 'include' });
    if (!res.ok) {
      throw new MessageSourceError(
        `Gmail refused the request for the original message (HTTP ${res.status}).`,
        { hint: 'If you are signed into several accounts, make sure the right one is active.' },
      );
    }

    const html = await res.text();
    this.lastShowOriginalHtml = html;

    // Prefer the page's own download link: it serves the message verbatim.
    // Scraping the rendered <pre> cannot be trusted for anything
    // cryptographic -- Gmail reflows and escapes it for display, and a single
    // altered byte turns a valid DKIM signature into a reported forgery.
    const download = findDownloadLink(html, res.url || url);
    if (download) {
      const exact = await fetch(download, { credentials: 'include' });
      if (exact.ok) {
        const raw = await exact.text();
        if (looksLikeMessage(raw)) {
          this.lastRetrieval = 'download-original (verbatim)';
          return raw;
        }
      }
    }

    this.lastRetrieval = 'rendered HTML (approximate)';
    return extractRawFromShowOriginal(html);
  }
}

/**
 * Locate the "Download Original" link on the Show-original page.
 *
 * Found by shape rather than by a fixed URL, so a Gmail change to the
 * endpoint does not silently push us back onto the lossy path.
 */
export function findDownloadLink(html, baseUrl) {
  const candidates = [
    /<a[^>]+download[^>]*href=["']([^"']+)["']/i,
    /<a[^>]+href=["']([^"']+)["'][^>]*download/i,
    /href=["']([^"']*view=att[^"']*disp=comp[^"']*)["']/i,
    /href=["']([^"']*view=om[^"']*dmode=txt[^"']*)["']/i,
  ];

  for (const pattern of candidates) {
    const m = html.match(pattern);
    if (!m) continue;
    try {
      return new URL(decodeEntities(m[1]), baseUrl).toString();
    } catch { /* malformed href: try the next shape */ }
  }
  return null;
}

/** A retrieved body must at least look like RFC 5322 before we trust it. */
export function looksLikeMessage(text) {
  if (!text) return false;
  if (/^\s*<(!doctype|html)\b/i.test(text)) return false;   // got a web page
  // Structure, not size: at least one header and a header/body separator.
  return /^[A-Za-z][A-Za-z0-9-]*:\s/m.test(text) && /\r?\n\r?\n/.test(text);
}

/**
 * Gmail's "Show original" page wraps the message in markup. Pull the raw
 * source back out of it.
 *
 * Exported so it can be unit-tested against saved fixtures without a browser.
 */
export function extractRawFromShowOriginal(html) {
  // The raw source is served inside a <pre>; newer layouts wrap it in a div
  // carrying the raw_message_text id. Try the specific case first.
  const byId = html.match(
    /<div[^>]*id=["']raw_message_text["'][^>]*>([\s\S]*?)<\/div>/i,
  );
  const byPre = html.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
  const block = (byId && byId[1]) || (byPre && byPre[1]);

  if (!block) {
    // Some responses are already the bare message rather than a page.
    if (/^[A-Za-z-]+:\s/m.test(html) && /\n\r?\n/.test(html)) return toCrlf(html);
    throw new MessageSourceError(
      'Gmail returned a page this version does not recognise.',
      { hint: 'Gmail may have changed its layout; the Gmail API source is unaffected.' },
    );
  }

  return toCrlf(decodeEntities(stripTags(block)));
}

const toCrlf = (s) => s.replace(/\r?\n/g, '\r\n');

/* Only strip things that are genuinely HTML tags.
 *
 * A naive /<[^>]+>/ also eats `<alice@example.com>`, which would silently
 * empty Return-Path and every address header -- the exact fields the
 * forensic analysis depends on. Requiring a valid tag name immediately after
 * the bracket leaves addresses intact whether or not Gmail encoded them. */
const TAG = /<\/?[a-zA-Z][a-zA-Z0-9:-]*(?:\s[^>]*?)?\/?>/g;

const stripTags = (s) => s.replace(/<br\s*\/?>/gi, '\n').replace(TAG, '');

function decodeEntities(s) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  return s
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&([a-z]+);/gi, (m, n) => (n.toLowerCase() in named ? named[n.toLowerCase()] : m));
}

/* ── Gmail API ──────────────────────────────────────────────────────── */

export class GmailApiSource {
  static id = 'gmail-api';
  static label = 'Gmail API';

  /** @returns {Promise<string>} OAuth access token */
  async #token(interactive = true) {
    return new Promise((resolve, reject) => {
      chrome.identity.getAuthToken({ interactive }, (token) => {
        if (chrome.runtime.lastError || !token) {
          reject(new MessageSourceError(
            chrome.runtime.lastError?.message || 'Authorisation was declined.',
            { recoverable: true, hint: 'Grant read access to continue.' },
          ));
          return;
        }
        resolve(token);
      });
    });
  }

  async getRawMessage({ messageId, legacyMessageId }) {
    // The API keys on the hex id, not the "msg-f:" form used in the DOM.
    const id = legacyMessageId || String(messageId || '').replace(/^#?msg-[af]:/, '');
    if (!id) throw new MessageSourceError('No message is open.', { recoverable: true });

    const token = await this.#token();
    const res = await fetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(id)}?format=raw`,
      { headers: { Authorization: `Bearer ${token}` } },
    );

    if (res.status === 401) {
      // Cached token went stale; drop it so the next attempt re-prompts.
      await new Promise((r) => chrome.identity.removeCachedAuthToken({ token }, r));
      throw new MessageSourceError('Session expired.', { recoverable: true });
    }
    if (!res.ok) {
      throw new MessageSourceError(`Gmail API returned HTTP ${res.status}.`);
    }

    const { raw } = await res.json();
    if (!raw) throw new MessageSourceError('Gmail API returned no message body.');
    this.lastRetrieval = 'Gmail API (verbatim)';
    return base64UrlToText(raw);
  }
}

function base64UrlToText(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, '='));
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder('utf-8').decode(bytes);
}

/* ── selection ──────────────────────────────────────────────────────── */

export const SOURCES = { session: SessionSource, 'gmail-api': GmailApiSource };

export function createSource(id = 'session') {
  const Source = SOURCES[id] || SessionSource;
  return new Source();
}
