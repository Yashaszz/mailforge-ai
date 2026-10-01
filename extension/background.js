/* Service worker.
 *
 * Owns everything the content script cannot do itself: calling the backend
 * (host_permissions exempt it from page CORS) and the Gmail API OAuth flow
 * (chrome.identity is unavailable in content scripts).
 *
 * The session message source deliberately stays in the content script, where
 * a request to mail.google.com is same-origin and carries the user's cookies
 * without any extra permission.
 */

import { analyse, health, getApiBase, setApiBase } from './lib/api.js';
import { GmailApiSource } from './lib/sources.js';

const handlers = {
  /** @param {{raw: string, filename?: string}} msg */
  async analyse({ raw, filename }) {
    return { ok: true, result: await analyse(raw, filename) };
  },

  /** Fetch the raw message through the Gmail API (OAuth path). */
  async fetchViaGmailApi({ messageId, legacyMessageId }) {
    const raw = await new GmailApiSource().getRawMessage({ messageId, legacyMessageId });
    return { ok: true, raw };
  },

  async health() {
    return { ok: true, health: await health() };
  },

  async getSettings() {
    const { source } = await chrome.storage.sync.get({ source: 'session' });
    return { ok: true, apiBase: await getApiBase(), source };
  },

  async setSettings({ apiBase, source }) {
    if (apiBase !== undefined) await setApiBase(apiBase);
    if (source !== undefined) await chrome.storage.sync.set({ source });
    return { ok: true };
  },

  async openReport({ url }) {
    await chrome.tabs.create({ url });
    return { ok: true };
  },
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) {
    sendResponse({ ok: false, error: `Unknown request: ${msg?.type}` });
    return false;
  }

  handler(msg)
    .then(sendResponse)
    .catch((err) => sendResponse({
      ok: false,
      error: err?.message || String(err),
      hint: err?.hint || '',
      recoverable: Boolean(err?.recoverable),
    }));

  return true;           // keep the channel open for the async reply
});
