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

import { analyse, authenticateOnly, health, getApiBase, setApiBase } from './lib/api.js';
import { buildRecord, hashMessageId, storage as research, toCsv } from './lib/research.js';
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
    const { source, researchMode } = await chrome.storage.sync.get(
      { source: 'session', researchMode: false });
    return { ok: true, apiBase: await getApiBase(), source, researchMode };
  },

  async setSettings({ apiBase, source, researchMode }) {
    if (apiBase !== undefined) await setApiBase(apiBase);
    if (source !== undefined) await chrome.storage.sync.set({ source });
    if (researchMode !== undefined) await chrome.storage.sync.set({ researchMode });
    return { ok: true };
  },

  /* Research mode: verify both retrievals of one message back to back, so the
   * bytes are the only variable, and keep measurements only. */
  async 'research:record'({ messageId, verbatim, rendered }) {
    const [authVerbatim, authRendered] = await Promise.all([
      authenticateOnly(verbatim, 'verbatim.eml').catch(() => null),
      authenticateOnly(rendered, 'rendered.eml').catch(() => null),
    ]);
    const record = buildRecord({
      msgHash: await hashMessageId(messageId, await research.salt()),
      day: new Date().toISOString().slice(0, 10),
      verbatim, rendered, authVerbatim, authRendered,
    });
    const total = await research.put(record);
    return { ok: true, record, total };
  },

  async 'research:stats'() {
    const records = await research.all();
    return {
      ok: true,
      total: records.length,
      flipped: records.filter((r) => r.dkim_flipped).length,
      differing: records.filter((r) => !r.identical).length,
    };
  },

  async 'research:export'() {
    return { ok: true, csv: toCsv(await research.all()) };
  },

  async 'research:clear'() {
    await research.clear();
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
