/* Mailforge backend client.
 *
 * Runs in the service worker: extension host_permissions cover the API host,
 * so requests from here are not subject to page CORS and the content script
 * never has to talk to the backend directly.
 */

export const DEFAULT_API = 'https://mailforge-ai1.vercel.app';

export async function getApiBase() {
  const { apiBase } = await chrome.storage.sync.get({ apiBase: DEFAULT_API });
  return String(apiBase || DEFAULT_API).replace(/\/+$/, '');
}

export async function setApiBase(value) {
  await chrome.storage.sync.set({ apiBase: String(value || DEFAULT_API).trim() });
}

export class ApiError extends Error {
  constructor(message, { status = 0 } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/**
 * Analyse a raw RFC 5322 message.
 *
 * The backend takes a multipart upload, which is the same contract the web
 * dashboard uses — one analysis path serving both surfaces rather than a
 * second endpoint that could drift.
 *
 * @param {string} raw
 * @param {string} filename
 * @returns {Promise<object>} the AnalysisResponse
 */
export async function analyse(raw, filename = 'message.eml') {
  if (!raw || !raw.trim()) throw new ApiError('The message was empty.');

  const base = await getApiBase();
  const form = new FormData();
  form.append('file', new Blob([raw], { type: 'message/rfc822' }), filename);

  let res;
  try {
    res = await fetch(`${base}/analyze`, {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(45_000),
    });
  } catch (err) {
    throw new ApiError(
      err.name === 'TimeoutError'
        ? 'The analysis timed out.'
        : `Could not reach the Mailforge backend at ${base}.`,
    );
  }

  let body;
  try {
    body = await res.json();
  } catch {
    throw new ApiError(`Backend returned a non-JSON response (HTTP ${res.status}).`,
      { status: res.status });
  }

  if (!res.ok) {
    throw new ApiError(body?.detail || `Analysis failed (HTTP ${res.status}).`,
      { status: res.status });
  }
  return body;
}

/** Liveness probe, used by the popup. */
export async function health() {
  const base = await getApiBase();
  const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new ApiError(`HTTP ${res.status}`, { status: res.status });
  return res.json();
}

/** Deep link into the full dashboard report. */
export async function reportUrl() {
  return `${await getApiBase()}/`;
}
