/* Research mode: measuring how often retrieval fidelity flips a DKIM verdict.
 *
 * For each message analysed, two copies are compared:
 *
 *   verbatim  the bytes from Gmail's own "Download Original" link
 *   rendered  the same message recovered from the "Show original" page markup
 *
 * Both are verified by the backend within seconds of each other, against the
 * same DNS state, so a difference in verdict is attributable to the bytes and
 * nothing else.
 *
 * Privacy by construction: a record holds measurements only. No sender, no
 * recipient, no subject, no content, no domain. The message id is salted and
 * hashed so repeat analyses of one message replace rather than double-count,
 * without the id itself being kept. An export is safe to hand to a colleague.
 *
 * Everything above `storage` is pure and unit-tested.
 */

const enc = new TextEncoder();

/** Byte offset where the header section ends (the blank line), or -1. */
export function headerEnd(text) {
  const crlf = text.indexOf('\r\n\r\n');
  const lf = text.indexOf('\n\n');
  if (crlf === -1) return lf;
  if (lf === -1) return crlf;
  return Math.min(crlf, lf);
}

/**
 * Describe how the rendered copy differs from the verbatim one.
 *
 * `kind` is the coarsest difference that explains the mismatch:
 *   identical     byte-for-byte equal
 *   line-endings  equal once CRLF/LF are normalised
 *   whitespace    equal once all whitespace is removed (reflow, wrapping)
 *   entities      equal once HTML entities are decoded
 *   content       anything else (truncation, dropped or altered text)
 */
export function compareRetrievals(verbatim, rendered) {
  const a = enc.encode(verbatim);
  const b = enc.encode(rendered);

  let first = -1;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) { first = i; break; }
  }
  if (first === -1 && a.length !== b.length) first = n;
  const identical = first === -1;

  // Region is judged on the verbatim copy, by character offset.
  const boundary = headerEnd(verbatim);
  const firstChar = identical ? -1 : charOffset(verbatim, first);
  const region = identical ? 'none'
    : (boundary === -1 || firstChar <= boundary ? 'header' : 'body');

  return {
    identical,
    kind: identical ? 'identical' : diffKind(verbatim, rendered),
    region,
    firstDiffByte: first,
    bytesVerbatim: a.length,
    bytesRendered: b.length,
  };
}

function charOffset(text, byteIndex) {
  // Count characters until their UTF-8 encoding passes byteIndex.
  let bytes = 0;
  let chars = 0;
  for (const ch of text) {
    bytes += enc.encode(ch).length;
    if (bytes > byteIndex) return chars;
    chars += ch.length;
  }
  return chars;
}

function diffKind(verbatim, rendered) {
  const lf = (s) => s.replace(/\r\n/g, '\n');
  if (lf(verbatim) === lf(rendered)) return 'line-endings';
  const bare = (s) => s.replace(/\s+/g, '');
  if (bare(verbatim) === bare(rendered)) return 'whitespace';
  if (bare(decodeEntities(rendered)) === bare(verbatim)) return 'entities';
  return 'content';
}

function decodeEntities(s) {
  const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
  return s
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&([a-z]+);/gi, (m, k) => named[k.toLowerCase()] ?? m);
}

/**
 * Structural features of the verbatim message that plausibly explain a flip.
 * Deliberately excludes anything that identifies a person or organisation.
 */
export function messageFeatures(verbatim) {
  const end = headerEnd(verbatim);
  const head = end === -1 ? verbatim : verbatim.slice(0, end);

  const encodings = [...new Set(
    [...verbatim.matchAll(/^Content-Transfer-Encoding:\s*([A-Za-z0-9-]+)/gim)]
      .map((m) => m[1].toLowerCase()),
  )].sort();

  const top = /^Content-Type:\s*([A-Za-z0-9.+-]+\/[A-Za-z0-9.+-]+)/im.exec(head);

  let maxLine = 0;
  for (const line of verbatim.split(/\r?\n/)) maxLine = Math.max(maxLine, line.length);

  return {
    dkimSignatures: (head.match(/^DKIM-Signature:/gim) || []).length,
    topContentType: top ? top[1].toLowerCase() : 'none',
    encodings: encodings.length ? encodings.join('|') : 'none',
    maxLineLength: maxLine,
    nonAscii: /[^\x00-\x7F]/.test(verbatim),
  };
}

/** One row of the dataset. Field order is the CSV column order. */
export function buildRecord({ msgHash, verbatim, rendered, authVerbatim, authRendered, day }) {
  const diff = compareRetrievals(verbatim, rendered);
  const feat = messageFeatures(verbatim);
  const v = (a, k) => a?.[k]?.result ?? 'error';

  return {
    day,
    msg: msgHash,
    bytes_verbatim: diff.bytesVerbatim,
    bytes_rendered: diff.bytesRendered,
    identical: diff.identical,
    diff_kind: diff.kind,
    diff_region: diff.region,
    first_diff_byte: diff.firstDiffByte,
    dkim_signatures: feat.dkimSignatures,
    top_content_type: feat.topContentType,
    encodings: feat.encodings,
    max_line_length: feat.maxLineLength,
    non_ascii: feat.nonAscii,
    dkim_verbatim: v(authVerbatim, 'dkim'),
    dkim_rendered: v(authRendered, 'dkim'),
    spf_verbatim: v(authVerbatim, 'spf'),
    spf_rendered: v(authRendered, 'spf'),
    dmarc_verbatim: v(authVerbatim, 'dmarc'),
    dmarc_rendered: v(authRendered, 'dmarc'),
    dkim_flipped: v(authVerbatim, 'dkim') !== v(authRendered, 'dkim'),
  };
}

export const COLUMNS = [
  'day', 'msg', 'bytes_verbatim', 'bytes_rendered', 'identical', 'diff_kind',
  'diff_region', 'first_diff_byte', 'dkim_signatures', 'top_content_type',
  'encodings', 'max_line_length', 'non_ascii', 'dkim_verbatim', 'dkim_rendered',
  'spf_verbatim', 'spf_rendered', 'dmarc_verbatim', 'dmarc_rendered', 'dkim_flipped',
];

export function toCsv(records) {
  const cell = (value) => {
    const s = String(value ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [COLUMNS.join(','), ...records.map((r) => COLUMNS.map((c) => cell(r[c])).join(','))]
    .join('\n') + '\n';
}

/** Salted SHA-256, truncated: stable per install, meaningless outside it. */
export async function hashMessageId(messageId, salt) {
  const data = enc.encode(`${salt}:${messageId}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].slice(0, 8)
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

/* ── storage (service worker only) ─────────────────────────────────────── */

export const storage = {
  async salt() {
    const { researchSalt } = await chrome.storage.local.get('researchSalt');
    if (researchSalt) return researchSalt;
    const fresh = [...crypto.getRandomValues(new Uint8Array(16))]
      .map((b) => b.toString(16).padStart(2, '0')).join('');
    await chrome.storage.local.set({ researchSalt: fresh });
    return fresh;
  },

  async all() {
    const { researchRecords = [] } = await chrome.storage.local.get('researchRecords');
    return researchRecords;
  },

  /** Insert, replacing an earlier record for the same message. */
  async put(record) {
    const records = (await this.all()).filter((r) => r.msg !== record.msg);
    records.push(record);
    await chrome.storage.local.set({ researchRecords: records });
    return records.length;
  },

  async clear() {
    await chrome.storage.local.remove('researchRecords');
  },
};
