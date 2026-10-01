/* The verdict panel rendered inside Gmail.
 *
 * Kept visually close to the Mailforge dashboard so the two read as one
 * product, but restrained: this sits inside someone else's interface, so it
 * stays a card in the message rather than taking over the page.
 */

const LEVEL = {
  'Allow':      { c: '#2f9e63', label: 'Allow' },
  'Suspicious': { c: '#c98a16', label: 'Suspicious' },
  'High-Risk':  { c: '#d2691e', label: 'High risk' },
  'Malicious':  { c: '#d13b4a', label: 'Malicious' },
};

const VERDICT_C = {
  pass: '#2f9e63', fail: '#d13b4a', softfail: '#d2691e', neutral: '#6b7a8c',
  none: '#c98a16', temperror: '#6b7a8c', permerror: '#c98a16', not_checked: '#6b7a8c',
};

const SEV_C = {
  critical: '#d13b4a', high: '#d2691e', medium: '#c98a16',
  low: '#6b7a8c', info: '#2f9e63',
};

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function mountPoint(anchor) {
  let host = document.getElementById('mailforge-panel');
  if (host) return host;

  host = document.createElement('div');
  host.id = 'mailforge-panel';
  host.className = 'mf-panel';

  if (anchor?.parent) {
    anchor.parent.insertBefore(host, anchor.before || null);
  } else if (anchor?.parentElement) {           // legacy single-element anchor
    anchor.parentElement.insertBefore(host, anchor.nextSibling);
  } else {
    anchor?.appendChild(host);
  }
  return host;
}

export function renderLoading(host, message = 'Reading message headers…') {
  host.innerHTML = `
    <div class="mf-card mf-loading">
      <span class="mf-spin" aria-hidden="true"></span>
      <span>${esc(message)}</span>
    </div>`;
}

export function renderError(host, error, hint = '') {
  host.innerHTML = `
    <div class="mf-card mf-error">
      <div class="mf-error-title">Mailforge could not analyse this message</div>
      <div class="mf-error-body">${esc(error)}</div>
      ${hint ? `<div class="mf-error-hint">${esc(hint)}</div>` : ''}
      <button class="mf-btn mf-retry" type="button">Try again</button>
    </div>`;
}

export function renderResult(host, data, { reportBase, raw, retrieval }) {
  const a = data.assessment;
  const level = LEVEL[a.level] || { c: '#6b7a8c', label: a.level };
  const auth = data.authentication;
  const net = data.origin?.network;

  const chips = [['SPF', auth.spf], ['DKIM', auth.dkim], ['DMARC', auth.dmarc]]
    .map(([name, r]) => `
      <span class="mf-chip" style="--c:${VERDICT_C[r.result] || '#6b7a8c'}">
        <b>${name}</b> ${esc(r.result.replace('_', ' '))}
      </span>`).join('');

  const netChip = net?.checked
    ? `<span class="mf-chip" style="--c:${net.is_anonymising ? '#d13b4a' : '#2f9e63'}">
         <b>NETWORK</b> ${esc(net.is_anonymising ? (net.kind || 'proxy') : 'no proxy')}
       </span>`
    : '';

  const top = a.reasons.filter((r) => r.points > 0).slice(0, 4);

  host.innerHTML = `
    <div class="mf-card" style="--level:${level.c}">
      <div class="mf-head">
        <div class="mf-score" style="--level:${level.c}">
          <span>${a.score}</span><small>risk</small>
        </div>
        <div class="mf-headline">
          <div class="mf-level" style="color:${level.c}">${esc(level.label)}</div>
          <div class="mf-summary">${esc(a.summary)}</div>
        </div>
        <button class="mf-close" type="button" title="Dismiss" aria-label="Dismiss">&times;</button>
      </div>

      <div class="mf-chips">${chips}${netChip}</div>

      ${data.origin?.client_ip ? `
        <div class="mf-origin">
          Sent from <b>${esc(data.origin.client_ip)}</b>
          ${data.received_chain?.length
            ? ` · ${data.received_chain.length} relay hop${data.received_chain.length === 1 ? '' : 's'}`
            : ''}
        </div>` : ''}

      ${top.length ? `
        <ul class="mf-reasons">
          ${top.map((r) => `
            <li style="--c:${SEV_C[r.severity] || '#6b7a8c'}">
              <span class="mf-sev">${esc(r.severity)}</span>
              <span class="mf-reason">${esc(r.title)}</span>
            </li>`).join('')}
        </ul>` : ''}

      ${provenance(retrieval)}

      <div class="mf-actions">
        <button class="mf-btn mf-report" type="button">Open full forensic report</button>
        <span class="mf-brand">Mailforge AI</span>
      </div>
    </div>`;

  host.querySelector('.mf-close')?.addEventListener('click', () => host.remove());
  host.querySelector('.mf-report')?.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'openReport', url: reportUrlFor(reportBase, raw) });
  });
}

/* Hand the message to the dashboard through the URL fragment.
 *
 * A fragment never reaches the server, so the message body is not logged or
 * stored anywhere en route, and no report-sharing backend is needed to make
 * the hand-off work. Oversized messages (big attachments) just open the
 * dashboard, where the file can be dropped in directly.
 */
export function reportUrlFor(base, raw) {
  const root = String(base || '').replace(/\/+$/, '') + '/';
  if (!raw) return root;

  const bytes = new TextEncoder().encode(raw);
  if (bytes.length > 400_000) return root;

  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64url = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${root}#eml=${b64url}`;
}

/* Say where the analysed bytes came from.
 *
 * SPF, DKIM and DMARC are computed over exact bytes. If the message had to be
 * recovered from Gmail's rendered HTML, a single reflowed line turns a valid
 * signature into a reported forgery -- so an approximate retrieval is called
 * out rather than presented as a cryptographic result. A security reviewer
 * should be able to see which it was without reading the source.
 */
function provenance(retrieval) {
  if (!retrieval) return '';
  const approximate = /approximate|unknown/i.test(retrieval);

  if (!approximate) {
    return `<div class="mf-prov">Verified over the message verbatim
      · <span>${esc(retrieval)}</span></div>`;
  }
  return `<div class="mf-prov mf-prov-warn">
    Signature results are <b>not reliable</b> for this message: the source had
    to be recovered from Gmail's rendered view (${esc(retrieval)}), which can
    alter bytes that DKIM covers. Switch the message source to
    <b>Gmail API</b> in the extension popup for exact bytes.</div>`;
}
