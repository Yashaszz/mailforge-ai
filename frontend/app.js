/* Mailforge AI — dashboard logic.
   Talks to the FastAPI backend that serves this page. */

'use strict';

const API = '';   // same origin: the backend serves this file

const $ = (id) => document.getElementById(id);

const LEVEL_COLOR = {
  'Allow':      'var(--allow)',
  'Suspicious': 'var(--suspicious)',
  'High-Risk':  'var(--highrisk)',
  'Malicious':  'var(--malicious)',
};

const SEVERITY_COLOR = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--low)',
  info:     'var(--pass)',
};

// Colour each authentication verdict by what it means for trust.
const VERDICT_COLOR = {
  pass:        'var(--pass)',
  fail:        'var(--critical)',
  softfail:    'var(--high)',
  neutral:     'var(--low)',
  none:        'var(--medium)',
  temperror:   'var(--low)',
  permerror:   'var(--medium)',
  not_checked: 'var(--low)',
};

const SAMPLE_ACCENT = {
  '01_legitimate_gmail.eml':     'var(--allow)',
  '02_spoofed_paypal_phish.eml': 'var(--malicious)',
  '03_bec_ceo_wire_fraud.eml':   'var(--highrisk)',
};

const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const bytes = (n) => n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;

/* ── view state ───────────────────────────────────────────── */

function show(which) {
  for (const id of ['empty-state', 'loading', 'error', 'report']) {
    $(id).hidden = id !== which;
  }
}

/* ── boot ─────────────────────────────────────────────────── */

async function boot() {
  try {
    const health = await (await fetch(`${API}/health`)).json();
    const el = $('status');
    el.className = 'status online';
    $('status-text').textContent = health.offline_mode
      ? `v${health.version} · offline mode`
      : `v${health.version} · live DNS`;
  } catch {
    $('status').className = 'status offline';
    $('status-text').textContent = 'backend unreachable';
  }
  loadSamples();
}

async function loadSamples() {
  const box = $('samples');
  try {
    const samples = await (await fetch(`${API}/samples`)).json();
    box.innerHTML = '';
    for (const s of samples) {
      const btn = document.createElement('button');
      btn.className = 'sample';
      btn.innerHTML =
        `<div class="sample-top">
           <span class="sample-badge" style="background:${SAMPLE_ACCENT[s.name] || 'var(--low)'}"></span>
           <span class="sample-title">${esc(s.title)}</span>
         </div>
         <div class="sample-desc">${esc(s.description)}</div>`;
      btn.onclick = () => {
        document.querySelectorAll('.sample').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        analyseSample(s.name, s.title);
      };
      box.appendChild(btn);
    }
  } catch {
    box.innerHTML = '<div class="sample-desc">Could not load samples.</div>';
  }
}

/* ── requests ─────────────────────────────────────────────── */

async function analyseSample(name, title) {
  await run(`${API}/samples/${encodeURIComponent(name)}/analyze`, { method: 'POST' }, title);
}

async function analyseBlob(blob, filename) {
  const form = new FormData();
  form.append('file', blob, filename);
  await run(`${API}/analyze`, { method: 'POST', body: form }, filename);
}

async function run(url, options, label) {
  show('loading');
  $('loading-text').textContent = `Analysing ${label}…`;
  try {
    const res = await fetch(url, options);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
    render(data);
    show('report');
    // Scroll the window, not the report: scrollIntoView would tuck the
    // verdict panel underneath the sticky header.
    window.scrollTo({ top: 0, behavior: 'smooth' });
  } catch (err) {
    $('error-text').textContent = err.message ||
      'Could not reach the backend. Is uvicorn still running?';
    show('error');
  }
}

/* ── rendering ────────────────────────────────────────────── */

function render(d) {
  renderVerdict(d);
  renderAuth(d.authentication);
  renderReasons(d.assessment.reasons);
  renderSender(d);
  renderRelay(d.received_chain, d.origin);
  renderWarnings(d.warnings);
  renderEvidence(d);
}

function renderVerdict(d) {
  const a = d.assessment;
  const colour = LEVEL_COLOR[a.level] || 'var(--low)';
  $('verdict').style.setProperty('--level-color', colour);

  $('level').textContent = a.level;
  $('confidence').textContent = `${a.confidence} confidence`;
  $('summary').textContent = a.summary;
  $('filename').textContent = d.filename || 'pasted message';
  $('filesize').textContent = bytes(d.size_bytes);
  $('subject-line').textContent = d.message.subject || '(no subject)';

  // Animate the score and the gauge arc together.
  const target = a.score;
  const arc = $('gauge-arc');
  const CIRC = 327;
  arc.style.strokeDashoffset = CIRC;
  requestAnimationFrame(() => {
    arc.style.strokeDashoffset = CIRC - (CIRC * target) / 100;
  });

  let n = 0;
  const scoreEl = $('score');
  clearInterval(scoreEl._timer);
  scoreEl._timer = setInterval(() => {
    n += Math.max(1, Math.ceil(target / 28));
    if (n >= target) { n = target; clearInterval(scoreEl._timer); }
    scoreEl.textContent = n;
  }, 24);
}

function renderAuth(auth) {
  const cards = [
    ['SPF', auth.spf, auth.spf.record
      ? `record: ${auth.spf.record}` : (auth.spf.domain ? `checked: ${auth.spf.domain}` : '')],
    ['DKIM', auth.dkim, auth.dkim.signatures.map(
      (s) => `d=${s.domain || '?'} s=${s.selector || '?'} → ${s.result}`).join('\n')],
    ['DMARC', auth.dmarc, auth.dmarc.record
      ? `${auth.dmarc.record_domain}: ${auth.dmarc.record}` : ''],
  ];

  $('auth-grid').innerHTML = cards.map(([name, r, meta]) => `
    <div class="auth-card" style="--c:${VERDICT_COLOR[r.result] || 'var(--low)'}">
      <div class="auth-card-top">
        <span class="auth-name">${name}</span>
        <span class="auth-verdict">${esc(r.result.replace('_', ' '))}</span>
      </div>
      <p class="auth-detail">${esc(r.detail)}</p>
      ${meta ? `<div class="auth-meta">${esc(meta)}</div>` : ''}
    </div>`).join('');

  // DMARC alignment is the detail that explains a brand spoof, so call it out.
  const dm = auth.dmarc;
  const notes = [];
  if (dm.spf_alignment !== 'not_checked' || dm.dkim_alignment !== 'not_checked') {
    notes.push(`DMARC alignment — SPF: ${dm.spf_alignment}, DKIM: ${dm.dkim_alignment}` +
      (dm.policy ? ` · published policy p=${dm.policy}` : ''));
  }
  if (!auth.dns_available) notes.push(...auth.notes);

  const note = $('dns-note');
  note.hidden = notes.length === 0;
  note.textContent = notes.join(' · ');
}

function renderReasons(reasons) {
  if (!reasons.length) {
    $('reasons').innerHTML =
      '<div class="reason"><div class="reason-body">No risk indicators found.</div></div>';
    return;
  }
  $('reasons').innerHTML = reasons.map((r) => `
    <div class="reason" style="--c:${SEVERITY_COLOR[r.severity] || 'var(--low)'}">
      <div class="reason-sev">${esc(r.severity)}</div>
      <div class="reason-body">
        <div class="reason-title">${esc(r.title)}</div>
        <p class="reason-detail">${esc(r.detail)}</p>
      </div>
      <div class="reason-points">${r.points > 0 ? '+' + r.points : '—'}</div>
    </div>`).join('');
}

function renderSender(d) {
  const m = d.message, o = d.origin;
  const mismatch = m.reply_to_domain && m.from_domain && m.reply_to_domain !== m.from_domain;

  const rows = [
    ['From', esc(m.from_address || '—'), ''],
    ['Display name', esc(m.from_display_name || '—'), ''],
    ['Reply-To', esc(m.reply_to_address || '—'), mismatch ? 'warn' : ''],
    ['Envelope', esc(m.envelope_from || '—'), ''],
    ['Origin IP', esc(o.client_ip || 'not recoverable'), o.client_ip_is_public ? 'ok' : 'warn'],
    ['HELO', esc(o.helo || '—'), ''],
    ['Date', esc(m.date ? new Date(m.date).toUTCString() : '—'), ''],
    ['Attachments', m.attachment_count
      ? esc(m.attachment_names.join(', ')) : 'none', m.attachment_count ? 'warn' : ''],
  ];

  $('sender').innerHTML = rows.map(([k, v, cls]) => `
    <div class="kv-row">
      <div class="kv-key">${k}</div>
      <div class="kv-val ${cls}">${v}</div>
    </div>`).join('') + `
    <div class="kv-row">
      <div class="kv-key">IP source</div>
      <div class="kv-val"><span class="kv-note">${esc(o.client_ip_source || '—')}</span></div>
    </div>`;
}

function renderRelay(chain, origin) {
  $('hop-count').textContent = chain.length ? `(${chain.length} hops)` : '';
  if (!chain.length) {
    $('relay').innerHTML =
      '<div class="hop-meta">No Received headers — the relay path cannot be reconstructed.</div>';
    return;
  }
  // Rendered oldest-first so the path reads in the direction the mail travelled.
  $('relay').innerHTML = [...chain].reverse().map((h) => {
    const isOrigin = h.from_ip && h.from_ip === origin.client_ip;
    const cls = isOrigin ? 'origin' : (h.from_ip_is_public ? 'public' : '');
    const tag = isOrigin
      ? '<span class="hop-tag">origin</span>'
      : (h.from_ip && !h.from_ip_is_public ? '<span class="hop-tag internal">internal</span>' : '');
    return `
      <div class="hop ${cls}">
        <div class="hop-dot"></div>
        <div class="hop-body">
          <div class="hop-host">${esc(h.from_host || 'unknown')}${
            h.from_ip ? ` <span class="hop-ip">[${esc(h.from_ip)}]</span>` : ''}${tag}</div>
          <div class="hop-meta">→ ${esc(h.by_host || '?')}${
            h.protocol ? ` · ${esc(h.protocol)}` : ''}${
            h.timestamp ? ` · ${new Date(h.timestamp).toUTCString()}` : ''}</div>
        </div>
      </div>`;
  }).join('');
}

function renderWarnings(warnings) {
  $('warnings-wrap').hidden = !warnings.length;
  $('warnings').innerHTML = warnings.map((w) => `<div>${esc(w)}</div>`).join('');
}

function renderEvidence(d) {
  $('header-count').textContent = `(${d.all_headers.length})`;
  $('headers').innerHTML = d.all_headers.map((h) =>
    `<tr><td>${esc(h.name)}</td><td>${esc(h.value)}</td></tr>`).join('');
  $('mta-results').textContent = d.reported_authentication_results.length
    ? d.reported_authentication_results.join('\n\n')
    : 'The receiving MTA did not stamp an Authentication-Results header.';
  $('raw-json').textContent = JSON.stringify(d, null, 2);
}

/* ── input handling ───────────────────────────────────────── */

const dz = $('dropzone');
const fileInput = $('file-input');

dz.onclick = () => fileInput.click();
dz.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } };
fileInput.onchange = () => {
  if (fileInput.files[0]) analyseBlob(fileInput.files[0], fileInput.files[0].name);
};

['dragenter', 'dragover'].forEach((ev) =>
  dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('dragover'); }));
['dragleave', 'drop'].forEach((ev) =>
  dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('dragover'); }));
dz.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files[0];
  if (f) analyseBlob(f, f.name);
});

$('paste-btn').onclick = () => {
  const text = $('paste-area').value.trim();
  if (!text) return;
  analyseBlob(new Blob([text], { type: 'message/rfc822' }), 'pasted.eml');
};

boot();
