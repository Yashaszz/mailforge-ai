/* Mailforge AI — dashboard.
   Talks to the FastAPI backend that serves this page. */

'use strict';

const API = '';                       // same origin
const $ = (id) => document.getElementById(id);
const root = document.documentElement;

const LEVEL_COLOR = {
  'Allow': 'var(--allow)', 'Suspicious': 'var(--suspicious)',
  'High-Risk': 'var(--highrisk)', 'Malicious': 'var(--malicious)',
};
const SEVERITY_COLOR = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)',
  low: 'var(--low)', info: 'var(--pass)',
};
// Each authentication verdict coloured by what it means for trust.
const VERDICT_COLOR = {
  pass: 'var(--pass)', fail: 'var(--critical)', softfail: 'var(--high)',
  neutral: 'var(--low)', none: 'var(--medium)', temperror: 'var(--low)',
  permerror: 'var(--medium)', not_checked: 'var(--low)',
};
const SAMPLE_ACCENT = {
  '01_legitimate_gmail.eml': 'var(--allow)',
  '02_spoofed_paypal_phish.eml': 'var(--malicious)',
  '03_bec_ceo_wire_fraud.eml': 'var(--highrisk)',
  '04_multihop_relay_laundering.eml': 'var(--malicious)',
};

const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const bytes = (n) => (n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`);

let lastResult = null;
let sampleNames = [];

/* ══ preferences ═══════════════════════════════════════════════════════ */

const DEFAULTS = { theme: 'midnight', accent: 'amber', density: 'comfortable', wire: true, motion: true };
let prefs = { ...DEFAULTS };

function loadPrefs() {
  try {
    Object.assign(prefs, JSON.parse(localStorage.getItem('mailforge.prefs') || '{}'));
  } catch { /* first visit, private window, or blocked storage */ }
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) prefs.motion = false;
  applyPrefs();
}

function savePrefs() {
  try { localStorage.setItem('mailforge.prefs', JSON.stringify(prefs)); } catch { /* non-fatal */ }
}

function applyPrefs() {
  root.dataset.theme = prefs.theme;
  root.dataset.accent = prefs.accent;
  root.dataset.density = prefs.density;
  document.body.classList.toggle('wire-off', !prefs.wire);
  document.body.classList.toggle('motion-off', !prefs.motion);

  for (const b of document.querySelectorAll('[data-theme-value]'))
    b.setAttribute('aria-pressed', b.dataset.themeValue === prefs.theme);
  for (const b of document.querySelectorAll('[data-accent-value]'))
    b.setAttribute('aria-pressed', b.dataset.accentValue === prefs.accent);
  for (const b of document.querySelectorAll('[data-density-value]'))
    b.setAttribute('aria-pressed', b.dataset.densityValue === prefs.density);
  $('wire-toggle').setAttribute('aria-checked', prefs.wire);
  $('motion-toggle').setAttribute('aria-checked', prefs.motion);

  requestAnimationFrame(() => { wire.build(); aurora.reconfigure(); });
}

function setPref(key, value) { prefs[key] = value; savePrefs(); applyPrefs(); }

/* ══ ambient background ════════════════════════════════════════════════ */

/* Slow-drifting soft blobs. Organic on purpose: no grid, no scanlines. */
const aurora = (() => {
  const canvas = $('bg-canvas');
  const ctx = canvas.getContext('2d');
  let blobs = [], raf = null, w = 0, h = 0;

  function accentRGB() {
    // Resolve the theme's accent once per reconfigure rather than per frame.
    const probe = document.createElement('div');
    probe.style.color = getComputedStyle(root).getPropertyValue('--accent');
    document.body.appendChild(probe);
    const rgb = getComputedStyle(probe).color.match(/\d+/g).map(Number);
    probe.remove();
    return rgb;
  }

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = canvas.width = innerWidth * dpr;
    h = canvas.height = innerHeight * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function reconfigure() {
    resize();
    const [r, g, b] = accentRGB();
    const light = root.dataset.theme === 'daylight';
    blobs = [
      { x: .18, y: .12, r: .42, c: [r, g, b], a: light ? .10 : .16, sx: .00007, sy: .00005 },
      { x: .82, y: .24, r: .38, c: [90, 140, 235], a: light ? .07 : .12, sx: -.00005, sy: .00008 },
      { x: .55, y: .82, r: .46, c: [r, g, b], a: light ? .06 : .09, sx: .00004, sy: -.00006 },
    ];
    draw(0);
  }

  function draw(t) {
    ctx.clearRect(0, 0, innerWidth, innerHeight);
    for (const bl of blobs) {
      const cx = (bl.x + Math.sin(t * bl.sx) * .07) * innerWidth;
      const cy = (bl.y + Math.cos(t * bl.sy) * .07) * innerHeight;
      const rad = bl.r * Math.max(innerWidth, innerHeight);
      const grd = ctx.createRadialGradient(cx, cy, 0, cx, cy, rad);
      grd.addColorStop(0, `rgba(${bl.c[0]},${bl.c[1]},${bl.c[2]},${bl.a})`);
      grd.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = grd;
      ctx.fillRect(0, 0, innerWidth, innerHeight);
    }
  }

  function loop(t) {
    draw(t);
    raf = requestAnimationFrame(loop);
  }

  function start() {
    cancelAnimationFrame(raf);
    if (prefs.motion) raf = requestAnimationFrame(loop);
    else draw(0);
  }

  addEventListener('resize', () => { resize(); draw(performance.now()); }, { passive: true });

  return { reconfigure: () => { reconfigure(); start(); } };
})();

/* ══ forensic trace wire ═══════════════════════════════════════════════ */

/* An S-curve drawn down the report that fills as you scroll, with a head
   that rides the path and a node per section. It is the trace, not decor. */
const wire = (() => {
  const svg = $('trace-wire');
  const results = $('results');
  const W = 52;
  let path = null, len = 0, samples = [], nodes = [];

  function build() {
    if (!prefs.wire) return;
    const h = results.offsetHeight;
    if (h < 200) return;

    svg.setAttribute('width', W);
    svg.setAttribute('height', h);
    svg.setAttribute('viewBox', `0 0 ${W} ${h}`);

    // Gentle serpentine: amplitude scaled so it never crowds the content.
    const mid = W / 2, amp = W * 0.32;
    const segs = Math.max(3, Math.round(h / 320));
    let d = `M ${mid} 0`;
    for (let i = 0; i < segs; i++) {
      const y0 = (h / segs) * i, y1 = (h / segs) * (i + 1);
      const dir = i % 2 === 0 ? 1 : -1;
      d += ` C ${mid + amp * dir} ${y0 + (y1 - y0) * .35},`
         + ` ${mid + amp * dir} ${y0 + (y1 - y0) * .65},`
         + ` ${mid} ${y1}`;
    }

    svg.innerHTML = `
      <defs>
        <linearGradient id="wire-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stop-color="var(--accent-2)"/>
          <stop offset="100%" stop-color="var(--accent)"/>
        </linearGradient>
      </defs>
      <path class="wire-base" d="${d}"/>
      <path class="wire-draw" id="wire-draw" d="${d}"/>
      <g id="wire-nodes"></g>
      <circle class="wire-head-halo" id="wire-halo" r="9" cx="-99" cy="-99"/>
      <circle class="wire-head" id="wire-head" r="4" cx="-99" cy="-99"/>`;

    path = $('wire-draw');
    len = path.getTotalLength();
    path.style.strokeDasharray = len;
    path.style.strokeDashoffset = len;

    // Sample the curve once so we can map any y to a point on it cheaply.
    samples = [];
    for (let i = 0; i <= 260; i++) samples.push(path.getPointAtLength((len * i) / 260));

    // One node per labelled section, placed where the wire crosses its top.
    const group = $('wire-nodes');
    nodes = [];
    const top = results.getBoundingClientRect().top + scrollY;
    for (const el of document.querySelectorAll('[data-wire-node]')) {
      if (el.offsetParent === null) continue;
      const y = el.getBoundingClientRect().top + scrollY - top + 10;
      const p = pointAtY(y);
      const ns = 'http://www.w3.org/2000/svg';
      const c = document.createElementNS(ns, 'circle');
      c.setAttribute('class', 'wire-node');
      c.setAttribute('cx', p.x); c.setAttribute('cy', y); c.setAttribute('r', 4);
      group.appendChild(c);
      nodes.push({ el, dot: c, y });
    }
    update();
  }

  function pointAtY(y) {
    let best = samples[0], diff = Infinity;
    for (const s of samples) {
      const d = Math.abs(s.y - y);
      if (d < diff) { diff = d; best = s; }
    }
    return best;
  }

  function update() {
    if (!prefs.wire || !path) return;
    const rect = results.getBoundingClientRect();
    // Progress of the viewport's midpoint through the report.
    const seen = innerHeight * 0.5 - rect.top;
    const progress = Math.max(0, Math.min(1, seen / rect.height));

    path.style.strokeDashoffset = len * (1 - progress);

    const p = path.getPointAtLength(len * progress);
    for (const id of ['wire-head', 'wire-halo']) {
      const el = $(id);
      if (el) { el.setAttribute('cx', p.x); el.setAttribute('cy', p.y); }
    }

    const cutoff = rect.height * progress;
    for (const n of nodes) n.dot.classList.toggle('lit', n.y <= cutoff + 12);
  }

  addEventListener('resize', () => { svg.innerHTML = ''; build(); }, { passive: true });
  return { build, update };
})();

/* ══ scroll ════════════════════════════════════════════════════════════ */

let ticking = false;
addEventListener('scroll', () => {
  if (ticking) return;
  ticking = true;
  requestAnimationFrame(() => {
    const max = document.body.scrollHeight - innerHeight;
    $('scroll-progress').style.width = `${max > 0 ? (scrollY / max) * 100 : 0}%`;
    wire.update();
    if (max > 0 && scrollY >= max - 4) forceRevealAll();
    ticking = false;
  });
}, { passive: true });

const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach((e, i) => {
    if (!e.isIntersecting) return;
    setTimeout(() => e.target.classList.add('shown'), prefs.motion ? i * 55 : 0);
    revealObserver.unobserve(e.target);
  });
}, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });

function observeReveals() {
  for (const el of document.querySelectorAll('[data-reveal]:not(.shown)')) revealObserver.observe(el);
}

/* Safety net: content must never stay invisible because an observer missed.
   Anything still hidden once the user reaches the bottom is forced visible. */
function forceRevealAll() {
  for (const el of document.querySelectorAll('[data-reveal]:not(.shown)')) {
    revealObserver.unobserve(el);
    el.classList.add('shown');
  }
}

/* ══ pointer glow ══════════════════════════════════════════════════════ */

(() => {
  const glow = $('cursor-glow');
  let x = innerWidth / 2, y = innerHeight / 2, tx = x, ty = y, raf = null;
  addEventListener('pointermove', (e) => {
    tx = e.clientX; ty = e.clientY;
    document.body.classList.add('pointer-active');
    if (!raf && prefs.motion) raf = requestAnimationFrame(follow);
  }, { passive: true });
  function follow() {
    // Lag the pointer so the glow feels like a physical light, not a cursor.
    x += (tx - x) * .07; y += (ty - y) * .07;
    glow.style.transform = `translate(${x}px, ${y}px)`;
    raf = Math.abs(tx - x) > .5 || Math.abs(ty - y) > .5 ? requestAnimationFrame(follow) : null;
  }
})();

/* ══ view state ════════════════════════════════════════════════════════ */

function show(which) {
  for (const id of ['empty-state', 'loading', 'error', 'report']) $(id).hidden = id !== which;
}

/* On desktop the report sits beside the sidebar, so the top of the page is
   already the right place to be. In the stacked single-column layout it is
   not: scrolling to the top would show the sidebar again and leave the user
   hunting for the result they just asked for. */
function scrollToResult() {
  const behavior = prefs.motion ? 'smooth' : 'auto';
  const stacked = window.matchMedia('(max-width: 1100px)').matches;
  if (!stacked) return window.scrollTo({ top: 0, behavior });

  const top = $('results').getBoundingClientRect().top + scrollY
    - (document.querySelector('.topbar')?.offsetHeight || 64) - 8;
  window.scrollTo({ top: Math.max(0, top), behavior });
}

function toast(message) {
  const t = $('toast');
  t.textContent = message;
  t.hidden = false;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.hidden = true; }, 2200);
}

/* ══ boot ══════════════════════════════════════════════════════════════ */

async function boot() {
  loadPrefs();
  try {
    const health = await (await fetch(`${API}/health`)).json();
    $('status').className = 'status online';
    $('status-text').textContent = health.offline_mode
      ? `v${health.version} · offline mode` : `v${health.version} · live DNS`;
  } catch {
    $('status').className = 'status offline';
    $('status-text').textContent = 'backend unreachable';
  }
  await loadSamples();
  observeReveals();
}

async function loadSamples() {
  const box = $('samples');
  try {
    const samples = await (await fetch(`${API}/samples`)).json();
    sampleNames = samples.map((s) => s.name);
    box.innerHTML = '';
    samples.forEach((s, i) => {
      const btn = document.createElement('button');
      btn.className = 'sample';
      btn.style.setProperty('--s', SAMPLE_ACCENT[s.name] || 'var(--low)');
      btn.innerHTML =
        `<div class="sample-top">
           <span class="sample-badge"></span>
           <span class="sample-title">${esc(s.title)}</span>
         </div>
         <div class="sample-desc">${esc(s.description)}</div>`;
      btn.onclick = () => selectSample(i);
      box.appendChild(btn);
    });
  } catch {
    box.innerHTML = '<div class="sample-desc">Could not load samples.</div>';
  }
}

function selectSample(index) {
  const buttons = [...document.querySelectorAll('.sample')];
  if (!buttons[index]) return;
  buttons.forEach((b) => b.classList.remove('active'));
  buttons[index].classList.add('active');
  const title = buttons[index].querySelector('.sample-title').textContent;
  run(`${API}/samples/${encodeURIComponent(sampleNames[index])}/analyze`, { method: 'POST' }, title);
}

/* ══ requests ══════════════════════════════════════════════════════════ */

function analyseBlob(blob, filename) {
  const form = new FormData();
  form.append('file', blob, filename);
  run(`${API}/analyze`, { method: 'POST', body: form }, filename);
}

async function run(url, options, label) {
  show('loading');
  $('loading-text').textContent = `Analysing ${label}…`;

  // Walk the step list so the wait reads as progress, not a frozen spinner.
  const steps = [...$('loading-steps').children];
  steps.forEach((s) => { s.className = ''; });
  let step = 0;
  steps[0].classList.add('active');
  const stepper = setInterval(() => {
    if (step >= steps.length - 1) return;
    steps[step].className = 'done';
    steps[++step].className = 'active';
  }, 260);

  try {
    const res = await fetch(url, options);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
    lastResult = data;
    render(data);
    show('report');
    scrollToResult();
    requestAnimationFrame(() => { observeReveals(); wire.build(); });
  } catch (err) {
    $('error-text').textContent = err.message
      || 'Could not reach the backend. Is uvicorn still running?';
    show('error');
  } finally {
    clearInterval(stepper);
  }
}

/* ══ rendering ═════════════════════════════════════════════════════════ */

function render(d) {
  for (const el of document.querySelectorAll('#report [data-reveal]')) el.classList.remove('shown');
  renderVerdict(d);
  renderAuth(d.authentication);
  renderReasons(d.assessment.reasons);
  renderSender(d);
  renderRelay(d.received_chain, d.origin);
  renderWarnings(d.warnings);
  renderEvidence(d);
  renderGeo(d);
  renderMap(d);
}

/* ══ geographic route ══════════════════════════════════════════════════
   Plots every locatable relay hop on an equirectangular world map, oldest
   first, so the path reads in the direction the mail actually travelled. */

let worldPath = null;

async function loadWorld() {
  if (worldPath !== null) return worldPath;
  try {
    const res = await fetch('world.json');
    worldPath = (await res.json()).d;
  } catch {
    worldPath = '';
  }
  return worldPath;
}

/* Equirectangular: the map is authored in a 360x180 viewBox, 1 unit = 1 degree. */
const project = (lat, lon) => ({ x: lon + 180, y: 90 - lat });

async function renderMap(d) {
  const status = $('map-status');
  const svg = $('worldmap');
  const legend = $('route-legend');
  svg.innerHTML = '';
  legend.innerHTML = '';
  $('map-caption').textContent = '';
  status.hidden = false;
  status.textContent = 'Plotting relay path…';

  // Oldest hop first: the order the message actually travelled.
  const ips = [];
  const netByIp = {};
  for (const hop of [...d.received_chain].reverse()) {
    if (hop.from_ip_is_public && !ips.includes(hop.from_ip)) {
      ips.push(hop.from_ip);
      if (hop.network) netByIp[hop.from_ip] = hop.network;
    }
  }
  if (!ips.length) {
    status.textContent = 'No publicly routable hop in the relay chain, so the '
      + 'route cannot be plotted.';
    return;
  }

  const [land, ...located] = await Promise.all([loadWorld(), ...ips.map(geolocate)]);
  const points = [];
  located.forEach((geo, i) => {
    if (geo && geo.latitude != null && geo.longitude != null) {
      points.push({ ip: ips[i], geo, ...project(geo.latitude, geo.longitude) });
    }
  });

  if (!points.length) {
    status.textContent = 'Geolocation unavailable, so the route could not be plotted. '
      + 'The relay chain itself is listed above.';
    return;
  }
  status.hidden = true;

  const countries = [...new Set(points.map((p) => p.geo.country).filter(Boolean))];
  $('map-caption').textContent = `(${points.length} located ${
    points.length === 1 ? 'hop' : 'hops'}, ${countries.length} ${
    countries.length === 1 ? 'country' : 'countries'})`;

  const svgns = 'http://www.w3.org/2000/svg';
  const parts = [];

  if (land) parts.push(`<path class="land" d="${land}"/>`);

  // Graticule every 30 degrees, for a sense of scale.
  let grat = '';
  for (let lon = 0; lon <= 360; lon += 30) grat += `M${lon} 0V180`;
  for (let lat = 0; lat <= 180; lat += 30) grat += `M0 ${lat}H360`;
  parts.push(`<path class="graticule" d="${grat}"/>`);

  // Arcs between consecutive hops, bowed perpendicular to the leg so the
  // path reads as a route rather than a straight line through the map.
  points.slice(0, -1).forEach((a, i) => {
    const b = points[i + 1];
    const dx = b.x - a.x, dy = b.y - a.y;
    const dist = Math.hypot(dx, dy) || 1;
    const bow = Math.min(dist * 0.28, 26);
    const cx = (a.x + b.x) / 2 - (dy / dist) * bow;
    const cy = (a.y + b.y) / 2 + (dx / dist) * bow;
    const len = dist + bow;
    parts.push(`<path class="route-arc animate" style="--len:${len.toFixed(1)};`
      + `--delay:${(i * 0.32).toFixed(2)}s" d="M${a.x.toFixed(1)} ${a.y.toFixed(1)} `
      + `Q${cx.toFixed(1)} ${cy.toFixed(1)} ${b.x.toFixed(1)} ${b.y.toFixed(1)}"/>`);
  });

  points.forEach((p, i) => {
    const role = i === 0 ? 'start' : (i === points.length - 1 ? 'end' : 'mid');
    const colour = role === 'start' ? 'var(--critical)'
      : role === 'end' ? 'var(--pass)' : 'var(--medium)';
    if (role === 'start') {
      parts.push(`<circle class="hop-halo ping" style="color:${colour}" `
        + `cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="1.6"/>`);
    }
    parts.push(`<circle class="hop-marker ${role}" cx="${p.x.toFixed(1)}" `
      + `cy="${p.y.toFixed(1)}" r="1.9"/>`);
    const label = p.geo.city || p.geo.country || '';
    if (label) {
      const flip = p.x > 300;                    // keep labels inside the frame
      parts.push(`<text class="map-label" x="${(p.x + (flip ? -3 : 3)).toFixed(1)}" `
        + `y="${(p.y + 1.2).toFixed(1)}"${flip ? ' text-anchor="end"' : ''}>${esc(label)}</text>`);
    }
  });

  svg.innerHTML = parts.join('');

  legend.innerHTML = points.map((p, i) => {
    const colour = i === 0 ? 'var(--critical)'
      : i === points.length - 1 ? 'var(--pass)' : 'var(--medium)';
    const role = i === 0 ? 'origin' : (i === points.length - 1 ? 'last relay before delivery' : 'transit');
    const conn = p.geo.connection || {};
    const net = netByIp[p.ip];
    return `<li style="--c:${colour}">
      <span>
        <span class="rl-place">${esc([p.geo.city, p.geo.country].filter(Boolean).join(', '))}</span>
        ${netBadge(net)}
        <span class="rl-meta"> · ${esc(p.ip)}${conn.isp ? ' · ' + esc(conn.isp) : ''}</span>
        <span class="rl-meta"> — ${role}</span>
      </span></li>`;
  }).join('');
}

/* ══ origin intelligence ═══════════════════════════════════════════════
   Geolocation runs in the browser rather than the backend: it keeps the
   serverless function fast, needs no API key, and a failure degrades to a
   message instead of holding up the verdict. */

const GEO_CACHE = new Map();

async function geolocate(ip) {
  if (!ip) return null;
  if (GEO_CACHE.has(ip)) return GEO_CACHE.get(ip);
  let result = null;
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`,
      { signal: AbortSignal.timeout?.(6000) });
    const data = await res.json();
    if (data && data.success) result = data;
  } catch { /* offline, blocked, rate-limited: handled by the caller */ }
  GEO_CACHE.set(ip, result);
  return result;
}

/* A styled country-code badge rather than a flag emoji: Windows ships no
   regional-indicator glyphs, so flags there degrade to bare letters. This
   renders identically everywhere and needs no image assets. */
const flagFor = (cc) => (cc && cc.length === 2) ? cc.toUpperCase() : '??';

/* Mail sent through a webmail or relay provider leaves that provider's
   datacentre, not the sender's machine. Geolocating it tells you where
   Google is, not where the person is -- and comparing the Date header
   against the datacentre's timezone produces a mismatch on every perfectly
   ordinary message. Both have to be reported differently. */
const PROVIDER_RELAYS = [
  [/\bgoogle\b/i, 'Google (Gmail)'],
  [/\bmicrosoft\b|\boutlook\b|\bhotmail\b/i, 'Microsoft (Outlook)'],
  [/\bamazon\b|\baws\b/i, 'Amazon SES'],
  [/\byahoo\b/i, 'Yahoo'],
  [/\bproton\b/i, 'Proton Mail'],
  [/\bzoho\b/i, 'Zoho'],
  [/\bapple\b|\bicloud\b/i, 'Apple iCloud'],
  [/sendgrid|mailgun|mailchimp|sparkpost|postmark/i, 'a bulk email platform'],
  [/mimecast|proofpoint|barracuda|\bcisco\b/i, 'a mail security gateway'],
];

function detectProvider(geo) {
  const conn = geo?.connection || {};
  const haystack = `${conn.isp || ''} ${conn.org || ''}`;
  for (const [pattern, name] of PROVIDER_RELAYS) {
    if (pattern.test(haystack)) return name;
  }
  return null;
}

/** Minutes of UTC offset in an ISO timestamp, or null if it carries none. */
function offsetMinutes(iso) {
  const m = /([+-])(\d{2}):?(\d{2})$/.exec(String(iso || '').trim());
  if (!m) return /Z$/.test(String(iso || '')) ? 0 : null;
  return (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3]));
}

const fmtOffset = (mins) => {
  const sign = mins < 0 ? '-' : '+';
  const a = Math.abs(mins);
  return `${sign}${String(Math.floor(a / 60)).padStart(2, '0')}:${String(a % 60).padStart(2, '0')}`;
};

async function renderGeo(d) {
  const box = $('geo');
  const ip = d.origin.client_ip;
  $('geo-source').textContent = '';

  if (!ip) {
    box.innerHTML = '<div class="geo-empty">No origin IP could be recovered from the '
      + 'headers, so the sender cannot be located.</div>';
    return;
  }

  box.innerHTML = `<div class="geo-loading">Locating ${esc(ip)}…</div>`;
  const geo = await geolocate(ip);

  if (!geo) {
    // Network reputation comes from our own backend, so it survives a failed
    // geolocation lookup and must still be shown.
    box.innerHTML = '<div class="geo-empty">Geolocation lookup unavailable — the '
      + `IP (${esc(ip)}) is still reported above and every other check is `
      + `unaffected.</div>${netAlert(d.origin.network)}`;
    return;
  }

  $('geo-source').textContent = '(ipwho.is)';
  const conn = geo.connection || {};
  const tz = geo.timezone || {};

  const tiles = [
    ['ISP', conn.isp || conn.org || '—'],
    ['Autonomous system', conn.asn ? `AS${conn.asn}` : '—'],
    ['Coordinates', (geo.latitude != null && geo.longitude != null)
      ? `${geo.latitude.toFixed(3)}, ${geo.longitude.toFixed(3)}` : '—'],
    ['Server timezone', tz.id ? `${tz.id} (${tz.utc || '?'})` : '—'],
  ];

  const provider = detectProvider(geo);
  const net = d.origin.network;

  box.innerHTML = `
    <div class="geo-main">
      <div class="geo-flag">${flagFor(geo.country_code)}</div>
      <div class="geo-place">
        <div class="geo-country">${esc(geo.country || 'Unknown')}${netBadge(net)}</div>
        <div class="geo-city">${esc([geo.city, geo.region].filter(Boolean).join(', ') || '—')}
          &nbsp;·&nbsp; ${esc(ip)}</div>
        <div class="geo-role">Location of the sending mail server</div>
      </div>
    </div>
    ${netAlert(net)}
    <dl class="geo-grid">
      ${tiles.map(([k, v]) => `<div class="geo-tile"><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('')}
    </dl>
    ${provider ? providerNote(provider, geo) : timezoneVerdict(d, tz)}`;
}

/** VPN / Tor / clean badge beside the country name. */
function netBadge(net) {
  if (!net || !net.checked) return '';
  const kind = (net.kind || '').toUpperCase();
  if (!net.is_anonymising) return '<span class="net-badge clean">no proxy</span>';
  return `<span class="net-badge ${kind === 'TOR' ? 'tor' : 'vpn'}">${esc(kind || 'PROXY')}</span>`;
}

/** Called out separately, because an anonymised sender is the finding. */
function netAlert(net) {
  if (!net || !net.checked || !net.is_anonymising) return '';
  const tor = (net.kind || '').toUpperCase() === 'TOR';
  return `<div class="geo-alert${tor ? '' : ' warn'}"><span>${tor ? '⛔' : '⚠'}</span><span>
    ${esc(net.detail)}${net.risk != null
      ? ` <b>Reputation risk score: ${net.risk}/100.</b>` : ''}</span></div>`;
}

/** Explain why a provider datacentre is not the sender's location. */
function providerNote(provider, geo) {
  return `<div class="geo-alert info"><span>ⓘ</span><span>This message was relayed by
    <b>${esc(provider)}</b>, so ${esc(geo.city || 'this location')} is that provider's
    datacentre — <b>not the sender's own location</b>, which webmail does not expose in
    the headers. Timezone comparison is skipped here because a mismatch is expected for
    provider-relayed mail and would mean nothing.</span></div>`;
}

/** Compare the timezone the message claims against where it was really sent. */
function timezoneVerdict(d, tz) {
  const claimed = offsetMinutes(d.message.date);
  const actual = offsetMinutes(`2000-01-01T00:00:00${tz.utc || ''}`);
  if (claimed === null || actual === null) return '';

  const drift = Math.abs(claimed - actual);
  if (drift <= 60) {
    return `<div class="geo-alert ok"><span>✓</span><span>The message's stated timezone
      (<b>${fmtOffset(claimed)}</b>) matches the sending server's location
      (<b>${fmtOffset(actual)}</b>).</span></div>`;
  }
  return `<div class="geo-alert"><span>⚠</span><span>The <code>Date</code> header claims
    <b>${fmtOffset(claimed)}</b>, but the sending server sits at
    <b>${fmtOffset(actual)}</b> — a ${(drift / 60).toFixed(1).replace(/\.0$/, '')}&nbsp;hour
    discrepancy.
    Mail composed in one region and relayed through infrastructure in another is
    common in outsourced phishing operations.</span></div>`;
}

function renderVerdict(d) {
  const a = d.assessment;
  $('verdict').style.setProperty('--level-color', LEVEL_COLOR[a.level] || 'var(--low)');
  $('level').textContent = a.level;
  $('confidence').textContent = `${a.confidence} confidence`;
  $('summary').textContent = a.summary;
  $('filename').textContent = d.filename || 'pasted message';
  $('filesize').textContent = bytes(d.size_bytes);
  $('subject-line').textContent = d.message.subject || '(no subject)';

  const CIRC = 339;
  const arc = $('gauge-arc');
  arc.style.strokeDashoffset = CIRC;
  requestAnimationFrame(() => { arc.style.strokeDashoffset = CIRC - (CIRC * a.score) / 100; });

  const el = $('score');
  clearInterval(el._timer);
  if (!prefs.motion) { el.textContent = a.score; return; }
  let n = 0;
  el._timer = setInterval(() => {
    n += Math.max(1, Math.ceil(a.score / 30));
    if (n >= a.score) { n = a.score; clearInterval(el._timer); }
    el.textContent = n;
  }, 22);
}

function renderAuth(auth) {
  const cards = [
    ['SPF', auth.spf, auth.spf.record ? `record: ${auth.spf.record}`
      : (auth.spf.domain ? `checked: ${auth.spf.domain}` : '')],
    ['DKIM', auth.dkim, auth.dkim.signatures
      .map((s) => `d=${s.domain || '?'} s=${s.selector || '?'} → ${s.result}`).join('\n')],
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
    notes.push(`DMARC alignment — SPF: ${dm.spf_alignment}, DKIM: ${dm.dkim_alignment}`
      + (dm.policy ? ` · published policy p=${dm.policy}` : ''));
  }
  if (!auth.dns_available) notes.push(...auth.notes);
  const note = $('dns-note');
  note.hidden = notes.length === 0;
  note.textContent = notes.join(' · ');
}

function renderReasons(reasons) {
  if (!reasons.length) {
    $('reasons').innerHTML = '<div class="reason"><div class="reason-head">No risk indicators found.</div></div>';
    return;
  }
  $('reasons').innerHTML = reasons.map((r, i) => `
    <div class="reason ${i === 0 ? 'open' : ''}" style="--c:${SEVERITY_COLOR[r.severity] || 'var(--low)'}">
      <button class="reason-head" aria-expanded="${i === 0}">
        <span class="reason-sev">${esc(r.severity)}</span>
        <span class="reason-title">${esc(r.title)}</span>
        <span class="reason-points">${r.points > 0 ? '+' + r.points : '—'}</span>
        <svg class="reason-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="m6 9 6 6 6-6"/></svg>
      </button>
      <div class="reason-detail"><p>${esc(r.detail)}</p></div>
    </div>`).join('');

  for (const head of $('reasons').querySelectorAll('.reason-head')) {
    head.onclick = () => {
      const row = head.closest('.reason');
      const open = row.classList.toggle('open');
      head.setAttribute('aria-expanded', open);
    };
  }
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
    ['Attachments', m.attachment_count ? esc(m.attachment_names.join(', ')) : 'none',
      m.attachment_count ? 'warn' : ''],
    ['IP source', `<span class="kv-note">${esc(o.client_ip_source || '—')}</span>`, ''],
  ];
  $('sender').innerHTML = rows.map(([k, v, cls]) =>
    `<div class="kv-row"><div class="kv-key">${k}</div><div class="kv-val ${cls}">${v}</div></div>`).join('');
}

function renderRelay(chain, origin) {
  $('hop-count').textContent = chain.length ? `(${chain.length} hops)` : '';
  if (!chain.length) {
    $('relay').innerHTML = '<div class="hop-meta">No Received headers — the relay path cannot be reconstructed.</div>';
    return;
  }
  // Oldest first, so the path reads in the direction the mail travelled.
  $('relay').innerHTML = [...chain].reverse().map((h) => {
    const isOrigin = h.from_ip && h.from_ip === origin.client_ip;
    const cls = isOrigin ? 'origin' : (h.from_ip_is_public ? 'public' : '');
    const tag = isOrigin ? '<span class="hop-tag">origin</span>'
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
  $('headers').innerHTML = d.all_headers
    .map((h) => `<tr><td>${esc(h.name)}</td><td>${esc(h.value)}</td></tr>`).join('');
  $('mta-results').textContent = d.reported_authentication_results.length
    ? d.reported_authentication_results.join('\n\n')
    : 'The receiving MTA did not stamp an Authentication-Results header.';
  $('raw-json').textContent = JSON.stringify(d, null, 2);
}

/* ══ input handling ════════════════════════════════════════════════════ */

const dz = $('dropzone'), fileInput = $('file-input');

dz.onclick = () => fileInput.click();
dz.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } };
fileInput.onchange = () => { if (fileInput.files[0]) analyseBlob(fileInput.files[0], fileInput.files[0].name); };

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
  if (!text) return toast('Nothing to analyse');
  analyseBlob(new Blob([text], { type: 'message/rfc822' }), 'pasted.eml');
};

$('expand-all').onclick = () => {
  const rows = [...document.querySelectorAll('.reason')];
  const opening = rows.some((r) => !r.classList.contains('open'));
  rows.forEach((r) => {
    r.classList.toggle('open', opening);
    r.querySelector('.reason-head')?.setAttribute('aria-expanded', opening);
  });
  $('expand-all').textContent = opening ? 'Collapse all' : 'Expand all';
};

$('copy-json').onclick = async () => {
  try {
    await navigator.clipboard.writeText(JSON.stringify(lastResult, null, 2));
    toast('JSON copied to clipboard');
  } catch {
    toast('Clipboard blocked by the browser');
  }
};

/* ══ settings wiring ═══════════════════════════════════════════════════ */

function openSettings(open) {
  $('settings').hidden = !open;
  $('scrim').hidden = !open;
  if (open) $('settings-close').focus();
  else $('settings-toggle').focus();
}

$('settings-toggle').onclick = () => openSettings(true);
$('settings-close').onclick = () => openSettings(false);
$('scrim').onclick = () => openSettings(false);

$('theme-swatches').onclick = (e) => {
  const b = e.target.closest('[data-theme-value]');
  if (b) setPref('theme', b.dataset.themeValue);
};
$('accent-swatches').onclick = (e) => {
  const b = e.target.closest('[data-accent-value]');
  if (b) setPref('accent', b.dataset.accentValue);
};
$('density-seg').onclick = (e) => {
  const b = e.target.closest('[data-density-value]');
  if (b) setPref('density', b.dataset.densityValue);
};
$('wire-toggle').onclick = () => setPref('wire', !prefs.wire);
$('motion-toggle').onclick = () => setPref('motion', !prefs.motion);
$('reset-settings').onclick = () => { prefs = { ...DEFAULTS }; savePrefs(); applyPrefs(); toast('Reset to defaults'); };

addEventListener('keydown', (e) => {
  if (e.target.matches('input, textarea')) return;
  if (e.key === 'Escape') return openSettings(false);
  if (/^[1-9]$/.test(e.key)) selectSample(Number(e.key) - 1);
});

boot();
