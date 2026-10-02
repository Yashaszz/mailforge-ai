/* Popup: backend health, endpoint and message-source selection. */

const $ = (id) => document.getElementById(id);

const HINTS = {
  session: 'Uses the Gmail session already signed in. Works immediately.',
  'gmail-api': 'Needs an OAuth client id in the manifest. Restricted scope: '
    + 'fine for up to 100 test users, verification required to publish.',
};

async function load() {
  const res = await chrome.runtime.sendMessage({ type: 'getSettings' });
  if (res?.ok) {
    $('api').value = res.apiBase;
    $('source').value = res.source;
    $('research').checked = Boolean(res.researchMode);
  }
  refreshStats();
  $('source-hint').textContent = HINTS[$('source').value] || '';

  try {
    const h = await chrome.runtime.sendMessage({ type: 'health' });
    if (h?.ok) {
      $('dot').className = 'dot ok';
      $('status').textContent = `v${h.health.version} · `
        + (h.health.offline_mode ? 'offline mode' : 'live DNS');
    } else {
      throw new Error(h?.error || 'unreachable');
    }
  } catch (err) {
    $('dot').className = 'dot bad';
    $('status').textContent = 'backend unreachable';
  }
}

$('source').addEventListener('change', () => {
  $('source-hint').textContent = HINTS[$('source').value] || '';
});

$('save').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({
    type: 'setSettings', apiBase: $('api').value.trim(), source: $('source').value,
  });
  $('save').textContent = 'Saved';
  setTimeout(() => { $('save').textContent = 'Save'; }, 1200);
  load();
});

load();

async function refreshStats() {
  const s = await chrome.runtime.sendMessage({ type: 'research:stats' });
  if (!s?.ok) return;
  const rate = s.total ? ` (${(100 * s.flipped / s.total).toFixed(1)}%)` : '';
  $('research-stats').textContent =
    `${s.total} messages · ${s.differing} copies differ · ${s.flipped} DKIM flips${rate}`;
}

$('research').addEventListener('change', async () => {
  await chrome.runtime.sendMessage({ type: 'setSettings', researchMode: $('research').checked });
});

$('export').addEventListener('click', async () => {
  const res = await chrome.runtime.sendMessage({ type: 'research:export' });
  if (!res?.ok) return;
  const url = URL.createObjectURL(new Blob([res.csv], { type: 'text/csv' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `mailforge-dkim-fidelity-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
});

$('clear').addEventListener('click', async () => {
  if (!confirm('Delete all recorded research measurements?')) return;
  await chrome.runtime.sendMessage({ type: 'research:clear' });
  refreshStats();
});
