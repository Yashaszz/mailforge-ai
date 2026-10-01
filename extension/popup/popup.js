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
  }
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
