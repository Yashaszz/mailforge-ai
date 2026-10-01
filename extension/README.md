# Mailforge AI — Gmail extension

Analyses the message you have open in Gmail: authenticates the sender
(SPF / DKIM / DMARC), traces where it actually came from, and flags VPN, proxy
and Tor origins — without leaving the inbox.

## Load it (2 minutes, no publishing needed)

1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked** and select this `extension/` folder
4. Open <https://mail.google.com> and **open any message**
5. Press the **Analyse** button in the message header

The verdict appears as a card under the message. "Open full forensic report"
hands the message to the dashboard for the relay map and geolocation.

No Google review, no Chrome Web Store, no OAuth setup for this path.

## Architecture

```
content/gmail.js   runs inside Gmail — finds the open message, injects the
                   button, renders the verdict card
lib/gmail-dom.js   every piece of Gmail DOM knowledge, isolated here so a
                   Gmail layout change lands in exactly one file
lib/sources.js     how a raw message is obtained — two implementations
lib/api.js         backend client
lib/panel.js       the verdict card
background.js      service worker: backend calls and the OAuth flow
```

### Message sources

Retrieval sits behind one interface so the production path is a config change
rather than a rewrite.

| Source | Setup | Notes |
|---|---|---|
| **`session`** (default) | none | Reads Gmail's own "Show original" view using the session already signed in. Works immediately; depends on Gmail's internal URL shape. |
| **`gmail-api`** | OAuth client id | `users.messages.get?format=raw`. Stable and documented — the path a shipped product should use. |

Switch between them in the extension popup.

`SessionSource` runs in the **content script**, where a request to Gmail is
same-origin and carries the user's cookies with no extra permission.
`GmailApiSource` runs in the **service worker**, because `chrome.identity` is
unavailable to content scripts. All backend calls also run in the service
worker, which `host_permissions` exempt from page CORS.

### Enabling the Gmail API source

1. Create a Google Cloud project and enable the **Gmail API**
2. Create an OAuth client of type **Chrome Extension** using this extension's ID
3. Put the client id in `manifest.json` under `oauth2.client_id`
4. Add your Google account as a **test user** on the consent screen
5. Select *Gmail API* in the extension popup

`gmail.readonly` is a **restricted** scope. Testing mode allows up to 100 test
users with no review. Public distribution additionally requires OAuth
verification and an annual CASA security assessment (roughly $500–$4,500/year),
which is a scheduling and budget item, not a code change.

## Backend

Defaults to the deployed instance. Point it at `http://127.0.0.1:8000` in the
popup while developing — `host_permissions` already covers localhost.

## Privacy

The message is sent to the Mailforge backend for analysis and is not stored
there. The hand-off to the dashboard travels in the URL **fragment**, which
browsers never transmit to a server, and the dashboard clears it from history
on arrival.

## Known limits

- Gmail ships obfuscated markup that changes without notice. All of it is
  confined to `lib/gmail-dom.js`, and the Gmail API source is unaffected by it.
- Analyses the message you explicitly ask about. There is no background
  inbox scanning — that needs quota and privacy design first.
- Webmail hides the sender's own IP: a Gmail message shows Google's relay, not
  the person. The UI says so rather than implying a location it cannot know.
