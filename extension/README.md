# Vaults Bridge browser extension

Chromium (MV3) extension that detects login forms, verifies the requesting
origin, and brokers credential releases through the Vaults Bridge protocol.
Use WebSocket simulator mode with Foundation SDK 1.0. The WebUSB adapter
targets the earlier in-tree proof of concept and cannot connect to an
independently signed SDK app. Hardware connectivity will move to QLv2; see
[`../docs/QLV2-MIGRATION.md`](../docs/QLV2-MIGRATION.md).

## Install (unpacked)

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this `extension/` directory.
3. Open the extension's **Settings** page, enable **Developer mode**, then enable
   **Simulator mode**. It connects to `ws://127.0.0.1:9876`.

The WebUSB controls remain for protocol development and the legacy in-tree
build. They do not connect to the Foundation SDK 1.0 hardware package.

## Files

```
manifest.json          MV3 manifest (permissions, service worker, content script)
background.js          message router + sender.tab.url origin verification (the security gate)
content.js             login-form detection, inline account chooser, and fill
offscreen.{html,js}    offscreen document that keeps the WebUSB session alive across SW recycles
options.{html,js,css}  Pair / Forget device, WebUSB ↔ simulator transport toggle
popup.{html,js,css}    connection status, "manage on device" link
webusb-transport.js    legacy vendor-class framing retained for protocol migration
icons/                 toolbar / store icons
```

## Security notes

- The background worker derives the requesting tab's origin authoritatively from
  `sender.tab.url`; a content script (or a cross-origin iframe) cannot spoof it.
  The page and content script never get to choose the origin sent over USB.
- Public builds use exact-origin matching. Multiple logins for the same origin
  are listed without passwords; the user chooses a username before Passport is
  asked to release the secret.
- Passwords arrive sealed under the ECDH-derived AES-256-GCM session key and are
  decrypted in-page with WebCrypto. The secret never crosses USB in clear.
- WebUSB is unavailable in Safari and Firefox; use a Chromium-family browser
  (Chrome, Brave, Edge, Arc).
