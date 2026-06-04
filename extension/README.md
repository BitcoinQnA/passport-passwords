# Vaults Bridge — Browser Extension (WebUSB build)

Chromium (MV3) extension that detects login forms, verifies the requesting
origin, and brokers credential releases to Passport Prime over **WebUSB** — no
native messaging host, no driver install on macOS/Linux. It speaks the Vaults
Bridge wire protocol (newline-delimited JSON over a vendor-class interface)
directly through `navigator.usb`. See [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md).

## Install (unpacked)

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this `extension/` directory.
3. Open the extension's **Settings** (options) page to pair:
   - **WebUSB** (default) — click **Pair Passport Prime** and pick your Prime in
     the Chromium picker. The grant is per-extension and drops on reload.
   - **Simulator mode** (WebSocket) — connects to `ws://127.0.0.1:9876` for
     hosted-mode development against a host build of the app (no hardware).

A user gesture is required for the WebUSB picker, which is why pairing is
initiated from the options page rather than automatically.

## Files

```
manifest.json          MV3 manifest (permissions, service worker, content script)
background.js          message router + sender.tab.url origin verification (the security gate)
content.js             login-form detection and fill
offscreen.{html,js}    offscreen document that keeps the WebUSB session alive across SW recycles
options.{html,js,css}  Pair / Forget device, WebUSB ↔ simulator transport toggle
popup.{html,js,css}    connection status, "manage on device" link
webusb-transport.js    vendor-class framing + chunked OUT writes (mirrors src/transport/webusb.rs)
icons/                 toolbar / store icons
```

## Security notes

- The background worker derives the requesting tab's origin authoritatively from
  `sender.tab.url`; a content script (or a cross-origin iframe) cannot spoof it.
  A request whose claimed origin disagrees with the tab origin is dropped before
  any USB call.
- Passwords arrive sealed under the ECDH-derived AES-256-GCM session key and are
  decrypted in-page with WebCrypto. The secret never crosses USB in clear.
- WebUSB is unavailable in Safari and Firefox; use a Chromium-family browser
  (Chrome, Brave, Edge, Arc).
