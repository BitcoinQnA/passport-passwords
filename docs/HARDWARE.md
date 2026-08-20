<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Running Vaults Bridge on real Passport Prime hardware

The first end-to-end run on a physical Prime: install the app, onboard, pair the
browser extension over WebUSB, and release a credential into a real login form.
The on-device transport is WebUSB vendor-class.

## Prerequisites

- The **Foundation SDK 1.0.0** for KeyOS 1.4, with `foundation` on `PATH` and a
  local signing identity (see [`../SDK-SETUP.md`](../SDK-SETUP.md)).
- A **Passport Prime running KeyOS 1.4 beta** or newer, with **Developer Mode**
  enabled and your publisher certificate allowed (for `foundation sideload`).
- A Chromium-family browser (Chrome, Brave, Edge, Arc). **WebUSB is not available
  in Safari or Firefox.**

## 1. Build, sign, and install the app

This is a standalone Foundation SDK app — you install it onto a Prime already
running KeyOS 1.4 beta, not a full firmware flash. From the repo root (see
[`../SDK-SETUP.md`](../SDK-SETUP.md) for one-time signing setup):

```sh
foundation build --release
foundation pack --release
foundation sideload --release   # push over USB (Developer Mode + allowed publisher cert)
```

Or copy the packaged `target/keyos/gui-app-passwords.app` to the Prime and
install it from **Settings → Apps → Install App**.

## 2. First boot and onboarding

1. Power up Prime and complete onboarding (set PIN, generate or restore a seed).
   The keystore master is derived from `security.app_seed()`, so a real seed and
   an unlocked session are needed for the store to open.
2. From the launcher (hidden apps / Secret Menu) open **Passwords**.
3. Add a credential: origin (`https://…`), username, password. It is sealed at
   rest under the app-seed-derived key.

## 3. Install the extension and pair

1. `chrome://extensions` → **Developer mode** → **Load unpacked** → `extension/`.
2. Open the extension's **Settings** page, leave the transport on **WebUSB**, and
   click **Pair Passport Prime**. Pick your Prime in the Chromium WebUSB picker
   (the gesture must come from the options page). The app registers a
   vendor-class interface (`0xFF/0x50/0x01`, two 64-byte interrupt endpoints,
   WebUSB + MS OS 2.0 descriptors) while it is open.

> WebUSB grants are per-extension and drop when the extension reloads — re-pair
> after each reload. If a device-control tool (e.g. the `passport-drive` MCP)
> holds the vendor interface, disconnect it before pairing.

## 4. Release a credential

1. Visit the matching login page (the demo gate is `https://github.com/login`).
2. The extension offers to fill. Triggering it sends `release_credential`; the
   **approval screen appears on Prime** showing the requesting origin.
3. Approve with the primary button on Prime. The credential returns over USB
   with the password **sealed under the ECDH session key**, the extension
   decrypts it with WebCrypto, and the form fills. Reject instead and the site
   sees a `user_rejected` error and nothing is released.

## Troubleshooting

- **Prime not in the WebUSB picker** — confirm the **Passwords** app is open
  (the switcher deregisters the USB interface on app hide); check
  `chrome://device-log`; make sure no other process holds the interface.
- **`register_interface` error at startup** — an endpoint/interface clash. KeyOS
  is one-foreground-app, so this shouldn't happen against the Nostr Signer at
  runtime; report it if it does.
- **Approval appears but nothing returns** — check Prime's log for
  `gui_app_passwords::transport::webusb` and the engine's `release_credential`
  flow.

## Known-good vs. first-hardware-run

**Known-good (exercised in the hosted simulator):** AES-256-GCM keystore-at-rest
via `security.app_seed()`; strict-origin matching; X25519 + AES-256-GCM session
sealing; the Slint add/details/edit/approval flow; the extension's form
detection, origin verification, and WebSocket + WebUSB transports.

**Validated on first hardware run:** vendor-class interface registration on the
real device, the first Chromium WebUSB handshake, and the production VID/PID
(currently the KeyOS USB server's default — a dedicated pair is TBD).
