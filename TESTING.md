<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Testing Vaults Bridge end to end

Vaults Bridge is exercised through the browser: load the extension, point it at a
login form, and watch each release request surface on Passport for approval.
There are two transports — pick the track that matches your setup.

| Track | Device side | Transport | Needs hardware |
|-------|-------------|-----------|----------------|
| **A — Simulator** | KeyOS hosted sim | WebSocket `ws://127.0.0.1:9876` | No |
| **B — Device** | Passport Prime | WebUSB | Yes |

Both tracks use the same extension.

---

## Track A — Simulator (no hardware)

1. **Run the app in the sim.** From your KeyOS checkout (app integrated per
   [`SDK-SETUP.md`](SDK-SETUP.md)):

   ```bash
   just sim          # or: cargo xtask run --hosted
   ```

   Open **Passwords** in the simulator and add a credential (origin + username +
   password). The app listens on `ws://127.0.0.1:9876`.

2. **Load the extension.** `chrome://extensions` → enable **Developer mode** →
   **Load unpacked** → select `extension/`.

3. **Switch the extension to simulator mode.** Open the extension's **Settings**
   (options) page, enable **Developer mode**, then enable **Simulator mode**
   (WebSocket). It connects to `ws://127.0.0.1:9876`.

4. **Trigger a fill.** Visit a login page whose exact origin matches the
   credential you added. The extension offers matching saved logins; choose one
   if there are multiple accounts. On `release_credential` the **approval screen
   appears in the simulator** — approve it, and the form fills with the released
   username/password.

---

## Track B — Device (Passport Prime)

1. **Flash a KeyOS build that includes the app.** Build the image (Ubuntu, the
   KeyOS Nix shell, or macOS with the ARM toolchain — see
   [`SDK-SETUP.md`](SDK-SETUP.md)), then flash over USB (SAM-BA):

   ```bash
   just build && cargo xtask flash
   ```

   If the device is already in SAM-BA mode, flash **without** `--switch`. On
   macOS a transfer can fail randomly mid-write (`Status after writing … was 3`);
   it's safe to just re-run `cargo xtask flash` — it usually succeeds on the
   second attempt.

2. **Open the app and add a credential.** Launch **Passwords** on Passport
   (hidden apps / Secret Menu) and add an origin + username + password. The
   credential is sealed to this device.

3. **Load the extension** (`chrome://extensions` → Developer mode → Load
   unpacked → `extension/`). Leave it on the default **WebUSB** transport.

4. **Pair over WebUSB.** Open the extension's **Settings** page and click
   **Pair Passport Prime**, then select your Prime in the Chromium WebUSB picker
   (this requires a user gesture, which is why it is initiated from the options
   page). The device registers a vendor-class interface
   (class/subclass/protocol = `0xFF/0xFF/0xFF`) with two 64-byte interrupt
   endpoints. WebUSB pairing is per-extension and drops on reload — re-pair after
   reloading the extension.

5. **Fill a real login form.** Visit the matching site (the demo gate is
   `https://github.com/login`). The extension offers matching saved logins;
   approving the selected release **on Passport** returns the credential — with
   the password sealed under the ECDH session key — and the form fills.

---

## What "pass" looks like

- The extension only offers to fill on exact origins the device actually has a
  credential for (`list_credentials`).
- Multiple saved logins for one origin require an explicit account choice; the
  host should not silently choose the first credential.
- A `release_credential` request **always** raises an approval on the device;
  rejecting it returns an error to the extension and releases nothing.
- The released password is never sent in clear: it travels sealed under the
  AES-256-GCM session key and is decrypted in the browser with WebCrypto.
- A cross-origin iframe requesting a credential for the top frame's origin is
  **rejected** — the background worker only accepts top-frame content-script
  messages and derives the USB origin from `sender.tab.url`.
- Replaying a captured USB exchange is rejected (per-request nonce).
- Leaving an approval pending returns `timeout` after the approval window.
- Exporting an encrypted backup asks for a passphrase twice and writes a
  `.vbpw` file to the selected directory. Restoring asks for the passphrase,
  shows the decrypted record count, and offers duplicate handling: skip,
  replace, or keep both.

## Notes

- **Simulator credential state** lives under the app's data dir; deleting it
  resets stored credentials in the sim.
- This repo ships the **WebUSB** extension build that matches
  `src/transport/webusb.rs`. Earlier WebSerial/CDC-ACM experiments are not
  included.
- Production USB VID/PID for the vendor interface is still TBD (see
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md)); dev builds pair by device selection in
  the WebUSB picker.
