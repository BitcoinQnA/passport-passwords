<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Testing Vaults Bridge end to end

Vaults Bridge has two supported test tracks. Use the simulator for the complete
browser flow and hardware for the independently signed local-vault flow.

| Track | Device side | Transport | Needs hardware |
|-------|-------------|-----------|----------------|
| **A — Simulator** | KeyOS hosted sim | WebSocket `ws://127.0.0.1:9876` | No |
| **B - Device** | Passport Prime | Local vault | Yes |

Both tracks use the same extension.

---

## Track A — Simulator (no hardware)

1. **Run the app in the simulator.** From the repo root, with the Foundation SDK
   installed (see [`SDK-SETUP.md`](SDK-SETUP.md)):

   ```bash
   foundation sim
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

## Track B - Device local vault

1. **Install the app on a Prime running KeyOS 1.4 beta.** Build, sign, and push
   it over USB with the Foundation SDK (see [`SDK-SETUP.md`](SDK-SETUP.md)):

   ```bash
   foundation build --release
   foundation pack --release
   foundation sideload --release
   ```

   Sideload needs Developer Mode enabled on Prime and your publisher certificate
   allowed. Alternatively, install the packaged `target/keyos/gui-app-passwords.app`
   from **Settings → Apps → Install App**.

2. **Exercise the local vault.** Launch **Passwords** and add, inspect, edit,
   archive, restore, and permanently delete a credential. Confirm search and
   password generation work without a host connection.

3. **Exercise persistence.** Close and relaunch Passwords. Confirm the record is
   restored from app-scoped encrypted storage.

4. **Exercise import and backup.** Import a supported CSV from User, Airlock, or
   external USB storage. Export an encrypted `.vbpw` backup, then restore it and
   test skip, replace, and keep-both conflict handling.

The SDK 1.0 app does not register a WebUSB interface. Raw `os/usbdev` access is
not grantable to independently signed apps. Hardware browser tests resume when
the public QLv2 app route and browser adapter land; see
[`docs/QLV2-MIGRATION.md`](docs/QLV2-MIGRATION.md).

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
- Hardware browser testing starts after the QLv2 SDK route and browser adapter
  described in [`docs/QLV2-MIGRATION.md`](docs/QLV2-MIGRATION.md) land.
