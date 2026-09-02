<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Running Passwords on Passport Prime hardware

Foundation SDK 1.0 supports the complete on-device vault. The browser bridge
remains simulator-only until KeyOS exposes the QLv2 app route described in
[`QLV2-MIGRATION.md`](QLV2-MIGRATION.md).

## Prerequisites

- Foundation SDK 1.0.0 for KeyOS 1.4, with `foundation` on `PATH` and a local
  signing identity (see [`../SDK-SETUP.md`](../SDK-SETUP.md)).
- A Passport Prime running KeyOS 1.4 beta or newer.
- Developer Mode and an allowed publisher certificate only if using
  `foundation sideload`; installing a packaged app uses the normal Apps screen.

## Build, sign, and install

From the repository root:

```sh
foundation doctor
foundation pack --release
```

Copy `target/keyos/gui-app-passwords.app` to a USB drive or the airlock, then
install it from **Settings > Apps > Install App**. Compare the app hash shown by
the CLI with the hash shown on Prime before approving installation.

For development hardware with your publisher certificate already allowed:

```sh
foundation sideload --release
```

## Exercise the local vault

1. Unlock Prime and launch **Passwords**.
2. Add a credential with an origin, username, and password.
3. Close and relaunch the app, then confirm the credential persists.
4. Edit, archive, restore, and permanently delete a test credential.
5. Import a supported CSV from User, Airlock, or external USB storage.
6. Export an encrypted `.vbpw` backup and restore it with each duplicate policy.

The keystore master is derived from `security.app_seed()`, so the app must be
unlocked before the store can open. The app seed never leaves the security
service; the app holds only a short-lived zeroizing copy while deriving the
vault key.

## Browser integration status

The independently signed SDK package does not request `os/usbdev` and does not
register a private WebUSB interface. Use the WebSocket simulator track in
[`../TESTING.md`](../TESTING.md) for current end-to-end browser testing.

When SFT-7295 exposes the QLv2 route, add a device adapter that translates QLv2
messages to `vaults_bridge_protocol::Request` and a matching browser adapter.
The engine, approval gate, encrypted session, and origin verification remain
unchanged.
