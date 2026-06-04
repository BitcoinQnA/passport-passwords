<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Running Vaults Bridge on real Passport Prime hardware

The first end-to-end run on a physical Prime: build the firmware, flash it,
onboard, pair the browser extension over WebUSB, and release a credential into a
real login form. The on-device transport is WebUSB vendor-class — the same
facility the Nostr Signer 1.3 validated on the `dev-v1.3.0` branch.

## Prerequisites

- A KeyOS `dev-v1.3.0` checkout with this app integrated (see
  [`../SDK-SETUP.md`](../SDK-SETUP.md)) and the Rust + GNU ARM toolchain.
  Supported build hosts: **Ubuntu**, the KeyOS **Nix flake**, or **macOS (Apple
  Silicon)** — on macOS export `AR_armv7a_unknown_xous_elf="arm-none-eabi-ar"`
  first (see SDK-SETUP for why).
- A Passport Prime dev unit with USB access and the SAM-BA entry procedure from
  `KeyOS/DEVELOPMENT.md`.
- A Chromium-family browser (Chrome, Brave, Edge, Arc). **WebUSB is not available
  in Safari or Firefox.**

## 1. Build the firmware

From the integrated KeyOS checkout:

```sh
just build          # = cargo xtask build && cargo xtask build-firmware-image
```

`build` flashes the existing `boot.img` — it does not rebuild it. If you've just
changed the app or its logic crates, run `just build` (above) to refresh
`boot.img` before flashing, otherwise you'll flash stale firmware.

## 2. Flash

Enter SAM-BA (hold power ~10 s, then tap power 3× at the logo and pick SAM-BA, or
short the SAM-BA contacts per `DEVELOPMENT.md`). Then:

```sh
cargo xtask flash          # NO --switch if the device is already in SAM-BA
```

`--switch` runs the reboot-to-SAM-BA script and will fail on a device that is
already in SAM-BA. The default flashes the full signed `boot.img`, verifies, and
reboots to normal mode.

> **macOS random write failure.** A transfer can fail mid-write with
> `Status after writing N to 0 was 3` (often on the first chunk) — macOS USB
> transfers fail randomly and `sambuca` chunks them to mitigate. It's safe to
> just re-run `cargo xtask flash`; the device stays in SAM-BA until a fully
> verified write completes (nothing reboots on failure). It usually succeeds on
> the second attempt.

Confirm the device re-enumerates in normal mode and reports the KeyOS version
before continuing.

## 3. First boot and onboarding

1. Power up Prime and complete onboarding (set PIN, generate or restore a seed).
   The keystore master is derived from `security.app_seed()`, so a real seed and
   an unlocked session are needed for the store to open.
2. From the launcher (hidden apps / Secret Menu) open **Passwords**.
3. Add a credential: origin (`https://…`), username, password. It is sealed at
   rest under the app-seed-derived key.

## 4. Install the extension and pair

1. `chrome://extensions` → **Developer mode** → **Load unpacked** → `extension/`.
2. Open the extension's **Settings** page, leave the transport on **WebUSB**, and
   click **Pair Passport Prime**. Pick your Prime in the Chromium WebUSB picker
   (the gesture must come from the options page). The app registers a
   vendor-class interface (`0xFF/0xFF/0xFF`, two 64-byte interrupt endpoints,
   WebUSB + MS OS 2.0 descriptors) while it is open.

> WebUSB grants are per-extension and drop when the extension reloads — re-pair
> after each reload. If a device-control tool (e.g. the `passport-drive` MCP)
> holds the vendor interface, disconnect it before pairing.

## 5. Release a credential

1. Visit the matching login page (the demo gate is `https://github.com/login`).
2. The extension offers to fill. Triggering it sends `release_credential`; the
   **approval screen appears on Prime** showing the requesting origin.
3. Approve on Prime (hold-to-confirm). The credential returns over USB with the
   password **sealed under the ECDH session key**, the extension decrypts it with
   WebCrypto, and the form fills. Reject instead and the site sees a
   `user_rejected` error and nothing is released.

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
