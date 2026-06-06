<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Vaults Bridge — Password Manager for Passport Prime

A hardware-backed password manager that runs natively on the
[Foundation Passport Prime](https://foundation.xyz), built on KeyOS. Your
credentials are sealed to the device and never leave it: the browser stays the
client, and Passport only releases a password — encrypted in transit — after you
approve the request on the device screen.

It has two halves that ship together in this repo:

- **`/` (the KeyOS app)** — a Rust + Slint application that holds the
  credentials, seals them with a key derived from the device's hardware-backed
  app seed, and shows an on-device approval screen for every release.
- **`extension/` (the browser extension)** — a Chromium (MV3) extension that
  detects login forms, verifies the requesting origin, and relays release
  requests to Passport over WebUSB (or WebSocket against the simulator).

> **Proof-of-concept.** This is a KeyOS application (it builds inside a KeyOS
> workspace, not standalone — see [Building](#building)) plus a companion
> extension. It exists to show third-party SDK developers that Passport Prime is
> a general-purpose **release-with-approval** mechanism, not just a Bitcoin
> signer. Validated on a Passport Prime dev unit over WebUSB.

## Screenshots

_Device captures live in `docs/screenshots/` (the credential list and the
release-approval screen)._

## Why one repo

The device app and the extension are two halves of one mechanism — Passport is
inert without the host-side form detection and origin verification, and both
sides speak the same wire protocol (the `vaults-bridge-protocol` crate, mirrored
in the extension's JS). Keeping them together means the firmware and the
extension move in lockstep and share one version. See
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire format.

## What it does

On the device, the **Passwords** app manages origin-bound credential records:
add a credential (origin + username + password), browse and inspect them, edit,
and delete. Records are sealed at rest under a key derived from the app seed.

Through the extension, a website login is brokered to the device:

- **`list_origins`** — the extension learns which origins have a stored
  credential (so it can offer to fill).
- **`release_credential`** — returns the username and the password **sealed to
  the browser session**, but only after you approve the release on the device.
  The approval screen shows the requesting origin so you can confirm it matches
  the tab. A per-request nonce prevents replay.

The password is encrypted under an ECDH-derived session key the whole way to the
browser, so a host-side attacker watching USB traffic can't read it.

## How credentials stay safe

- **Sealed to the device.** The keystore-at-rest key is derived from the KeyOS
  **app seed** (`os/security` → `GetAppSeed`), so credentials are bound to this
  Passport and the master key only exists in RAM while the app is unlocked.
- **Approval gate.** Nothing is released silently. Every `release_credential`
  routes through the `Approver` trait (`logic/vaults-bridge-core/src/approval.rs`),
  which drives the on-device hold-to-confirm approve/reject screen. The extension
  can only ever obtain a credential the device owner explicitly approved.
- **Origin-bound, host-verified.** Each request carries a strict origin (scheme +
  host + explicit non-default port, no path/query). The extension's background
  worker derives the requesting tab's origin authoritatively from `sender.tab.url`
  for content-script requests, or from the active tab for popup requests, rather
  than trusting page-provided input. Public builds use exact-origin matching —
  subdomains do not silently share credentials.
- **Encrypted in transit.** `establish_session` does an X25519 ECDH; the shared
  secret is HKDF-SHA256-expanded to a 32-byte AES-256-GCM key. Passwords are
  sealed under it (AES-GCM, so the extension decrypts natively with WebCrypto).
- **The core is host-testable and KeyOS-free.** All credential, origin, session,
  and protocol logic lives under `logic/` with no KeyOS dependencies, so it runs
  under `cargo test` on the host.

## Architecture

- **`logic/`** — a vendored, self-contained sub-workspace (no external repo
  needed to build):
  - **`vaults-bridge-core`** — strict-origin parsing/equality (`origin`), the
    X25519 + AES-256-GCM session sealing (`session`), the credential record
    schema (`record`), the `CredentialStore` trait (`store`), the async approver
    (`approval`), and the protocol dispatcher (`engine`).
  - **`vaults-bridge-keystore`** — encrypted-at-rest credential storage over the
    app-seed-derived master key.
  - **`vaults-bridge-protocol`** — the newline-delimited-JSON framing (`frame`)
    and the request/response wire types (`message`) shared with the extension.
  - **`vaults-bridge-import`** — credential import helpers.
  - **Portable encrypted backups** — `vaults-bridge-keystore` and the KeyOS UI
    can export and restore passphrase-encrypted backups for replacement-device
    recovery.
- **`src/`** — the KeyOS/Slint app shell: the engine wiring, the approval-screen
  glue, the import flow, keystore persistence, and the device-key wiring (app
  seed → master key). `transport/` carries WebUSB (device) and WebSocket
  (simulator).
- **`ui/`** — Slint pages under `ui/pages/*` (main, details, edit, approval);
  routing in `ui/gen/*` is generated by `build.rs` from each page's `props.slint`.
- **`extension/`** — the Chromium WebUSB extension (form detection, origin
  verification, fill).
- **`i18n/en.json`** — user-facing strings (localization scaffold; see
  [SDK-SETUP.md](SDK-SETUP.md)).

## Building

This is a KeyOS app and builds **inside a KeyOS workspace** (it depends on KeyOS
crates such as `slint_keyos_platform`, `security`, `server`, `usb`, `fs`, and
`file-backed`). See [`SDK-SETUP.md`](SDK-SETUP.md) for the toolchain and
integration, and [`TESTING.md`](TESTING.md) for the end-to-end test. In a KeyOS
checkout the app lives at `apps/gui-app-passwords`.

Dropping the app into a KeyOS tree needs three small integration edits
(workspace member, launcher tile, dev-app lists) — see
[`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md) and
[`docs/keyos-integration.patch`](docs/keyos-integration.patch). The on-device
WebUSB transport relies on USB (PIO) stack fixes that are already present in the
`dev-v1.3.0` trunk (the same fixes the Nostr Signer validated); no separate USB
patch is required.

The extension installs unpacked (`chrome://extensions` → Developer mode → Load
unpacked → `extension/`); see [`extension/README.md`](extension/README.md).

## Status

Public-release hardening branch in progress. The core now supports exact-origin
matching, account selection for multiple logins, transactional remote saves,
approval timeouts, stronger generated-password guarantees, and portable
encrypted backup/restore. The extension still ships as a sideloaded Chromium
MV3 build; simulator transport is treated as a developer-only feature.

## License

GPL-3.0-or-later. Copyright Foundation Devices, Inc. Source files carry SPDX
headers; the full text is in [`LICENSE`](LICENSE).
