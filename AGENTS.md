<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# AGENTS.md — build guide for AI coding agents

Guidance for an AI agent helping someone build, run, or modify this repo. Humans:
see [`README.md`](README.md), [`SDK-SETUP.md`](SDK-SETUP.md), [`TESTING.md`](TESTING.md).

## What this is

**Vaults Bridge** — a hardware-backed password manager for the Foundation
Passport Prime, in two halves that ship together:

- **`/`** — a KeyOS (Rust + Slint) app that holds credentials sealed to the
  device and shows an on-device approval screen for every release.
- **`extension/`** — a Chromium MV3 extension that detects login forms, verifies
  the origin, and talks to Passport over WebUSB.

The KeyOS-free crypto/protocol core lives in `logic/` and is `cargo test`-able on
the host with no device.

## This is a standalone Foundation SDK app

It builds with the Foundation SDK alone — **no KeyOS source checkout**. The
`Cargo.toml` KeyOS dependencies resolve through the git-ignored
`.foundation-sdk/current` mapping the CLI creates. Never repoint them at a local
KeyOS checkout, and never commit `.foundation-sdk/`, `ui/ui`, or `manifest.toml`
(the CLI owns those).

## Prerequisites

- The **Foundation SDK 1.0.0** for KeyOS 1.4, with `foundation` on `PATH`.
- **Nix** (Determinate or upstream) — the SDK build runs in a Nix shell.
- A **Chromium-family** browser (Chrome/Brave/Edge/Arc) for the extension.
  WebUSB does **not** work in Safari or Firefox.
- For on-device work: a **Passport Prime on KeyOS 1.4 beta** with Developer Mode.

## Build, sign, sideload

Run from the repo root:

```bash
foundation doctor                    # verify SDK env; run `foundation develop` if it asks
foundation cert gen passwords-dev    # one-time local signing identity
foundation build --release
foundation pack --release            # → target/keyos/gui-app-passwords.app
foundation sideload --release        # optional: push to a connected Prime over USB
```

`foundation clean` resets the generated `.foundation-sdk/current`, `ui/ui`,
`manifest.toml`, and `target/`. End-to-end browser test: [`TESTING.md`](TESTING.md).

## Repo map

| Path | What |
|---|---|
| `logic/` | KeyOS-free core: `vaults-bridge-{core,protocol,keystore,import}`. `cargo test`-able. Start here for logic changes. |
| `src/` | KeyOS/Slint app shell: engine wiring, approval UI glue, keystore persistence, `theme.rs`, transports (`webusb` device / `websocket` sim). |
| `ui/` | Slint pages under `ui/pages/*` + `ui/compat/` (the SDK `@ui` shim). **`ui/gen/**` and `ui/ui` are generated — never hand-edit.** |
| `extension/` | Chromium WebUSB extension. `background.js` holds the origin-verification security gate. |
| `resources/` | App `icon.svg` + `theme.json`. |
| `app-config.toml` | The SDK app manifest: identity, permissions, icon, theme, signing identity. |

## Conventions for agents

- **No em dashes** in prose you add here (house style).
- SPDX header on every new source file (`GPL-3.0-or-later`; MIT for SDK-side files).
- The crypto/protocol logic is host-testable — run `cargo test` in `logic/` before
  proposing changes there; you don't need a device.
- Don't run `foundation sideload`, `foundation logs`, or `foundation cert gen`
  unless the user is explicitly working with hardware or signing.
- No secrets in the repo; it's public. GPL-3.0-or-later.
