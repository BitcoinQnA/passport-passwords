<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# KeyOS integration patch

Dropping `gui-app-passwords` into a KeyOS checkout needs three small edits to
tracked KeyOS files. They are captured as a single diff in
[`keyos-integration.patch`](keyos-integration.patch) and described below.

Unlike the Nostr Signer (which carried USB PIO stack fixes), **Vaults Bridge
needs no USB patch**: the on-device WebUSB transport sits on the runtime
vendor-class `register_interface` facility plus the PIO OUT / IRQ-mask fixes that
are already present in the `dev-v1.3.0` trunk (SUP-1243, validated by the Nostr
Signer 1.3 on the same branch). The simulator's WebSocket transport touches no
USB at all.

## Base

- Repo: `Foundation-Devices/KeyOS-dev` (private)
- Branch base: `dev-v1.3.0`

## The three edits

### 1. `Cargo.toml` — workspace wiring

- Add `"apps/gui-app-passwords"` to `[workspace].members`.
- Add `exclude = ["logic"]` so the app's nested `logic/` sub-workspace (the
  vendored `vaults-bridge-*` crates) is not pulled into the root workspace. The
  app path-depends into it directly.

### 2. `os/gui-app-launcher/src/main.rs` — launcher tile

Register one `HiddenApp` entry, behind the same dev-only gate as the other
hidden apps (System Actions, Playground, Update, …):

```rust
HiddenApp {
    label: "Passwords".into(),
    app_id: "0x50617373776f72647300000000000000".into(),
},
```

The `app_id` is the ASCII of `Passwords` (`0x50 61 73 73 77 6f 72 64 73`)
right-padded with zeroes — matching `manifest.toml`'s `appId`.

### 3. `xtask/src/main.rs` — build lists

Add `"gui-app-passwords"` to both `DEV_APPS` (so it builds for the device image)
and `DEFAULT_SERVICES_HOSTED` (so it builds into the hosted simulator).

## How to apply

From a clean `dev-v1.3.0` checkout with the app directory already copied to
`apps/gui-app-passwords/`:

```sh
git apply docs/keyos-integration.patch       # or --3way if trunk has moved
cargo xtask check gui-app-passwords          # should pass for device + sim
```

If `git apply` rejects a hunk, the cause is upstream movement on `dev-v1.3.0`
since this snapshot — re-apply with `git apply --3way` and resolve, or make the
three edits by hand from the descriptions above.

## Coexistence

KeyOS is a one-foreground-app system: switching apps deregisters the previous
app's USB interface, so Vaults Bridge's vendor-class interface never competes
with the Nostr Signer's at runtime even though both use the `0xFF/0xFF/0xFF`
triple. FIDO HID is independent and runs alongside either.
