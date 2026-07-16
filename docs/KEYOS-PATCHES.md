<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# KeyOS integration patch

Dropping `gui-app-passwords` into a KeyOS checkout needs four small edits to
tracked KeyOS files. They are captured as a single diff in
[`keyos-integration.patch`](keyos-integration.patch) and described below.

Vaults Bridge uses the runtime vendor-class `register_interface` facility plus
the PIO OUT / IRQ-mask fixes already present in the `dev-v1.3.0` trunk
(SUP-1243). It also needs the app-interface lifecycle fix described below.
Without it, reopening Passwords leaves interface 6 registered with endpoints
owned by the exited process, so the browser can pair with Passport but cannot
reach the app. The simulator's WebSocket transport touches no USB at all.

## Base

- Repo: `Foundation-Devices/KeyOS-dev` (private)
- Patch validated at KeyOS commit
  `87a5b7236bc8b739d892c6be0de7718803352fcf`.

## The four edits

### 1. `Cargo.toml` — workspace wiring

- Add `"apps/gui-app-passwords"` to `[workspace].members`.
- Add `"apps/gui-app-passwords/logic"` to the existing workspace exclusions so
  the nested vendored logic workspace is not pulled into the root workspace.

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

### 4. `os/usb/src/device/implementation.rs`: app interface lifecycle

- Treat interface numbers 0 through 5 as fixed KeyOS interfaces.
- Replace an existing app-owned interface at 6 or above, completing stale I/O
  and releasing its endpoints before allocating new ones.
- Make repeated platform-capability registration idempotent.
- Set `bNumInterfaces` to the highest interface number plus one, as required by
  the USB configuration descriptor.

## How to apply

The preferred command stages the canonical source and applies the patch:

```sh
./scripts/stage-keyos-app.sh /path/to/KeyOS-dev
```

For a manual integration, from a clean checkout with the app directory already
copied to `apps/gui-app-passwords/`:

```sh
git apply --unidiff-zero /path/to/passport-passwords/docs/keyos-integration.patch
cargo xtask check gui-app-passwords          # should pass for device + sim
```

If `git apply` rejects a hunk, the cause is upstream movement since this
snapshot. Re-apply manually against the new context, or make the
four edits by hand from the descriptions above.

## Coexistence

KeyOS is a one-foreground-app system. Foreground apps share the app-owned USB
interface slot and replace the previous app's stale registration when launched.
Vaults Bridge uses `0xFF/0x50/0x01`, so extensions for other vendor-class apps
do not claim its interface or send it an incompatible protocol. FIDO HID is
independent and runs alongside it.
