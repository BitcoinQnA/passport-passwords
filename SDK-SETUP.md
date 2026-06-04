<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Vaults Bridge — SDK setup & integration

## Is this an "SDK app"? Yes.

The official Foundation developer docs (<https://docs.foundation.xyz/developers>)
describe an `app-config.toml` + `foundation sideload` flow. The **shipped
`foundation` CLI is ahead-of / behind those docs**: running
`foundation new <name> --template multi-page-app` produces a project that is
**structurally identical to this one** — a `manifest.toml` (not `app-config.toml`),
the same `slint-keyos-platform` path-deps, the same `src/main.rs` + `ui/pages/*`
+ `build.rs` + `resources/icon.svg` + `i18n/en.json` layout, the `app!()` macro,
and the `@ui` widget library. So **`manifest.toml` is the real SDK manifest**,
and this app already conforms to the SDK project shape.

**CLI maturity (important):** at the time of writing only `foundation new` and
`foundation develop` are implemented; `sim`, `sideload`, and `cert` are not. So
the CLI can scaffold a project and open the Nix dev shell, but it cannot yet
build or install to hardware. Use KeyOS's own `cargo xtask` flow for that (it is
the same toolchain the CLI will eventually wrap).

## Layout vs. the SDK template

| SDK template (`foundation new`) | This repo |
|---|---|
| `manifest.toml` | ✅ `manifest.toml` |
| `Cargo.toml`, `build.rs` | ✅ |
| `src/main.rs` + `ui/app.slint` + `ui/pages/*` | ✅ |
| `resources/icon.svg` | ✅ |
| `i18n/en.json` | ✅ (scaffold — see note) |
| — | `logic/` vendored crates, `extension/`, `docs/` (this app's extras) |

> **i18n note.** `i18n/en.json` is present for SDK-template parity and as the
> localization source-of-truth, but strings are currently inline in the Slint
> pages (`build.rs` sets `include_translations: false`). Wiring `@tr`/keyed
> lookups through the pages is a follow-up.

## Build & run (today, via `cargo xtask`)

From a KeyOS checkout with this app integrated (see below):

```bash
# Type/borrow-check the app for BOTH device (ARM/xous) and the simulator:
cargo xtask check gui-app-passwords

# Run the hosted simulator (opens the Passport window):
just sim            # or: cargo xtask run --hosted
```

The app appears in the dev **Secret Menu** / hidden-apps launcher list as
**Passwords**. For the end-to-end browser test, see [`TESTING.md`](TESTING.md).

### Device image build (full flashable firmware)

```bash
just build          # = cargo xtask build && cargo xtask build-firmware-image
cargo xtask flash   # flash the signed boot.img over USB (SAM-BA)
```

The supported build hosts are **Ubuntu** and the KeyOS **Nix flake**. The full
image **also builds on macOS (Apple Silicon)** with the GNU ARM toolchain
installed — with one gotcha:

> **macOS `micro-ecc-sys` link failure.** `.cargo/config.toml` sets
> `CC_armv7a_unknown_xous_elf = "arm-none-eabi-gcc"` but no archiver, so `cc`
> falls back to the host `ar`/`ranlib`, which can't build a valid symbol index
> for ARM ELF archives — `cargo xtask` then fails to link with
> `undefined symbol: uECC_verify / uECC_secp256k1 / uECC_decompress`. Point the
> archiver at the GNU ARM `ar`:
>
> ```bash
> export AR_armv7a_unknown_xous_elf="arm-none-eabi-ar"
> export RANLIB_armv7a_unknown_xous_elf="arm-none-eabi-ranlib"
> just build
> ```
>
> (Durable fix: add the `AR_armv7a_unknown_xous_elf` line next to the `CC_...`
> line in `.cargo/config.toml`.)

## Integrating into a KeyOS checkout

This repo is the app plus its vendored logic and companion extension. To build
it you drop the app into a KeyOS workspace. From a clean KeyOS checkout on
`dev-v1.3.0`:

1. **Copy the app in** (the whole repo minus the host-side extras):

   ```bash
   mkdir -p <keyos>/apps/gui-app-passwords
   # copy: Cargo.toml manifest.toml build.rs src/ ui/ resources/ i18n/ logic/
   ```

   The app path-depends into its own bundled `logic/` sub-workspace
   (`logic/vaults-bridge-core`, `-protocol`, `-keystore`, `-import`), so `logic/`
   rides inside the app directory — nothing else to place.

2. **Apply the integration edits** ([`docs/keyos-integration.patch`](docs/keyos-integration.patch),
   detailed in [`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md)):
   - `Cargo.toml` — add `"apps/gui-app-passwords"` to `[workspace].members` and
     `exclude = ["logic"]` so the nested logic workspace is not pulled into the
     root workspace.
   - `os/gui-app-launcher/src/main.rs` — add a `HiddenApp { label: "Passwords",
     app_id: "0x50617373776f72647300000000000000" }` entry.
   - `xtask/src/main.rs` — add `"gui-app-passwords"` to `DEV_APPS` and
     `DEFAULT_SERVICES_HOSTED` (so it builds for device and the simulator).

   ```bash
   git apply docs/keyos-integration.patch    # or --3way if trunk has moved
   ```

3. **USB stack.** The on-device WebUSB transport (vendor-class `0xFF/0xFF/0xFF`,
   two 64-byte interrupt endpoints, WebUSB + MS OS 2.0 descriptors) relies on USB
   (PIO) fixes that are **already present in `dev-v1.3.0`** — the same fixes the
   Nostr Signer validated (SUP-1243). No separate patch is needed. The simulator
   (WebSocket transport) doesn't touch USB at all.

After that, `cargo xtask check gui-app-passwords` should pass for both targets.

## Adopting the official `foundation` CLI later

Once `foundation sim`/`sideload`/`cert` ship, the migration is mechanical:
`foundation new passwords --template multi-page-app`, then move `src/`, `ui/`,
`resources/`, `i18n/`, `logic/`, and `manifest.toml` into the scaffold — the
layout already matches. `foundation sideload` would then push the signed app
bundle over USB without a full firmware rebuild.

## Open items

- Full signed device image + sideload via the `foundation` CLI (pending CLI
  `build`/`sideload`).
- Wire `i18n/en.json` through the Slint pages (currently inline strings).
- Production USB VID/PID assignment for the vendor-class interface (see
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md)); dev builds pair by device selection in
  the WebUSB picker.
- Store flow, bulk import (1Password/Bitwarden/CSV), multi-account-per-origin
  picker, and the Firefox port are explicitly out of PoC scope.
