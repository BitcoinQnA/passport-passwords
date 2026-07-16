<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Vaults Bridge — SDK setup & integration

## Source of truth

This repository is the canonical Passwords source. A copy under
`KeyOS-dev/apps/gui-app-passwords` is generated build input, not a second place
to develop the app.

To stage the current source into a private KeyOS checkout and apply the required
KeyOS edits:

```bash
./scripts/stage-keyos-app.sh /path/to/KeyOS-dev
```

The script copies only app build inputs, rewrites the standalone Cargo paths for
the monorepo layout, applies `docs/keyos-integration.patch`, and links a private
signing config when
`~/.foundation/signing/passwords/cosign2.toml` exists.

## Is this an SDK app? Yes.

The official Foundation developer docs (<https://docs.foundation.xyz/developers>)
describe an `app-config.toml` + `foundation sideload` flow. The **shipped
`foundation` CLI is ahead-of / behind those docs**: running
`foundation new <name> --template multi-page-app` produces a project that is
**structurally identical to this one** — a `manifest.toml` (not `app-config.toml`),
the same `slint-keyos-platform` path-deps, the same `src/main.rs` + `ui/pages/*`
+ `build.rs` + `resources/icon.svg` + `i18n/en.json` layout, the `app!()` macro,
and the `@ui` widget library. So **`manifest.toml` is the real SDK manifest**,
and this app already conforms to the SDK project shape.

**Current SDK blocker:** the intended `foundation sim` and build path is blocked
by the SDK's bundled `server-macro`, which uses the removed unstable
`track_path` feature. Until that SDK fix lands, use the private KeyOS
`cargo xtask` flow below.

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
cargo xtask build-all
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
> cargo xtask build-all
> ```
>
> (Durable fix: add the `AR_armv7a_unknown_xous_elf` line next to the `CC_...`
> line in `.cargo/config.toml`.)

## Integrating into a KeyOS checkout

This repo is the app plus its vendored logic and companion extension. To build
it you drop the app into a compatible private KeyOS workspace. The integration
patch is validated against the revision listed in
[`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md).

The recommended path is the staging script:

```bash
./scripts/stage-keyos-app.sh /path/to/KeyOS-dev
```

For a manual integration:

1. Copy `Cargo.toml`, `app-config.toml`, `manifest.toml`, `build.rs`, `src/`,
   `ui/`, `resources/`, `i18n/`, and `logic/` into
   `<keyos>/apps/gui-app-passwords`.
2. Remove the standalone `[workspace]` and `[patch.crates-io]` blocks from the
   copied `Cargo.toml`, then rewrite `../KeyOS-dev2/` paths to `../../`.
3. Apply the integration edits ([`docs/keyos-integration.patch`](docs/keyos-integration.patch),
   detailed in [`docs/KEYOS-PATCHES.md`](docs/KEYOS-PATCHES.md)):
   - `Cargo.toml` — add `"apps/gui-app-passwords"` to `[workspace].members` and
     add `"apps/gui-app-passwords/logic"` to the workspace exclusions.
   - `os/gui-app-launcher/src/main.rs` — add a `HiddenApp { label: "Passwords",
     app_id: "0x50617373776f72647300000000000000" }` entry.
   - `xtask/src/main.rs` — add `"gui-app-passwords"` to `DEV_APPS` and
     `DEFAULT_SERVICES_HOSTED` (so it builds for device and the simulator).
   - `os/usb/src/device/implementation.rs` — replace stale app-owned USB
     interfaces and endpoints when the foreground app is reopened.

   ```bash
   git apply --unidiff-zero /path/to/passport-passwords/docs/keyos-integration.patch
   ```

After that, `cargo xtask check gui-app-passwords` should pass for both targets.

## Adopting the official `foundation` CLI later

Once the SDK `track_path` blocker is fixed, repoint the remaining
`../KeyOS-dev2` path dependencies at the SDK's bundled `lib/keyos` and validate
`foundation sim`, `foundation build`, and `foundation sideload`.

## Open items

- Full signed device image + sideload via the `foundation` CLI (pending CLI
  `build`/`sideload`).
- Wire `i18n/en.json` through the Slint pages (currently inline strings).
- Production USB VID/PID assignment for the vendor-class interface (see
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md)); dev builds pair by device selection in
  the WebUSB picker.
- Hardware verification of portable encrypted backup export/restore over the
  KeyOS file picker/writer flow.
- Chrome Web Store packaging, privacy-policy copy, and Firefox port.
