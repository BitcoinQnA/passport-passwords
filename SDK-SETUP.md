<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Foundation SDK setup

This app targets Foundation SDK 1.0.0 and KeyOS 1.4 beta. It builds as a
standalone Foundation SDK application: it does **not** need a KeyOS source
checkout and must not be copied into a KeyOS workspace.

1. Install the Foundation SDK bundle for your operating system and put its
   `foundation` binary on `PATH`.
2. From this repository, run `foundation doctor`.
3. Enter the SDK environment with `foundation develop` if the doctor reports
   that the Nix shell or KeyOS target is missing.
4. Create a local signing identity with `foundation cert gen <name>`.
5. Build and package with `foundation build --release` then
   `foundation pack --release`.

The CLI owns `.foundation-sdk/current`, `ui/ui`, `manifest.toml`, and `target/`.
They are generated and git-ignored. Do not commit them or replace their paths
with paths to a local KeyOS checkout — the `Cargo.toml` dependencies resolve
through the `.foundation-sdk/current` mapping the CLI creates automatically.

To reset generated state:

```sh
foundation clean
foundation doctor
foundation build --release && foundation pack --release
```

See [README.md](README.md) for the publisher identity, signing, install, and the
end-to-end browser test.
