#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
keyos_root="${1:-${KEYOS_DEV:-"$repo_root/../KeyOS-dev2"}}"
app_dir="$keyos_root/apps/gui-app-passwords"
integration_patch="$repo_root/docs/keyos-integration.patch"
signing_config="${PASSWORDS_COSIGN2_CONFIG:-"$HOME/.foundation/signing/passwords/cosign2.toml"}"

if ! git -C "$keyos_root" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    [[ ! -f "$keyos_root/Cargo.toml" ]]; then
    echo "Not a KeyOS checkout: $keyos_root" >&2
    echo "Pass the checkout path as the first argument or set KEYOS_DEV." >&2
    exit 1
fi

mkdir -p "$app_dir"

for file in Cargo.toml app-config.toml build.rs manifest.toml permission_templates.toml; do
    if [[ -f "$repo_root/$file" ]]; then
        cp "$repo_root/$file" "$app_dir/$file"
    fi
done

for dir in i18n logic resources src ui; do
    mkdir -p "$app_dir/$dir"
    rsync -a --delete \
        --exclude target/ \
        --exclude gen/ \
        "$repo_root/$dir/" "$app_dir/$dir/"
done

rm -f "$app_dir/Cargo.lock"

# The public repo is a standalone Cargo workspace with sibling KeyOS path
# dependencies. Inside the KeyOS monorepo, the app is a workspace member and
# those dependencies are two directories above the app.
perl -0pi -e '
    s/\n\[workspace\]\n\n\[patch\.crates-io\]\ngetrandom = \{ path = "\.\.\/KeyOS-dev2\/imports\/getrandom" \}\n//s;
    s#\.\./KeyOS-dev2/#../../#g;
' "$app_dir/Cargo.toml"

if git -C "$keyos_root" apply --unidiff-zero --reverse --check "$integration_patch" >/dev/null 2>&1; then
    echo "KeyOS integration patch is already applied."
elif git -C "$keyos_root" apply --unidiff-zero --check "$integration_patch"; then
    git -C "$keyos_root" apply --unidiff-zero "$integration_patch"
    echo "Applied KeyOS integration patch."
else
    echo "The KeyOS integration patch does not apply cleanly to this checkout." >&2
    echo "See docs/KEYOS-PATCHES.md for the four required edits." >&2
    exit 1
fi

if [[ -f "$signing_config" && ! -e "$keyos_root/cosign2.toml" ]]; then
    ln -s "$signing_config" "$keyos_root/cosign2.toml"
    echo "Linked private signing config from $signing_config."
fi

echo "Staged the canonical app at $app_dir"
echo "Next: cd \"$keyos_root\" && cargo xtask check gui-app-passwords"
