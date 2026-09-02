<!--
SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# QLv2 hardware transport migration

## Current boundary

Foundation SDK 1.0 does not package `api/usb`. Raw `os/usbdev` interface
registration and endpoint I/O are not grantable to independently signed apps.
The SDK build therefore uses `src/transport/local.rs`. The hardware-tested raw
WebUSB implementation remains in `src/transport/webusb.rs` behind the disabled
`legacy-webusb` feature.

The supported destination is a third-party QLv2 app route over the shared USB
transport. Foundation tracks that work in
[SFT-7295](https://linear.app/foundation-devices/issue/SFT-7295) and
[SFT-7677](https://linear.app/foundation-devices/issue/SFT-7677). The device
transport prototype is in
[KeyOS-dev PR 2138](https://github.com/Foundation-Devices/KeyOS-dev/pull/2138).

## Device adapter

When the public SDK ships the QLv2 crate and permission group:

1. Add the SDK QLv2 dependency and its user-grantable app-route permissions.
2. Implement `transport::serve` over one QLv2 stream addressed to this app ID.
3. Carry the existing bounded JSON frames inside the stream without changing
   the engine API.
4. Preserve exact-origin checks, request nonces, field limits, approval timeout,
   and the one-request approval slot.
5. Treat peer disconnect as a session reset and reject any pending approval.

The QLv2 session already authenticates and encrypts the transport. Keep the
Vaults Bridge session envelope during the first migration so the browser and
device protocol remain compatible. Removing redundant encryption is a separate
protocol-version decision.

## Browser adapter

Replace `extension/webusb-transport.js` with a transport that uses Foundation's
QLv2 JS/WASM runtime and WebUSB adapter. The extension must still derive origins
from `sender.tab.url`; the transport peer never supplies or overrides a browser
origin.

The adapter is complete when a user can pair through the system consent flow,
open the Passwords app route, reconnect without descriptor churn, and exercise
save, list, generate, release, cancel, and timeout on production KeyOS.
