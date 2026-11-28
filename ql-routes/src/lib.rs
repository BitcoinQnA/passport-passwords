// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Passwords app's QLv2 route.
//!
//! One request route carries one Vaults Bridge JSON message each way, unchanged from the
//! WebSocket simulator protocol (see `docs/PROTOCOL.md`). QLv2 already authenticates and encrypts
//! the link; the Vaults Bridge session envelope stays on top so the extension needs no change.

/// The Passwords app ID, as in `app-config.toml`
pub const APP_ID: ql_keyos::AppId = ql_keyos::AppId::from_hex("0x50617373776f72647300000000000000");

/// Longest JSON message either side accepts, as the line limit in `vaults-bridge-protocol::frame`
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

ql_keyos::app_routes! {
    crate::APP_ID => {
        RequestBridgeFrame: Request = 1,
    }
}

/// One Vaults Bridge JSON request or response
#[derive(Debug, Clone, PartialEq, Eq, ql_codec::Codec)]
pub struct BridgeFrame {
    pub json: String,
}

impl ql_rpc::Request for RequestBridgeFrame {
    type Request = BridgeFrame;
    type Response = BridgeFrame;
}
