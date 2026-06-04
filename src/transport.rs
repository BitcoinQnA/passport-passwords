// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Transport abstraction for Vaults Bridge.
//!
//! Two transports compile-gate by `cfg(keyos)`:
//!
//!   - **WebSocket** on `cfg(not(keyos))` for the hosted-mode simulator. Lets the browser extension talk to a
//!     host-side build of the app during development without a Prime.
//!
//!   - **WebUSB vendor-class** on `cfg(keyos)` for hardware. The app registers a vendor-class interface
//!     (class/subclass/protocol 0xFF/0xFF/0xFF) with two 64-byte interrupt endpoints plus the WebUSB and MS
//!     OS 2.0 Platform Capability descriptors. The browser extension reaches it via `navigator.usb`.
//!
//! Wire format on both transports: 64-byte interrupt-endpoint framing
//! (see `vaults-bridge-protocol::frame`) carrying JSON payloads.
//!
//! This split keeps the USB implementation off the host build (it needs
//! the `os/usbdev` server which only exists on device).

use std::sync::{Mutex, OnceLock};

#[cfg(not(keyos))]
mod websocket;
#[cfg(not(keyos))]
pub use websocket::serve;

#[cfg(keyos)]
mod webusb;
#[cfg(keyos)]
pub use webusb::serve;

/// Shared, human-readable status line the UI banner mirrors.
pub fn status() -> &'static Mutex<String> {
    static INSTANCE: OnceLock<Mutex<String>> = OnceLock::new();
    INSTANCE.get_or_init(|| Mutex::new("starting".into()))
}

pub fn set_status(msg: impl Into<String>) {
    if let Ok(mut g) = status().lock() {
        *g = msg.into();
    }
}
