// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Transport abstraction for Vaults Bridge.
//!
//! Two transports compile-gate by target:
//!
//!   - **WebSocket** on `cfg(not(keyos))` for the hosted-mode simulator. Lets the browser extension talk to a
//!     host-side build of the app during development without a Prime.
//!
//!   - **Local vault** on SDK hardware builds. The public SDK does not expose the USB device service yet, so
//!     the browser bridge stays disabled while local credential, import, backup, and restore flows remain usable.
//!
//! The browser protocol remains transport-independent so a QLv2 adapter can
//! replace the local hardware adapter when the public SDK exposes that route.

use std::sync::{Mutex, OnceLock};

#[cfg(not(keyos))]
mod websocket;
#[cfg(not(keyos))]
pub use websocket::serve;

#[cfg(keyos)]
mod local;
#[cfg(keyos)]
pub use local::serve;

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
