// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Transport abstraction for Vaults Bridge.
//!
//! Two transports compile-gate by target:
//!
//!   - **WebSocket** on `cfg(not(keyos))` for the hosted-mode simulator. Lets the browser extension talk to a
//!     host-side build of the app during development without a Prime.
//!
//!   - **QLv2** on hardware builds. The app answers its own QLv2 route (`vaults-bridge-ql`) from paired
//!     peers the user let reach it; a host bridge carries the extension's WebSocket messages to it.
//!
//! The browser protocol remains transport-independent so a QLv2 adapter can
//! replace the local hardware adapter when the public SDK exposes that route.

use std::sync::{Mutex, OnceLock};

#[cfg(not(keyos))]
mod websocket;
#[cfg(not(keyos))]
pub use websocket::serve;

#[cfg(keyos)]
mod qlv2;
#[cfg(keyos)]
pub use qlv2::start as start_qlv2;

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
