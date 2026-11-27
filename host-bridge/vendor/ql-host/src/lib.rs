// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! QuantumLink with Passport Prime from a computer, over USB or through the router Passport reaches
//! with Envoy.
//!
//! A [`Session`] talks to one peer over a [`Transport`]. Sessions spawn their tasks with
//! `tokio::task::spawn_local`, so they must run inside a `tokio::task::LocalSet`.

mod framed;
mod router;
mod session;
mod transport;
mod usb;

pub use ql_common::{StreamInfo, QID};
pub use ql_fsm::PeerStatus;
pub use ql_keyos::AppId;
pub use ql_runtime::{rpc::RpcHandle, QlStream, StreamOptions, StreamReader, StreamWriter};
pub use ql_wire::{PeerBundle, QlIdentity};

pub use crate::{
    framed::MAX_FRAMED_RECORD,
    router::{production_router, PRODUCTION_ROUTER_ADDRESS},
    session::Session,
    transport::Transport,
};

/// A new identity, which peers show as `name`
pub fn generate_identity(name: &str) -> QlIdentity {
    ql_wire::generate_identity(&ql_wire::SoftwareCrypto, name)
}
