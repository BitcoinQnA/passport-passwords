// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! QLv2 transport on Passport Prime.
//!
//! Answers the Passwords route (`vaults-bridge-ql`) from paired QLv2 peers that the user let reach
//! this app. Each request carries one Vaults Bridge JSON message, handled by the same engine as the
//! WebSocket simulator, so releases still go through the on-device approval screen.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ql_rpc::request::{RequestHandlerLocal, Response};
use slint_keyos_platform::{spawn_local, worker, TaskHandle};
use vaults_bridge_core::engine::{Engine, ReleasePeer};
use vaults_bridge_keystore::Keystore;
use vaults_bridge_protocol::{ErrorCode, ErrorPayload, Request};
use vaults_bridge_ql::{BridgeFrame, RequestBridgeFrame, MAX_FRAME_BYTES};

use crate::transport::set_status;

ql::use_api!();

#[derive(Clone, Copy)]
struct SlintLocalSpawner;

impl ql_rpc::Spawner for SlintLocalSpawner {
    type Handle = TaskHandle<()>;
}

impl ql_rpc::LocalSpawner for SlintLocalSpawner {
    fn spawn<F>(&self, future: F) -> Self::Handle
    where
        F: std::future::Future<Output = ()> + 'static,
    {
        spawn_local(future)
    }
}

#[derive(Clone)]
struct Routes {
    engine: Arc<Engine<Keystore>>,
}

impl RequestHandlerLocal<RequestBridgeFrame, RpcStream> for Routes {
    async fn handle(
        self,
        context: ql_rpc::Context,
        request: BridgeFrame,
        response: Response<BridgeFrame, RpcWriter>,
    ) {
        let peer = lookup_release_peer(context.qid);
        let json = handle_json(&self.engine, &request.json, Some(peer)).await;
        if let Err(error) = response.respond(BridgeFrame { json }).await {
            log::warn!("QL bridge response failed: {error:?}");
        }
    }
}

fn lookup_release_peer(qid: ql::QID) -> ReleasePeer {
    let qid_str = qid.to_string();
    let name = QlApi::default()
        .status()
        .ok()
        .and_then(|status| {
            status.peers.into_iter().find(|peer| peer.qid == qid).map(|peer| peer.name)
        })
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Unknown peer".into());
    ReleasePeer { name, qid: qid_str }
}

async fn handle_json(engine: &Engine<Keystore>, json: &str, peer: Option<ReleasePeer>) -> String {
    let parsed = if json.len() > MAX_FRAME_BYTES { None } else { serde_json::from_str::<Request>(json).ok() };
    let response = match parsed {
        Some(request) => engine.handle_from(request, now_ms(), peer).await,
        None => vaults_bridge_protocol::Response::Err {
            id: "0".into(),
            error: ErrorPayload { code: ErrorCode::InvalidRequest as i32, message: "invalid request".into() },
        },
    };
    serde_json::to_string(&response).unwrap_or_default()
}

/// Starts answering the Passwords route on the UI thread's executor. Keep the handle for as long as
/// the app runs: dropping it stops the route.
pub fn start(engine: Arc<Engine<Keystore>>) -> TaskHandle<()> {
    spawn_local(async move {
        let ql = QlApi::default();
        let router = ql::router(SlintLocalSpawner).request::<RequestBridgeFrame>().build(Routes { engine });
        // TODO: localize
        set_status("Browser connection ready over Quantum Link");
        if let Err(error) = ql.run_rpc_handlers(worker(), router).await {
            log::warn!("QL route subscription failed: {error:?}");
            set_status(format!("Quantum Link unavailable: {error:?}"));
            return;
        }
        set_status("Quantum Link route stopped");
    })
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
