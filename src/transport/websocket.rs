// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebSocket transport for the hosted-mode simulator.
//!
//! Listens on `127.0.0.1:9876` and accepts one client at a time. Each
//! WebSocket text frame is a complete JSON request; we respond with one
//! text frame per response. The 64-byte interrupt framing layer is
//! bypassed here since WebSocket already provides message boundaries.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use vaults_bridge_core::engine::Engine;
use vaults_bridge_keystore::Keystore;
use vaults_bridge_protocol::{ErrorCode, ErrorPayload, Request, Response};

use crate::transport::set_status;

pub async fn serve(engine: Arc<Engine<Keystore>>, bind: &str) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    set_status(format!("ws listening on {bind}"));
    log::info!("vaults-bridge ws listening on {bind}");

    loop {
        let (stream, peer) = listener.accept().await?;
        log::info!("vaults-bridge ws client connected: {peer}");
        set_status(format!("ws client {peer}"));
        let engine = engine.clone();

        tokio::spawn(async move {
            let ws = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    log::warn!("ws handshake failed: {e}");
                    return;
                }
            };
            let (mut sink, mut src) = ws.split();
            while let Some(msg) = src.next().await {
                let text = match msg {
                    Ok(Message::Text(t)) => t,
                    Ok(Message::Close(_)) => break,
                    Ok(_) => continue,
                    Err(e) => {
                        log::warn!("ws read: {e}");
                        break;
                    }
                };
                let req: Request = match serde_json::from_str(&text) {
                    Ok(r) => r,
                    Err(_e) => {
                        let err = Response::Err {
                            id: "0".into(),
                            error: ErrorPayload {
                                code: ErrorCode::InvalidRequest as i32,
                                message: "invalid request".to_string(),
                            },
                        };
                        let _ = sink.send(Message::Text(serde_json::to_string(&err).unwrap())).await;
                        continue;
                    }
                };
                let resp = engine.handle(req, now_ms()).await;
                let payload = serde_json::to_string(&resp).unwrap();
                if sink.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            log::info!("vaults-bridge ws client disconnected");
            set_status("ws idle");
        });
    }
}

fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }
