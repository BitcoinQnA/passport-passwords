// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bridges the Passwords browser extension to the Passwords app on Passport Prime.
//!
//! The extension already speaks the Vaults Bridge JSON protocol over a loopback WebSocket (its
//! simulator transport). This process listens on that WebSocket and carries each JSON message to
//! the Passwords app over QLv2 on USB, using the identity and pairing that the `ql-host` CLI from
//! the same KeyOS tree stored. It never sees a password in the clear: releases are sealed to the
//! extension's own session, and it doesn't log message contents.

use std::{cell::RefCell, path::PathBuf, rc::Rc, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use ql_codec::Decode;
use ql_host::{PeerBundle, QlIdentity, Session, StreamOptions, Transport};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use vaults_bridge_ql::{BridgeFrame, RequestBridgeFrame, APP_ID, MAX_FRAME_BYTES};

#[derive(Parser)]
#[command(about = "Carries the Passwords extension's WebSocket to the Passwords app on Passport Prime over QLv2 USB")]
struct Cli {
    /// The `ql-host` state file: this computer's identity and the peers it paired with
    #[arg(long, default_value = "ql-host.state")]
    state: PathBuf,
    /// The paired Passport to use, as its QID or the start of it, when there are several
    #[arg(long)]
    peer: Option<String>,
    /// Loopback address the extension connects to
    #[arg(long, default_value = "127.0.0.1:9876")]
    listen: String,
    /// Only check that a Passport Prime with a QL interface is on USB, then exit
    #[arg(long)]
    probe_usb: bool,
}

/// What the `ql-host` CLI's state file holds; the same layout as its `State`
#[derive(ql_codec::Codec)]
struct State {
    identity: QlIdentity,
    peers: Vec<PeerBundle>,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    if cli.probe_usb {
        drop(Transport::usb().context("opening Passport Prime's QL interface")?);
        println!("Passport Prime's QL interface is on USB and was claimed");
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    tokio::task::LocalSet::new().block_on(&runtime, run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let bytes = std::fs::read(&cli.state).with_context(|| format!("reading {}", cli.state.display()))?;
    let state = State::decode_bytes(bytes.as_slice())
        .map_err(|error| anyhow::anyhow!("corrupt {}: {error:?}", cli.state.display()))?;
    let peer = select_peer(&state.peers, cli.peer.as_deref())?.clone();
    ensure_loopback(&cli.listen)?;

    let link = Rc::new(Link { identity: state.identity, peer, session: RefCell::new(None) });
    let listener = TcpListener::bind(&cli.listen).await.with_context(|| format!("listening on {}", cli.listen))?;
    log::info!("listening on ws://{} for the Passwords extension; Passport is {}", cli.listen, link.peer.name);

    // Connect up front, so the access prompt shows on Passport before the first fill.
    if let Err(error) = link.session().await {
        log::warn!("Passport not reached yet, will retry on the first request: {error:#}");
    }

    loop {
        let (stream, address) = listener.accept().await?;
        log::info!("extension connected from {address}");
        let link = link.clone();
        tokio::task::spawn_local(async move {
            if let Err(error) = serve_client(stream, &link).await {
                log::warn!("extension connection ended: {error:#}");
            }
            log::info!("extension disconnected");
        });
    }
}

/// The QLv2 session to Passport, opened on demand and replaced after a failure
struct Link {
    identity: QlIdentity,
    peer: PeerBundle,
    session: RefCell<Option<Rc<Session>>>,
}

impl Link {
    async fn session(&self) -> Result<Rc<Session>> {
        if let Some(session) = self.session.borrow().as_ref() {
            return Ok(session.clone());
        }
        log::info!("connecting to {} over USB", self.peer.name);
        let transport = Transport::usb().context("opening Passport Prime's QL interface")?;
        let session = Session::connect(transport, self.identity.clone(), self.peer.clone())
            .await
            .context("connecting to Passport")?;
        // Passport asks its user the first time; it answers once they decided.
        log::info!("asking Passport for access to the Passwords app (approve it on Passport if asked)");
        session.request_access(&[APP_ID]).await.context("asking for access to the Passwords app")?;
        log::info!("connected, with access to the Passwords app");
        let session = Rc::new(session);
        *self.session.borrow_mut() = Some(session.clone());
        Ok(session)
    }

    fn drop_session(&self) { self.session.borrow_mut().take(); }

    /// Carries one JSON request to the Passwords app, and returns its JSON response.
    async fn call(&self, json: String) -> Result<String> {
        let session = self.session().await?;
        let result = session.rpc().request::<RequestBridgeFrame>(&BridgeFrame { json }, StreamOptions::default()).await;
        match result {
            Ok(response) => Ok(response.json),
            Err(error) => {
                self.drop_session();
                bail!("Passport not connected: {error:?}")
            }
        }
    }
}

async fn serve_client(stream: TcpStream, link: &Link) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(stream).await.context("WebSocket handshake")?;
    let (mut sink, mut source) = ws.split();
    while let Some(message) = source.next().await {
        let text = match message? {
            Message::Text(text) => text,
            Message::Close(_) => break,
            Message::Ping(data) => {
                sink.send(Message::Pong(data)).await?;
                continue;
            }
            _ => continue,
        };
        let id = request_id(&text);
        let reply = if text.len() > MAX_FRAME_BYTES {
            error_reply(&id, 1, "request too large")
        } else {
            let started = std::time::Instant::now();
            match tokio::time::timeout(Duration::from_secs(150), link.call(text)).await {
                Ok(Ok(reply)) => {
                    log::info!("request {id} answered in {:.1?}", started.elapsed());
                    reply
                }
                Ok(Err(error)) => {
                    log::warn!("request {id} failed: {error:#}");
                    error_reply(&id, 99, &format!("{error:#}"))
                }
                Err(_) => {
                    link.drop_session();
                    error_reply(&id, 5, "Passport not connected: no answer in time")
                }
            }
        };
        sink.send(Message::Text(reply)).await?;
    }
    Ok(())
}

/// The request's `id`, which a reply the bridge makes up itself has to echo
fn request_id(json: &str) -> String {
    // A full JSON parser isn't worth a dependency: ids are short decimal strings the extension makes.
    json.split_once("\"id\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(id, _)| id)
        .filter(|id| id.len() <= 32 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or("0")
        .to_string()
}

fn error_reply(id: &str, code: i32, message: &str) -> String {
    let message: String = message.chars().filter(|c| *c != '"' && *c != '\\' && !c.is_control()).take(200).collect();
    format!("{{\"id\":\"{id}\",\"error\":{{\"code\":{code},\"message\":\"{message}\"}}}}")
}

fn select_peer<'a>(peers: &'a [PeerBundle], filter: Option<&str>) -> Result<&'a PeerBundle> {
    let mut matching =
        peers.iter().filter(|peer| filter.is_none_or(|filter| peer.qid.to_string().starts_with(filter)));
    match (matching.next(), matching.next()) {
        (Some(peer), None) => Ok(peer),
        (None, _) if peers.is_empty() => bail!("no paired Passport: pair with `ql-host pair <code>` first"),
        (None, _) => bail!("no paired Passport matches --peer"),
        (Some(_), Some(_)) => bail!("several paired Passports: pick one with --peer"),
    }
}

/// The extension and the SSH tunnel both use loopback; the bridge must not listen anywhere else.
fn ensure_loopback(address: &str) -> Result<()> {
    let address: std::net::SocketAddr = address.parse().context("--listen must be an IP address and port")?;
    if !address.ip().is_loopback() {
        bail!("--listen must be a loopback address");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_request_id() {
        assert_eq!(request_id(r#"{"id":"17","method":"ping"}"#), "17");
        assert_eq!(request_id(r#"{"method":"ping","id": "abc"}"#), "abc");
        assert_eq!(request_id(r#"{"method":"ping"}"#), "0");
        assert_eq!(request_id(r#"{"id":"a\"b"}"#), "0");
    }

    #[test]
    fn error_reply_is_json_the_extension_reads() {
        let reply = error_reply("3", 99, "Passport not connected: \"x\"\n");
        assert_eq!(reply, r#"{"id":"3","error":{"code":99,"message":"Passport not connected: x"}}"#);
    }

    #[test]
    fn refuses_non_loopback() {
        assert!(ensure_loopback("127.0.0.1:9876").is_ok());
        assert!(ensure_loopback("0.0.0.0:9876").is_err());
    }
}
