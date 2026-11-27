// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bridges the Passwords browser extension to the Passwords app on Passport Prime.
//!
//! The extension already speaks the Vaults Bridge JSON protocol over a loopback WebSocket (its
//! simulator transport). This process runs next to the browser, listens on that WebSocket and
//! carries each JSON message to the Passwords app over a QLv2 session it holds itself. Passport's
//! USB port can be on another computer: `--relay` runs `ql-usb-relay` there (over SSH), which only
//! moves the session's encrypted records and holds no keys. Releases are also sealed to the
//! extension's own session, and this process doesn't log message contents.

use std::{cell::RefCell, path::{Path, PathBuf}, process::Stdio, rc::Rc, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use ql_codec::{Decode, Encode};
use ql_host::{PeerBundle, QlIdentity, Session, StreamOptions, Transport};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use vaults_bridge_ql::{BridgeFrame, RequestBridgeFrame, APP_ID, MAX_FRAME_BYTES};

/// Runs `ql-usb-relay` next to Passport, over the box's SSH connection to Jarvis
const DEFAULT_RELAY: &str = "ssh -o BatchMode=yes -o ConnectTimeout=30 -o ServerAliveInterval=15 \
    jarvis@100.80.55.66 /home/jarvis/prime-dev-build/ql-usb-relay";

#[derive(Parser)]
#[command(about = "Carries the Passwords extension's WebSocket to the Passwords app on Passport Prime over QLv2, through a USB relay")]
struct Cli {
    /// This computer's QL identity and the Passports it paired with (holds a private key)
    #[arg(long, global = true, default_value = "ql-host.state")]
    state: PathBuf,
    /// Shell command whose stdio reaches Passport's QL USB interface (`ql-usb-relay`)
    #[arg(long, global = true, default_value = DEFAULT_RELAY)]
    relay: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate this computer's QL identity, which Passport shows as `name`.
    Init {
        #[arg(long)]
        name: String,
    },
    /// Pair with the code on Passport's Settings > Quantum Link > Connect new peer page.
    Pair { code: String },
    /// Check that the relay reaches Passport's QL USB interface, without a session.
    Probe,
    /// Serve the extension.
    Serve {
        /// The paired Passport to use, as its QID or the start of it, when there are several
        #[arg(long)]
        peer: Option<String>,
        /// Loopback address the extension connects to
        #[arg(long, default_value = "127.0.0.1:9876")]
        listen: String,
    },
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
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    tokio::task::LocalSet::new().block_on(&runtime, run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let Cli { state: path, relay, command } = cli;
    match command {
        Command::Init { name } => {
            if path.exists() {
                bail!("{} exists already", path.display());
            }
            let identity = ql_host::generate_identity(&name);
            println!("generated {} ({name})", identity.qid);
            save(&path, &State { identity, peers: Vec::new() })
        }
        Command::Pair { code } => {
            let mut state = load(&path)?;
            let (session, peer) = Session::pair(open_relay(&relay)?, state.identity.clone(), &code).await?;
            state.peers.retain(|known| known.qid != peer.qid);
            state.peers.push(peer.clone());
            save(&path, &state)?;
            println!("paired with {} {}; accept it on Passport", peer.qid, peer.name);
            session.close().await;
            Ok(())
        }
        Command::Probe => probe(&relay).await,
        Command::Serve { peer, listen } => {
            let state = load(&path)?;
            let peer = select_peer(&state.peers, peer.as_deref())?.clone();
            serve(Rc::new(Link { identity: state.identity, peer, relay, session: RefCell::new(None) }), &listen).await
        }
    }
}

async fn serve(link: Rc<Link>, listen: &str) -> Result<()> {
    ensure_loopback(listen)?;
    let listener = TcpListener::bind(listen).await.with_context(|| format!("listening on {listen}"))?;
    log::info!("listening on ws://{listen} for the Passwords extension; Passport is {}", link.peer.name);

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

/// Starts the relay and returns a transport over its stdio. Its stderr passes through.
fn open_relay(relay: &str) -> Result<Transport> {
    let mut child = tokio::process::Command::new("sh")
        .args(["-c", relay])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("starting the USB relay")?;
    let stdin = child.stdin.take().context("relay stdin")?;
    let stdout = child.stdout.take().context("relay stdout")?;
    // The relay exits when its stdin closes, which happens when the session drops the transport.
    tokio::spawn(async move {
        match child.wait().await {
            Ok(status) => log::info!("USB relay exited: {status}"),
            Err(error) => log::warn!("USB relay: {error}"),
        }
    });
    Ok(Transport::framed(stdout, stdin))
}

async fn probe(relay: &str) -> Result<()> {
    let status = tokio::process::Command::new("sh")
        .args(["-c", &format!("{relay} --probe")])
        .stdin(Stdio::null())
        .status()
        .await
        .context("starting the USB relay")?;
    if !status.success() {
        bail!("the relay didn't reach Passport's QL interface ({status})");
    }
    // The same relay, as a transport: open it, check it stays up, and close it.
    let transport = open_relay(relay)?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(transport);
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("the box reaches Passport's QL USB interface through the relay");
    Ok(())
}

fn load(path: &Path) -> Result<State> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {} (run `init` first)", path.display()))?;
    State::decode_bytes(bytes.as_slice()).map_err(|error| anyhow::anyhow!("corrupt {}: {error:?}", path.display()))
}

/// Replaces the file at `path` with `state`, readable only by its owner, as it holds a private key.
fn save(path: &Path, state: &State) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("new");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&temporary).with_context(|| format!("writing {}", temporary.display()))?;
    file.write_all(&state.encode_vec())?;
    file.sync_all()?;
    std::fs::rename(&temporary, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// The QLv2 session to Passport, opened on demand and replaced after a failure
struct Link {
    identity: QlIdentity,
    peer: PeerBundle,
    relay: String,
    session: RefCell<Option<Rc<Session>>>,
}

impl Link {
    async fn session(&self) -> Result<Rc<Session>> {
        if let Some(session) = self.session.borrow().as_ref() {
            return Ok(session.clone());
        }
        log::info!("connecting to {} through the USB relay", self.peer.name);
        let transport = open_relay(&self.relay)?;
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
        (None, _) if peers.is_empty() => bail!("no paired Passport: run `pair <code>` first"),
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
