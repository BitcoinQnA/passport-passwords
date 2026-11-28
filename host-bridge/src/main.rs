// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bridges the Passwords browser extension to the Passwords app on Passport Prime.
//!
//! The extension already speaks the Vaults Bridge JSON protocol over a loopback WebSocket (its
//! simulator transport). This process runs next to the browser, listens on that WebSocket and
//! carries each JSON message to the Passwords app over a QLv2 session it holds itself. Passport's
//! USB port can be on another computer. `--relay` runs `ql-usb-relay` there (over SSH), or
//! `--connect host:port` dials a rendezvous that the USB relay also dials (both sides outbound;
//! a keyless splice on Jarvis joins them when the box is not reachable on the tailnet). The
//! process on the USB computer holds no keys and only moves encrypted records. Releases are also
//! sealed to the extension's own session, and this process doesn't log message contents.

use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    process::Stdio,
    rc::Rc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use ql_codec::{Decode, Encode};
use ql_host::{PeerBundle, QlIdentity, Session, StreamOptions, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse as HandshakeError, Request as HandshakeRequest},
    Message,
};
use vaults_bridge_ql::{BridgeFrame, RequestBridgeFrame, APP_ID, MAX_FRAME_BYTES};

/// Runs `ql-usb-relay` next to Passport, over the box's SSH connection to Jarvis
const DEFAULT_RELAY: &str = "ssh -o BatchMode=yes -o ConnectTimeout=30 -o ServerAliveInterval=15 \
    jarvis@100.80.55.66 /home/jarvis/prime-dev-build/ql-usb-relay";

/// Chromium's ID for an unpacked extension is derived from its path; this is the ID of
/// /workspace/prime-ql-autofill/passport-passwords/extension.
const DEFAULT_EXTENSION_ORIGIN: &str = "chrome-extension://hmhfapggphalabfmcdkkocjgbggbhilf";

/// How long a shown invite stays usable
const INVITE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Parser)]
#[command(
    about = "Carries the Passwords extension's WebSocket to the Passwords app on Passport Prime over QLv2, through a USB relay"
)]
struct Cli {
    /// This computer's QL identity and the Passports it paired with (holds a private key)
    #[arg(long, global = true, default_value = "ql-host.state")]
    state: PathBuf,
    /// Shell command whose stdio reaches Passport's QL USB interface (`ql-usb-relay`)
    #[arg(long, global = true, default_value = DEFAULT_RELAY)]
    relay: String,
    /// Outbound `host:port` to a rendezvous (for example Jarvis running ql-byte-splice.py) that
    /// the USB relay also dials. When set, this is used instead of spawning `--relay`.
    #[arg(long, global = true)]
    connect: Option<String>,
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
    /// Show a code for Passport to scan (Settings > Quantum Link > Connect new peer > Scan a code),
    /// and pair once it did. The code goes from this computer's screen to Passport's camera only.
    Invite {
        /// Where to write the code as a QR image, to show to Passport
        #[arg(long, default_value = "/workspace/prime-ql-autofill/pairing-qr.png")]
        qr_png: PathBuf,
    },
    /// Check that the relay reaches Passport's QL USB interface, without a session.
    Probe,
    /// Check the outbound rendezvous path only: no USB, no Passport prompt.
    DialTest,
    /// Serve the extension.
    Serve {
        /// The paired Passport to use, as its QID or the start of it, when there are several
        #[arg(long)]
        peer: Option<String>,
        /// Loopback address the extension connects to
        #[arg(long, default_value = "127.0.0.1:9876")]
        listen: String,
        /// The only WebSocket Origin accepted: the Passwords extension as loaded unpacked from
        /// /workspace/prime-ql-autofill/passport-passwords/extension (its ID follows from that path)
        #[arg(long, default_value = DEFAULT_EXTENSION_ORIGIN)]
        allowed_origin: String,
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&runtime, run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let Cli {
        state: path,
        relay,
        connect,
        command,
    } = cli;
    match command {
        Command::Init { name } => {
            if path.exists() {
                bail!("{} exists already", path.display());
            }
            let identity = ql_host::generate_identity(&name);
            save(
                &path,
                &State {
                    identity: identity.clone(),
                    peers: Vec::new(),
                },
            )?;
            println!("generated the identity {name:?}");
            println!("QID {}", grouped_qid(&identity.qid.to_string()));
            println!(
                "Passport shows this QID on the new peer's page once paired: check it matches."
            );
            Ok(())
        }
        Command::Invite { qr_png } => invite(&path, &relay, connect.as_deref(), &qr_png).await,
        Command::Probe => probe(&relay, connect.as_deref()).await,
        Command::DialTest => dial_test(&relay, connect.as_deref()).await,
        Command::Serve {
            peer,
            listen,
            allowed_origin,
        } => {
            let state = load(&path)?;
            let peer = select_peer(&state.peers, peer.as_deref())?.clone();
            let link = Link {
                identity: state.identity,
                peer,
                relay,
                connect,
                allowed_origin,
                session: RefCell::new(None),
            };
            serve(Rc::new(link), &listen).await
        }
    }
}

/// Shows an invite as a QR image and pairs once Passport scanned it. Any failure ends this
/// invite for good: it may mean someone else raced for it, so the user starts over with a new one.
async fn invite(path: &Path, relay: &str, connect: Option<&str>, qr_png: &Path) -> Result<()> {
    let mut state = load(path)?;
    let (code, pairing) = Session::invite(
        open_transport(relay, connect).await?,
        state.identity.clone(),
    );
    write_qr_png(&code, qr_png)?;
    println!("Pairing QR written to {}", qr_png.display());
    println!(
        "On Passport: Settings > Quantum Link > Connect new peer > Scan a code, then scan it."
    );
    println!(
        "This computer is {:?}, QID {}",
        state.identity.name,
        grouped_qid(&state.identity.qid.to_string())
    );
    let result = tokio::time::timeout(INVITE_TIMEOUT, pairing).await;
    // The invite is single use either way: take its image down.
    std::fs::remove_file(qr_png).ok();
    match result {
        Ok(Ok((session, peer))) => {
            state.peers.retain(|known| known.qid != peer.qid);
            state.peers.push(peer.clone());
            save(path, &state)?;
            println!("paired with {:?}, QID {}", peer.name, grouped_qid(&peer.qid.to_string()));
            println!("Accept it on Passport if asked, and check Passport lists this computer's QID above.");
            session.close().await;
            Ok(())
        }
        Ok(Err(error)) => bail!(
            "pairing failed ({error}). Treat it as possible interference: this invite is void. On Passport, \
             forget any new peer it added in Settings > Quantum Link, then run `invite` again for a new code."
        ),
        Err(_) => bail!(
            "no pairing within {} minutes; the invite is void. Run `invite` again for a new code.",
            INVITE_TIMEOUT.as_secs() / 60
        ),
    }
}

fn write_qr_png(code: &str, path: &Path) -> Result<()> {
    let qr = qrcode::QrCode::new(code.as_bytes()).context("encoding the invite as a QR code")?;
    let image = qr
        .render::<image::Luma<u8>>()
        .min_dimensions(600, 600)
        .quiet_zone(true)
        .build();
    image
        .save(path)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// A QID in the groups of 8 Passport shows it in
fn grouped_qid(qid: &str) -> String {
    qid.as_bytes()
        .chunks(8)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

async fn serve(link: Rc<Link>, listen: &str) -> Result<()> {
    ensure_loopback(listen)?;
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("listening on {listen}"))?;
    log::info!(
        "listening on ws://{listen} for the Passwords extension; Passport is {}",
        link.peer.name
    );

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
async fn open_transport(relay: &str, connect: Option<&str>) -> Result<Transport> {
    if let Some(address) = connect {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .with_context(|| format!("dialing the USB relay rendezvous at {address}"))?;
        stream.set_nodelay(true)?;
        log::info!("connected to the USB relay rendezvous at {address}");
        let (reader, writer) = stream.into_split();
        return Ok(Transport::framed(reader, writer));
    }
    open_relay(relay)
}

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

async fn probe(relay: &str, connect: Option<&str>) -> Result<()> {
    if connect.is_some() {
        bail!("probe over --connect would claim the Prime's USB interface; use dial-test for a path check");
    }
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
    let transport = open_transport(relay, None).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(transport);
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("the box reaches Passport's QL USB interface through the relay");
    Ok(())
}

/// Echoes one framed record from the USB relay over the rendezvous, without a QL session.
async fn dial_test(relay: &str, connect: Option<&str>) -> Result<()> {
    if let Some(address) = connect {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .with_context(|| format!("dialing the USB relay rendezvous at {address}"))?;
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.into_split();
        echo_dial_test(reader, writer).await?;
        println!("dial-test ok: echoed a record through the rendezvous at {address}");
        return Ok(());
    }
    let mut child = tokio::process::Command::new("sh")
        .args(["-c", relay])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("starting the rendezvous relay")?;
    let writer = child.stdin.take().context("relay stdin")?;
    let reader = child.stdout.take().context("relay stdout")?;
    echo_dial_test(reader, writer).await?;
    println!("dial-test ok: echoed a record through --relay");
    Ok(())
}

async fn echo_dial_test(
    mut reader: impl AsyncReadExt + Unpin,
    mut writer: impl AsyncWriteExt + Unpin,
) -> Result<()> {
    let mut length = [0; 4];
    tokio::time::timeout(Duration::from_secs(30), reader.read_exact(&mut length))
        .await
        .context("waiting for the USB relay's dial-test record")?
        .context("the rendezvous closed before the dial-test record")?;
    let n = u32::from_be_bytes(length) as usize;
    if n == 0 || n > 64 * 1024 {
        bail!("dial-test record length {n} is not valid");
    }
    let mut record = vec![0; n];
    reader
        .read_exact(&mut record)
        .await
        .context("reading the dial-test record")?;
    writer.write_all(&length).await?;
    writer.write_all(&record).await?;
    writer.flush().await?;
    Ok(())
}

fn load(path: &Path) -> Result<State> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading {} (run `init` first)", path.display()))?;
    State::decode_bytes(bytes.as_slice())
        .map_err(|error| anyhow::anyhow!("corrupt {}: {error:?}", path.display()))
}

/// Replaces the file at `path` with `state`, readable only by its owner, as it holds a private key.
fn save(path: &Path, state: &State) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("new");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("writing {}", temporary.display()))?;
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
    connect: Option<String>,
    allowed_origin: String,
    session: RefCell<Option<Rc<Session>>>,
}

impl Link {
    async fn session(&self) -> Result<Rc<Session>> {
        if let Some(session) = self.session.borrow().as_ref() {
            return Ok(session.clone());
        }
        log::info!("connecting to {} through the USB relay", self.peer.name);
        let transport = open_transport(&self.relay, self.connect.as_deref()).await?;
        let session = Session::connect(transport, self.identity.clone(), self.peer.clone())
            .await
            .context("connecting to Passport")?;
        // Passport asks its user the first time; it answers once they decided.
        log::info!(
            "asking Passport for access to the Passwords app (approve it on Passport if asked)"
        );
        session
            .request_access(&[APP_ID])
            .await
            .context("asking for access to the Passwords app")?;
        log::info!("connected, with access to the Passwords app");
        let session = Rc::new(session);
        *self.session.borrow_mut() = Some(session.clone());
        Ok(session)
    }

    fn drop_session(&self) {
        self.session.borrow_mut().take();
    }

    /// Carries one JSON request to the Passwords app, and returns its JSON response.
    async fn call(&self, json: String) -> Result<String> {
        let session = self.session().await?;
        let result = session
            .rpc()
            .request::<RequestBridgeFrame>(&BridgeFrame { json }, StreamOptions::default())
            .await;
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
    let allowed = link.allowed_origin.as_str();
    let ws = tokio_tungstenite::accept_hdr_async(stream, |request: &HandshakeRequest, response| {
        check_origin(request, allowed).map(|()| response)
    })
    .await
    .context("WebSocket handshake")?;
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

/// Accepts a WebSocket handshake only from the Passwords extension's Origin. Web pages and other
/// extensions get 403, so they can't drive the bridge from the same browser.
fn check_origin(request: &HandshakeRequest, allowed: &str) -> Result<(), HandshakeError> {
    let origin = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok());
    if origin == Some(allowed) {
        return Ok(());
    }
    log::warn!("refused a WebSocket handshake from origin {origin:?}");
    let mut refusal = HandshakeError::new(Some("origin not allowed".into()));
    *refusal.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN;
    Err(refusal)
}

/// The request's `id`, which a reply the bridge makes up itself has to echo
fn request_id(json: &str) -> String {
    // A full JSON parser isn't worth a dependency: ids are short decimal strings the extension makes.
    json.split_once("\"id\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(id, _)| id)
        .filter(|id| {
            id.len() <= 32
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .unwrap_or("0")
        .to_string()
}

fn error_reply(id: &str, code: i32, message: &str) -> String {
    let message: String = message
        .chars()
        .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
        .take(200)
        .collect();
    format!("{{\"id\":\"{id}\",\"error\":{{\"code\":{code},\"message\":\"{message}\"}}}}")
}

fn select_peer<'a>(peers: &'a [PeerBundle], filter: Option<&str>) -> Result<&'a PeerBundle> {
    let mut matching = peers
        .iter()
        .filter(|peer| filter.is_none_or(|filter| peer.qid.to_string().starts_with(filter)));
    match (matching.next(), matching.next()) {
        (Some(peer), None) => Ok(peer),
        (None, _) if peers.is_empty() => bail!("no paired Passport: run `invite` first"),
        (None, _) => bail!("no paired Passport matches --peer"),
        (Some(_), Some(_)) => bail!("several paired Passports: pick one with --peer"),
    }
}

/// The extension runs on this computer; the bridge must not listen anywhere but loopback.
fn ensure_loopback(address: &str) -> Result<()> {
    let address: std::net::SocketAddr = address
        .parse()
        .context("--listen must be an IP address and port")?;
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
        assert_eq!(
            reply,
            r#"{"id":"3","error":{"code":99,"message":"Passport not connected: x"}}"#
        );
    }

    async fn handshake(origin: Option<&str>) -> bool {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_hdr_async(stream, |request: &HandshakeRequest, response| {
                check_origin(request, DEFAULT_EXTENSION_ORIGIN).map(|()| response)
            })
            .await
            .is_ok()
        });
        let mut request = format!("ws://{address}/").into_client_request().unwrap();
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert("origin", origin.parse().unwrap());
        }
        let client = tokio_tungstenite::connect_async(request).await.is_ok();
        let server = server.await.unwrap();
        assert_eq!(client, server);
        client
    }

    #[tokio::test]
    async fn accepts_only_the_extension_origin() {
        assert!(handshake(Some(DEFAULT_EXTENSION_ORIGIN)).await);
        assert!(!handshake(Some("http://127.0.0.1:8081")).await);
        assert!(!handshake(Some("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).await);
        assert!(!handshake(Some("null")).await);
        assert!(!handshake(None).await);
    }

    #[test]
    fn writes_a_scannable_size_qr_png() {
        let path = std::env::temp_dir().join("passwords-ql-bridge-test-qr.png");
        write_qr_png("not a real invite", &path).unwrap();
        let image = image::open(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(image.width() >= 600 && image.width() == image.height());
    }

    #[test]
    fn groups_the_qid_like_passport() {
        assert_eq!(grouped_qid("0123456789abcdefXY"), "01234567 89abcdef XY");
    }

    #[test]
    fn refuses_non_loopback() {
        assert!(ensure_loopback("127.0.0.1:9876").is_ok());
        assert!(ensure_loopback("0.0.0.0:9876").is_err());
    }
}
