// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_lite::StreamExt;
use ql_codec::{Decode, Encode};
use ql_common::{StreamInfo, QID};
use ql_fsm::{PairingInvite, PeerStatus};
use ql_keyos::{AppId, PeerPermissions};
use ql_runtime::{
    new_runtime, rpc::RpcHandle, QlInbound, QlPlatform, QlStream, QlTimer, RuntimeConfig, RuntimeHandle,
    StreamOptions,
};
use ql_wire::{PairingToken, PeerBundle, QlIdentity, QlRandom, SoftwareCrypto};
use system_rpc::{PeerPermissionsParams, PeerPermissionsResponse, RequestPeerPermissions};

use crate::Transport;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// A QuantumLink session with one peer
pub struct Session {
    handle: RuntimeHandle,
    runtime: tokio::task::JoinHandle<()>,
    outgoing: async_channel::Sender<Vec<u8>>,
    status: async_channel::Receiver<PeerStatus>,
    incoming: async_channel::Receiver<(StreamInfo, QlStream)>,
    paired: async_channel::Receiver<PeerBundle>,
}

impl Session {
    /// Opens a session with `peer`, which `identity` paired with before.
    pub async fn connect(transport: Transport, identity: QlIdentity, peer: PeerBundle) -> io::Result<Self> {
        let session = Self::start(transport, identity);
        session.handle.bind_peer(peer);
        session.handle.connect();
        // The router drops what it can't deliver, and a lost handshake record isn't sent again, so
        // the handshake ends in Disconnected and a new one has to replace it.
        let connected = session.wait_connected(|| session.handle.connect());
        tokio::time::timeout(CONNECT_TIMEOUT, connected).await.map_err(|_| not_connected())??;
        Ok(session)
    }

    /// Pairs `identity` with the maker of the invite `code`, returning the peer's bundle for later
    /// [`Session::connect`]s. Passport still asks its user to accept the new peer afterwards.
    pub async fn pair(
        transport: Transport,
        identity: QlIdentity,
        code: &str,
    ) -> io::Result<(Self, PeerBundle)> {
        let invite = decode_invite(code)?;
        let session = Self::start(transport, identity);
        session.handle.start_pairing(invite);
        tokio::time::timeout(CONNECT_TIMEOUT, session.finish_pairing()).await.map_err(|_| not_connected())?
    }

    /// An invite code to `identity` for Passport to scan, and the pairing, which finishes once a
    /// peer used the code.
    pub fn invite(
        transport: Transport,
        identity: QlIdentity,
    ) -> (String, impl Future<Output = io::Result<(Self, PeerBundle)>>) {
        let mut token = PairingToken([0; PairingToken::SIZE]);
        SoftwareCrypto.fill_random_bytes(&mut token.0);
        let invite = PairingInvite { version: PairingInvite::VERSION, qid: identity.qid, token };
        let code = ql_invite_code::encode(transport.invite_transport, &invite.encode_vec());
        let pairing = async move {
            let session = Self::start(transport, identity);
            session.handle.arm_pairing(token);
            session.finish_pairing().await
        };
        (code, pairing)
    }

    /// Asks the peer to let this one reach `app_ids`, which replace the apps it may reach so far.
    /// Passport asks its user about the apps new to the peer, and answers once they decided.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::PermissionDenied`] when the peer refused.
    pub async fn request_access(&self, app_ids: &[AppId]) -> io::Result<()> {
        let params = PeerPermissionsParams(PeerPermissions { app_ids: app_ids.to_vec() });
        let response = self
            .rpc()
            .request::<RequestPeerPermissions>(&params, StreamOptions::default())
            .await
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        match response {
            PeerPermissionsResponse::Updated => Ok(()),
            PeerPermissionsResponse::Denied => {
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "the peer denied access"))
            }
        }
    }

    /// Calls the peer's routes. The handle keeps the session going until it is dropped.
    pub fn rpc(&self) -> RpcHandle { self.handle.rpc() }

    /// The next stream the peer opened, or `None` once the session stopped. Streams the peer
    /// opens while too many others wait here are reset.
    pub async fn next_incoming(&self) -> Option<(StreamInfo, QlStream)> { self.incoming.recv().await.ok() }

    /// The next change of the peer's status, or `None` once the link is gone
    pub async fn next_status(&self) -> Option<PeerStatus> { self.status.recv().await.ok() }

    /// Unpairs the peer, telling it so if it's connected, and ends the session.
    pub async fn unpair(self) {
        self.handle.unpair();
        self.close().await;
    }

    /// Ends the session, so that the peer doesn't wait for this one to time out, and waits a little
    /// for the link to send what's left.
    pub async fn close(self) {
        let Self { handle, runtime, outgoing, .. } = self;
        // Dropping the last handle stops the runtime, which queues a close record before it ends.
        drop(handle);
        tokio::time::timeout(CLOSE_TIMEOUT, runtime).await.ok();
        // The link can still take what's queued, and lets go of its end once it sent everything.
        outgoing.close();
        let sent = async {
            while outgoing.receiver_count() > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(CLOSE_TIMEOUT, sent).await.ok();
    }

    fn start(transport: Transport, identity: QlIdentity) -> Self {
        const MAX_WAITING_STREAMS: usize = 16;

        let Transport { outgoing, incoming, .. } = transport;
        let (status_sender, status) = async_channel::unbounded();
        let (paired_sender, paired) = async_channel::unbounded();
        let (streams, incoming_streams) = async_channel::bounded(MAX_WAITING_STREAMS);
        let platform = HostPlatform {
            origin: tokio::time::Instant::now(),
            outgoing: outgoing.clone(),
            inbound: Some(Inbound { records: Box::pin(incoming), status: status_sender.clone() }),
            status: status_sender,
            paired: paired_sender,
            streams,
        };
        let (runtime, handle) = new_runtime(identity, platform, RuntimeConfig::default());
        let runtime = tokio::task::spawn_local(runtime.run());
        Self { handle, runtime, outgoing, status, incoming: incoming_streams, paired }
    }

    async fn finish_pairing(self) -> io::Result<(Self, PeerBundle)> {
        self.wait_connected(|| {}).await?;
        let peer = self.paired.recv().await.map_err(|_| io::Error::other("the pairing left no peer"))?;
        Ok((self, peer))
    }

    async fn wait_connected(&self, on_disconnected: impl Fn()) -> io::Result<()> {
        loop {
            match self.status.recv().await {
                Ok(PeerStatus::Connected) => return Ok(()),
                Ok(PeerStatus::Disconnected) => on_disconnected(),
                Ok(PeerStatus::Initiator) => {}
                Ok(PeerStatus::Unpaired) => return Err(io::Error::other("the peer unpaired")),
                Err(_) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "the link is gone")),
            }
        }
    }
}

fn not_connected() -> io::Error { io::Error::new(io::ErrorKind::TimedOut, "the session did not connect") }

fn decode_invite(code: &str) -> io::Result<PairingInvite> {
    // The caller picked the transport, so the one the code names doesn't matter here.
    let invite = ql_invite_code::decode(code.trim().as_bytes())
        .and_then(|(_, invite)| PairingInvite::decode_bytes(invite.as_slice()).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a QuantumLink invite code"))?;
    if invite.version != PairingInvite::VERSION {
        let message = format!("unsupported invite version {}", invite.version);
        return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
    }
    Ok(invite)
}

struct HostPlatform {
    origin: tokio::time::Instant,
    outgoing: async_channel::Sender<Vec<u8>>,
    inbound: Option<Inbound>,
    status: async_channel::Sender<PeerStatus>,
    paired: async_channel::Sender<PeerBundle>,
    streams: async_channel::Sender<(StreamInfo, QlStream)>,
}

impl QlPlatform for HostPlatform {
    type Crypto = SoftwareCrypto;
    type Inbound = Inbound;
    type Timer = TokioTimer;
    type WriteMessageFut<'a> = std::future::Ready<bool>;

    fn crypto(&self) -> &Self::Crypto { &SoftwareCrypto }

    fn now(&self) -> Duration { self.origin.elapsed() }

    fn write_message(&self, message: Vec<u8>) -> Self::WriteMessageFut<'_> {
        std::future::ready(self.outgoing.try_send(message).is_ok())
    }

    fn inbound(&mut self) -> Self::Inbound {
        self.inbound.take().expect("the runtime takes its inbound once")
    }

    fn timer(&self) -> Self::Timer {
        TokioTimer { origin: self.origin, sleep: Box::pin(tokio::time::sleep_until(far_future())) }
    }

    fn persist_peer(&self, peer: PeerBundle) { self.paired.try_send(peer).ok(); }

    fn handle_peer_status(&self, _peer: Option<QID>, status: PeerStatus) {
        self.status.try_send(status).ok();
    }

    fn handle_inbound(&self, info: StreamInfo, stream: QlStream) {
        if let Err(error) = self.streams.try_send((info, stream)) {
            // Dropping the stream resets it.
            let (info, _) = error.into_inner();
            log::warn!("resetting {info:?}, as too many streams wait");
        }
    }
}

struct Inbound {
    records: Pin<Box<async_channel::Receiver<Vec<u8>>>>,
    status: async_channel::Sender<PeerStatus>,
}

impl QlInbound for Inbound {
    fn poll_recv(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<u8>> {
        match self.records.as_mut().poll_next(cx) {
            Poll::Ready(Some(record)) => Poll::Ready(record),
            Poll::Ready(None) => {
                // The runtime has no notion of a link going away, so tell the session through the
                // status, which stops changing anyway.
                if self.status.close() {
                    log::warn!("the link is gone");
                }
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

struct TokioTimer {
    origin: tokio::time::Instant,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl QlTimer for TokioTimer {
    fn set_deadline(mut self: Pin<&mut Self>, deadline: Option<Duration>) {
        let deadline = deadline.map_or_else(far_future, |deadline| self.origin + deadline);
        self.sleep.as_mut().reset(deadline);
    }

    fn poll_wait(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> { self.sleep.as_mut().poll(cx) }
}

fn far_future() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60 * 60 * 24 * 365)
}
