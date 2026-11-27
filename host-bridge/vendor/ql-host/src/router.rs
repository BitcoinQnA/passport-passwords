// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The router that forwards records between the identities attached to it, over TCP

use std::{io, time::Duration};

use ql_codec::Decode;
use ql_wire::{PeerBundle, QlIdentity};

use crate::{transport::Link, Transport};

/// The address of the router Envoy attaches Passport to
pub const PRODUCTION_ROUTER_ADDRESS: &str = "router.foundation.xyz:7447";

/// The bundle of the router Envoy attaches Passport to
pub fn production_router() -> PeerBundle {
    PeerBundle::decode_bytes(include_bytes!("router-bundle.bin").as_slice())
        .expect("the embedded router bundle decodes")
}

impl Transport {
    /// A transport through the `router` at `address`, which forwards the records addressed to
    /// `identity` to it. It only reaches a Passport attached to the same router.
    pub async fn router(address: &str, router: &PeerBundle, identity: &QlIdentity) -> io::Result<Transport> {
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

        let connected = async {
            let (mut receiver, mut sender) = ql_router::connect(address, router).await?;
            ql_router::attach(&mut receiver, &mut sender, identity, router).await?;
            io::Result::Ok((receiver, sender))
        };
        let (mut receiver, mut sender) = tokio::time::timeout(CONNECT_TIMEOUT, connected)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the router did not answer"))??;

        let (transport, Link { outgoing, incoming }) = Transport::new(ql_invite_code::Transport::Router);
        let sending = async move {
            while let Ok(record) = outgoing.recv().await {
                if let Err(error) = ql_router::send(&mut sender, &record).await {
                    return log::error!("router send failed: {error}");
                }
            }
        };
        let receiving = async move {
            loop {
                match ql_router::receive(&mut receiver).await {
                    Ok(Some(record)) => {
                        if incoming.send(record).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => return log::warn!("the router closed the connection"),
                    Err(error) => return log::error!("router receive failed: {error}"),
                }
            }
        };
        // Either side stopping drops the other, so the connection closes along with the session's
        // end of the link and the other way round.
        tokio::spawn(futures_lite::future::or(sending, receiving));
        Ok(transport)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn production_router_is_valid() {
        super::production_router().validate(&ql_wire::SoftwareCrypto).unwrap();
    }
}
