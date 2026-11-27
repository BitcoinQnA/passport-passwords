// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A transport over a byte stream that carries each record as a 4-byte big-endian length and the
//! record, such as the stdio of a USB relay reached over SSH. The relay sees only encrypted QL
//! records; the identity and the session stay with the caller.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{transport::Link, Transport};

/// Longest record either way; Passport's USB records are at most 8 KiB.
pub const MAX_FRAMED_RECORD: usize = 64 * 1024;

impl Transport {
    /// A transport over `reader` and `writer`, which reach Passport's QL USB interface through a
    /// relay. Invites name USB, as the records end up on Passport's USB interface.
    pub fn framed<R, W>(mut reader: R, mut writer: W) -> Transport
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (transport, Link { outgoing, incoming }) = Transport::new(ql_invite_code::Transport::Usb);
        let sending = async move {
            while let Ok(record) = outgoing.recv().await {
                let sent = async {
                    writer.write_all(&(record.len() as u32).to_be_bytes()).await?;
                    writer.write_all(&record).await?;
                    writer.flush().await
                };
                if let Err(error) = sent.await {
                    return log::error!("relay send failed: {error}");
                }
            }
        };
        let receiving = async move {
            loop {
                let mut length = [0; 4];
                if let Err(error) = reader.read_exact(&mut length).await {
                    return log::warn!("the relay closed: {error}");
                }
                let length = u32::from_be_bytes(length) as usize;
                if length > MAX_FRAMED_RECORD {
                    return log::error!("the relay sent a {length} byte record");
                }
                let mut record = vec![0; length];
                if let Err(error) = reader.read_exact(&mut record).await {
                    return log::warn!("the relay closed: {error}");
                }
                if incoming.send(record).await.is_err() {
                    return;
                }
            }
        };
        // Either side stopping drops the other, closing the relay along with the session.
        tokio::spawn(futures_lite::future::or(sending, receiving));
        transport
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::Transport;

    #[tokio::test]
    async fn carries_records_both_ways_unchanged() {
        let (session_end, relay_end) = tokio::io::duplex(1024);
        let (session_read, session_write) = tokio::io::split(session_end);
        let (mut relay_read, mut relay_write) = tokio::io::split(relay_end);
        let transport = Transport::framed(session_read, session_write);

        transport.outgoing.send(b"opaque record".to_vec()).await.unwrap();
        let mut length = [0; 4];
        relay_read.read_exact(&mut length).await.unwrap();
        let mut record = vec![0; u32::from_be_bytes(length) as usize];
        relay_read.read_exact(&mut record).await.unwrap();
        assert_eq!(record, b"opaque record");

        relay_write.write_all(&3u32.to_be_bytes()).await.unwrap();
        relay_write.write_all(b"abc").await.unwrap();
        assert_eq!(transport.incoming.recv().await.unwrap(), b"abc");

        // A relay claiming an oversized record ends the link rather than allocating it.
        relay_write.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert!(transport.incoming.recv().await.is_err());
    }
}
