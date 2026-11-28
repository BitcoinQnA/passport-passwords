// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Carries one session's records to Passport, over USB ([`Transport::usb`]) or the router
/// ([`Transport::router`]).
pub struct Transport {
    pub(crate) outgoing: async_channel::Sender<Vec<u8>>,
    pub(crate) incoming: async_channel::Receiver<Vec<u8>>,
    pub(crate) invite_transport: ql_invite_code::Transport,
}

/// The link's end of a [`Transport`]: send the `outgoing` records over the link, push the ones it
/// receives into `incoming`, and drop both once the link is gone.
pub(crate) struct Link {
    pub(crate) outgoing: async_channel::Receiver<Vec<u8>>,
    pub(crate) incoming: async_channel::Sender<Vec<u8>>,
}

impl Transport {
    /// A transport over a link the caller runs, which invites name as `invite_transport`
    pub(crate) fn new(invite_transport: ql_invite_code::Transport) -> (Transport, Link) {
        let (outgoing, outgoing_link) = async_channel::unbounded();
        let (incoming_link, incoming) = async_channel::unbounded();
        let transport = Transport { outgoing, incoming, invite_transport };
        (transport, Link { outgoing: outgoing_link, incoming: incoming_link })
    }
}
