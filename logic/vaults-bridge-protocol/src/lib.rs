// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Vaults Bridge wire protocol.
//!
//! Two layers live in this crate:
//!   - [`message`] JSON request/response types exchanged between the browser extension and the device.
//!   - [`frame`]   64-byte interrupt-endpoint chunking and reassembly for the JSON blobs.
//!
//! Both layers are pure Rust with no platform dependencies. Wire shape
//! mirrors `nostr-signer/protocol` (same framing, same envelope) so a
//! reader of one understands the other. Method surface is Vaults-specific.
//!
//! See `protocol/SPEC.md` for the normative spec.

pub mod frame;
pub mod message;

pub use frame::{frame, FrameError, LineSplitter, MAX_LINE_BYTES};
pub use message::{
    CharsetHint, CredentialSummary, ErrorCode, ErrorPayload, EstablishSessionParams, EstablishSessionResult,
    GeneratePasswordParams, GeneratePasswordResult, ListCredentialsParams, ListCredentialsResult,
    ListOriginsResult, Method, ReleaseCredentialParams, ReleaseCredentialResult, Request, Response,
    ResponseBody, StoreAction, StoreCredentialParams, StoreCredentialResult,
};
