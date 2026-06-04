// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Platform-agnostic core for Vaults Bridge.
//!
//! Modules:
//!   - [`origin`]   strict-origin parsing and equality
//!   - [`session`]  ECDH X25519 + AES-256-GCM sealing of payloads
//!   - [`record`]   credential record schema (no I/O)
//!   - [`store`]    `CredentialStore` trait the engine consumes
//!   - [`approval`] async approver trait + auto sims
//!   - [`engine`]   protocol dispatcher (ping, establish_session,
//!                  list_origins, release/store/generate, cancel)

pub mod approval;
pub mod engine;
pub mod origin;
pub mod record;
pub mod session;
pub mod store;

pub use approval::{ApprovalAction, ApprovalDecision, ApprovalRequest, Approver, ArcApprover};
pub use engine::{Engine, EngineConfig, DEFAULT_IDLE_MS, SESSION_INFO};
pub use origin::{origin_match_key, registrable_domain, Origin, OriginError};
pub use record::CredentialRecord;
pub use session::{Session, SessionError, SessionState};
pub use store::{CredentialMatch, CredentialStore, ExistingCredential, StoreError};