// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! JSON request/response types. Serde is the source of truth.
//!
//! Envelope:
//!   Request  = { "id": "...", "method": "<name>", "params": { ... } }
//!   Response = { "id": "...", "result": { ... } }
//!            | { "id": "...", "error": { "code": int, "message": str } }
//!
//! v1 method surface:
//!   ping
//!   establish_session    ECDH X25519 handshake
//!   list_origins         origins with at least one live credential
//!   release_credential   release stored password to host (with approval)
//!   store_credential     save / update / restore-and-update a credential (with approval)
//!   generate_password    device generates strong random password and stores
//!   cancel               cancel an in-flight approval

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    #[serde(flatten)]
    pub method: Method,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Method {
    Ping,
    EstablishSession(EstablishSessionParams),
    ListOrigins,
    ReleaseCredential(ReleaseCredentialParams),
    StoreCredential(StoreCredentialParams),
    GeneratePassword(GeneratePasswordParams),
    Cancel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EstablishSessionParams {
    /// Host's ephemeral X25519 public key, hex-encoded.
    pub host_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EstablishSessionResult {
    pub device_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListOriginsResult {
    pub origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCredentialParams {
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub username_hint: Option<String>,
    pub request_nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseCredentialResult {
    pub username: String,
    /// Password, sealed under the session AEAD key.
    /// Layout: `iv (12B) || ciphertext_with_tag`, hex-encoded.
    pub password_sealed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoreCredentialParams {
    pub origin: String,
    pub username: String,
    /// Optional human label; defaults to the origin host on the device side.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub label: Option<String>,
    /// Password to store, sealed under the session AEAD key.
    /// Same layout as `ReleaseCredentialResult.password_sealed`.
    pub password_sealed: String,
    pub request_nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreCredentialResult {
    /// What the device actually did. Useful for the host to surface
    /// "Saved" vs "Updated" vs "Restored from archive" feedback.
    pub action: StoreAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StoreAction {
    Saved,
    Updated,
    RestoredAndUpdated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GeneratePasswordParams {
    pub origin: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub label: Option<String>,
    /// Hint: requested length. Device clamps to its own [min..max] policy
    /// (currently 16..=64). If absent, defaults to 24.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub length: Option<u32>,
    /// Hint: which character classes to include. If absent, all classes
    /// are enabled (letters + digits + symbols).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub charset: Option<CharsetHint>,
    pub request_nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CharsetHint {
    #[serde(default = "default_true")]
    pub letters: bool,
    #[serde(default = "default_true")]
    pub digits: bool,
    #[serde(default = "default_true")]
    pub symbols: bool,
}

impl Default for CharsetHint {
    fn default() -> Self {
        Self {
            letters: true,
            digits: true,
            symbols: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratePasswordResult {
    /// Generated password, sealed under the session AEAD key.
    /// Same layout as the other sealed payloads.
    pub password_sealed: String,
    /// What the device did with the password (always Saved or
    /// RestoredAndUpdated for atomic generate+store).
    pub action: StoreAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Response {
    Ok { id: String, result: ResponseBody },
    Err { id: String, error: ErrorPayload },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ResponseBody {
    Pong { pong: bool },
    EstablishSession(EstablishSessionResult),
    ListOrigins(ListOriginsResult),
    ReleaseCredential(ReleaseCredentialResult),
    StoreCredential(StoreCredentialResult),
    GeneratePassword(GeneratePasswordResult),
    Empty {},
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorPayload {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    InvalidRequest = 1,
    UnknownMethod = 2,
    UnknownOrigin = 3,
    UserRejected = 4,
    Timeout = 5,
    NotUnlocked = 6,
    SessionExpired = 7,
    NonceReused = 8,
    /// Password generation policy violated (e.g., requested length out of
    /// range, or all charset classes disabled).
    BadPolicy = 9,
    Internal = 99,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_ping_request() {
        let req = Request {
            id: "1".into(),
            method: Method::Ping,
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn round_trip_release_credential() {
        let req = Request {
            id: "abc".into(),
            method: Method::ReleaseCredential(ReleaseCredentialParams {
                origin: "https://github.com".into(),
                username_hint: Some("qna@foundation.xyz".into()),
                request_nonce: 42,
            }),
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn round_trip_store_credential() {
        let req = Request {
            id: "s1".into(),
            method: Method::StoreCredential(StoreCredentialParams {
                origin: "https://example.com".into(),
                username: "alice".into(),
                label: Some("Test".into()),
                password_sealed: "deadbeef".into(),
                request_nonce: 7,
            }),
        };
        let back: Request = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn round_trip_generate_password() {
        let req = Request {
            id: "g1".into(),
            method: Method::GeneratePassword(GeneratePasswordParams {
                origin: "https://example.com".into(),
                username: "alice".into(),
                label: None,
                length: Some(32),
                charset: Some(CharsetHint {
                    letters: true,
                    digits: true,
                    symbols: false,
                }),
                request_nonce: 9,
            }),
        };
        let back: Request = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(req, back);
    }
}