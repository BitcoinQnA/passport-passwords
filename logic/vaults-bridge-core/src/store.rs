// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Trait the engine consumes to look up + write credentials.

#[derive(Clone)]
pub struct CredentialMatch {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for CredentialMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialMatch")
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct CredentialSummary {
    pub username: String,
    pub label: String,
    pub last_used_at: u64,
}

impl std::fmt::Debug for CredentialSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSummary")
            .field("username", &"<redacted>")
            .field("label", &self.label)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

/// Result of a probe for an existing credential by `(origin, username)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExistingCredential {
    None,
    Live,
    Archived,
}

pub trait CredentialStore: Send + Sync {
    type Snapshot: Send;

    fn list_origins(&self) -> Vec<String>;
    fn list_credentials_for_origin(&self, origin: &str) -> Vec<CredentialSummary>;
    fn find_by_origin(&self, origin: &str) -> Vec<CredentialMatch>;
    fn snapshot(&self) -> Self::Snapshot;
    fn restore_snapshot(&mut self, snapshot: Self::Snapshot);

    /// Probe whether a record exists for (origin, username) and what state
    /// it's in. Used by `store_credential` to decide between save / update
    /// / restore-and-update before asking the user.
    fn probe(&self, origin: &str, username: &str) -> ExistingCredential;

    /// Insert or update a credential. If an existing record (live or
    /// archived) matches `(origin, username)`, replace its password and
    /// label and clear `archived`. Otherwise create a new record.
    /// The engine persists and rolls back around this mutation.
    fn upsert(
        &mut self,
        origin: String,
        username: String,
        password: String,
        label: Option<String>,
    ) -> Result<(), StoreError>;
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum StoreError {
    #[error("storage backend error: {0}")]
    Backend(String),
}
