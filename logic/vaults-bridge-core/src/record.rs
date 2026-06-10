// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Credential record schema. Persistence lives in the keystore crate.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct CredentialRecord {
    #[zeroize(skip)]
    pub id: Uuid,
    /// Strict origin: scheme + host + port. Match key for autofill.
    #[zeroize(skip)]
    pub origin: String,
    #[zeroize(skip)]
    pub username: String,
    /// Plaintext password, sealed at rest by the keystore.
    /// Zeroed on drop in memory.
    pub password: String,
    /// Optional human label. Falls back to origin host when empty.
    #[zeroize(skip)]
    #[serde(default)]
    pub label: String,
    /// Card colour index (matches `card-color-picker-model` order in
    /// `@ui/utils.slint`). Default 0 (teal).
    #[zeroize(skip)]
    #[serde(default = "default_color")]
    pub color: i32,
    /// Soft-deleted. Hidden from main list and skipped by `release_credential`
    /// lookups; can be restored or permanently deleted from the archive view.
    #[zeroize(skip)]
    #[serde(default)]
    pub archived: bool,
    #[zeroize(skip)]
    pub notes: Option<String>,
    #[zeroize(skip)]
    pub created_at: u64,
    #[zeroize(skip)]
    pub last_used_at: u64,
}

fn default_color() -> i32 {
    0
}

impl CredentialRecord {
    pub fn new(origin: String, username: String, password: String) -> Self {
        let now = now_secs();
        Self {
            id: Uuid::new_v4(),
            origin,
            username,
            password,
            label: String::new(),
            color: default_color(),
            archived: false,
            notes: None,
            created_at: now,
            last_used_at: now,
        }
    }

    /// Display label: explicit label if set, else the origin's host.
    pub fn display_label(&self) -> &str {
        if !self.label.is_empty() {
            &self.label
        } else {
            &self.origin
        }
    }
}

// Manual Debug elides password / username / notes so they cannot be
// accidentally leaked through tracing, log::debug, dbg!, panic messages,
// or future `#[derive(Debug)]` propagation.
impl std::fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("origin", &self.origin)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("label", &self.label)
            .field("color", &self.color)
            .field("archived", &self.archived)
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("created_at", &self.created_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip_through_serde() {
        let mut r = CredentialRecord::new(
            "https://github.com".into(),
            "qna@foundation.xyz".into(),
            "hunter2".into(),
        );
        r.label = "GitHub".into();
        r.color = 5;
        r.archived = false;
        let s = serde_json::to_string(&r).unwrap();
        let back: CredentialRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(r.origin, back.origin);
        assert_eq!(r.username, back.username);
        assert_eq!(r.password, back.password);
        assert_eq!(r.label, back.label);
        assert_eq!(r.color, back.color);
        assert_eq!(r.archived, back.archived);
    }

    #[test]
    fn display_label_falls_back_to_origin() {
        let r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        assert_eq!(r.display_label(), "https://x");
        let mut r2 = r.clone();
        r2.label = "Custom".into();
        assert_eq!(r2.display_label(), "Custom");
    }
}
