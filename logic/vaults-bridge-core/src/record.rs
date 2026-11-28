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
    /// Card colour index (matches `CardColorPicker` order in the UI).
    /// New standalone records begin at teal; the keystore advances the
    /// colour for each record it inserts automatically.
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
    /// Surfaces this password has been released to. Only the device writes
    /// this; it is not accepted from the host. Missing on older records.
    #[zeroize(skip)]
    #[serde(default)]
    pub release_history: Vec<ReleaseEvent>,
}

/// Longest release history kept on one record. Oldest entries are dropped.
pub const MAX_RELEASE_HISTORY: usize = 50;

/// One successful release, as the device recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEvent {
    /// Client/app name the requester reported, after sanitizing.
    pub surface: String,
    /// Peer name as the Prime knew it at release time.
    pub peer_name: String,
    /// Peer QID as authenticated by Quantum Link. Empty if there was no QL peer.
    pub peer_qid: String,
    /// Unix time in seconds.
    pub released_at: u64,
}

impl ReleaseEvent {
    /// Short line for the password's detail page, e.g.
    /// `Passwords extension on Grok Bot, 27 Nov 18:15`.
    pub fn display_line(&self) -> String {
        format!(
            "{} on {}, {}",
            self.surface,
            self.peer_name,
            format_short_time(self.released_at)
        )
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `27 Nov 18:15`, or `27 Nov 2025 18:15` when the year is not the current UTC year.
pub fn format_short_time(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let (y, m, d) = date_from_unix_days(days);
    let mon = MONTHS[(m - 1) as usize];
    let now_days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86400)
        .unwrap_or(days);
    let (now_y, _, _) = date_from_unix_days(now_days);
    if y == now_y {
        format!("{d} {mon} {hour:02}:{min:02}")
    } else {
        format!("{d} {mon} {y} {hour:02}:{min:02}")
    }
}

/// Civil date from days since Unix epoch, Howard Hinnant's algorithm.
fn date_from_unix_days(days: u64) -> (i32, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

fn default_color() -> i32 {
    5
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
            release_history: Vec::new(),
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
            .field("release_history", &self.release_history)
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

    #[test]
    fn new_records_default_to_teal() {
        let r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        assert_eq!(r.color, 5);
    }

    #[test]
    fn missing_release_history_deserializes_as_empty() {
        let mut r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        r.label = "X".into();
        let mut v = serde_json::to_value(&r).unwrap();
        v.as_object_mut().unwrap().remove("release_history");
        let back: CredentialRecord = serde_json::from_value(v).unwrap();
        assert!(back.release_history.is_empty());
        assert_eq!(back.password, "p");
    }

    #[test]
    fn format_short_time_omits_current_year() {
        // 27 Nov 2026 18:15:00 UTC
        let secs = 1_795_803_300;
        let line = format_short_time(secs);
        assert_eq!(line, "27 Nov 18:15", "got {line}");
    }

    #[test]
    fn format_short_time_includes_other_years() {
        // 1 Jan 2020 00:00:00 UTC
        let line = format_short_time(1_577_836_800);
        assert_eq!(line, "1 Jan 2020 00:00", "got {line}");
    }

    #[test]
    fn display_line_matches_the_detail_page_shape() {
        let ev = ReleaseEvent {
            surface: "Passwords extension".into(),
            peer_name: "Grok Bot".into(),
            peer_qid: "c3a640a62bc3c1e56ea1542fe7b0cff4".into(),
            released_at: 1_795_803_300,
        };
        assert_eq!(
            ev.display_line(),
            "Passwords extension on Grok Bot, 27 Nov 18:15"
        );
    }
}
