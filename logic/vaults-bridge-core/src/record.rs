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

/// Longest surface or peer name kept in a history entry, in bytes.
pub const MAX_HISTORY_NAME_BYTES: usize = 128;

/// Longest peer QID kept in a history entry, in bytes.
pub const MAX_HISTORY_QID_BYTES: usize = 64;

/// "Released to" opens showing only the newest release.
pub const RELEASE_ROWS_FIRST: usize = 1;

/// Each press of the expand arrow reveals this many more.
pub const RELEASE_ROWS_PER_PRESS: usize = 5;

/// How many of `total` history rows are visible after `presses` presses of the
/// expand arrow. Never more than `total`.
pub fn release_rows_shown(total: usize, presses: usize) -> usize {
    total.min(RELEASE_ROWS_FIRST.saturating_add(presses.saturating_mul(RELEASE_ROWS_PER_PRESS)))
}

/// Whether the expand arrow is still needed: some rows remain hidden.
pub fn release_rows_have_more(total: usize, presses: usize) -> bool {
    release_rows_shown(total, presses) < total
}

/// True when the details page should go back to showing only the newest
/// release. Used when a new release lands while that page is already open.
/// A redraw of the same history (for example after a colour edit) is not
/// a reason to collapse an expanded list.
pub fn release_list_should_recollapse(previous: &[ReleaseEvent], next: &[ReleaseEvent]) -> bool {
    previous.len() != next.len() || previous.last() != next.last()
}

/// Clocks earlier than this (1 Jan 2025) have not been set yet, same floor as
/// the status bar. A history entry stamped before it has no usable date.
pub const MIN_PLAUSIBLE_UNIX_SECS: u64 = 1_735_693_200;

/// Last second of year 9999. Later stamps cannot be shown as a date.
const MAX_DISPLAY_UNIX_SECS: u64 = 253_402_300_799;

/// One successful release, as the device recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEvent {
    /// Client/app name the requester reported, after sanitizing. This is the
    /// requester's own claim, not something the device verified.
    pub surface: String,
    /// Peer name as the Prime knew it at release time. A later rename of the
    /// peer does not rewrite old entries.
    pub peer_name: String,
    /// Peer QID as authenticated by Quantum Link. Empty if there was no QL peer.
    pub peer_qid: String,
    /// Unix time in seconds.
    pub released_at: u64,
}

/// A calendar date in the viewer's local time zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDate {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl LocalDate {
    /// `28 Nov`
    pub fn day_month(&self) -> String {
        format!("{} {}", self.day, MONTHS[(self.month - 1) as usize])
    }

    /// `2026`
    pub fn year_line(&self) -> String {
        self.year.to_string()
    }
}

/// What one row of the detail page's "Released to" table shows. Each cell is
/// two lines: date over year on the left, surface over peer on the right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseRowText {
    pub date: String,
    pub year: String,
    pub surface: String,
    pub peer: String,
}

impl ReleaseEvent {
    /// Local calendar date of this release, or `None` when the stamp is from a
    /// clock that was never set (or is out of range).
    pub fn local_date(&self, utc_offset_secs: i32) -> Option<LocalDate> {
        if self.released_at < MIN_PLAUSIBLE_UNIX_SECS || self.released_at > MAX_DISPLAY_UNIX_SECS {
            return None;
        }
        Some(local_date(self.released_at, utc_offset_secs))
    }

    /// Text for the detail page row. `utc_offset_secs` is the offset in force
    /// at `released_at` in the Prime's time zone (so daylight saving is the
    /// caller's business, not guessed here).
    pub fn row_text(&self, utc_offset_secs: i32) -> ReleaseRowText {
        let (date, year) = match self.local_date(utc_offset_secs) {
            Some(d) => (d.day_month(), d.year_line()),
            None => ("Unknown".to_string(), String::new()),
        };
        ReleaseRowText {
            date,
            year,
            surface: self.surface.clone(),
            peer: self.peer_name.clone(),
        }
    }

    /// Re-apply the length and character limits to an entry that came from
    /// somewhere other than this device's own recorder (a restored backup).
    fn clamp(&mut self) {
        self.surface = sanitize_display_text(&self.surface, MAX_HISTORY_NAME_BYTES);
        self.peer_name = sanitize_display_text(&self.peer_name, MAX_HISTORY_NAME_BYTES);
        self.peer_qid = sanitize_display_text(&self.peer_qid, MAX_HISTORY_QID_BYTES);
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Calendar date `utc_offset_secs` east of UTC at `unix_secs`.
pub fn local_date(unix_secs: u64, utc_offset_secs: i32) -> LocalDate {
    let local = unix_secs.min(i64::MAX as u64 / 2) as i64 + i64::from(utc_offset_secs);
    let (year, month, day) = civil_from_days(local.div_euclid(86_400));
    LocalDate { year, month, day }
}

/// Civil date from days since the Unix epoch (Howard Hinnant's algorithm),
/// valid for negative days too.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// Strip control and invisible formatting characters (including the bidi
/// overrides that can reorder surrounding text), trim, and cut to `max` bytes
/// on a character boundary. Used on text the requester or a backup supplies.
pub fn sanitize_display_text(raw: &str, max: usize) -> String {
    let cleaned: String = raw
        .chars()
        // Tabs and line breaks become a space so "Grok\nBot" stays two words.
        .map(|c| if c.is_control() && c.is_whitespace() { ' ' } else { c })
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    *c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{2028}'..='\u{2029}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'..='\u{2064}'
                        | '\u{2066}'..='\u{206F}'
                        | '\u{FEFF}'
                )
        })
        .collect();
    let mut out = String::new();
    for ch in cleaned.trim().chars() {
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(ch);
    }
    out.trim_end().to_string()
}

fn default_color() -> i32 {
    5
}

impl CredentialRecord {
    /// Append a release to the history, keeping only the newest
    /// `MAX_RELEASE_HISTORY`, and note the use.
    pub fn push_release(&mut self, event: ReleaseEvent) {
        self.last_used_at = event.released_at;
        self.release_history.push(event);
        self.clamp_release_history();
    }

    /// Enforce the history cap (newest kept) and the per-entry text limits.
    /// Run on records that did not come from this device's own recorder.
    pub fn clamp_release_history(&mut self) {
        let extra = self.release_history.len().saturating_sub(MAX_RELEASE_HISTORY);
        if extra > 0 {
            self.release_history.drain(0..extra);
        }
    }

    /// `clamp_release_history` plus re-sanitizing every entry's text.
    pub fn sanitize_release_history(&mut self) {
        self.clamp_release_history();
        for event in &mut self.release_history {
            event.clamp();
        }
    }

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

    fn event(released_at: u64) -> ReleaseEvent {
        ReleaseEvent {
            surface: "Chrome extension".into(),
            peer_name: "Grok Bot".into(),
            peer_qid: "c3a640a62bc3c1e56ea1542fe7b0cff4".into(),
            released_at,
        }
    }

    const EST: i32 = -5 * 3600;
    const EDT: i32 = -4 * 3600;

    // ---- old vaults and stored shape -------------------------------------

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
    fn history_written_by_the_first_release_build_still_loads() {
        // Exactly the entry shape the earlier build stored for the Foogle demo
        // password: surface, peer_name, peer_qid, released_at, nothing else.
        let json = r#"{"surface":"Passwords extension","peer_name":"Grok Bot",
            "peer_qid":"c3a640a62bc3c1e56ea1542fe7b0cff4","released_at":1795828320}"#;
        let ev: ReleaseEvent = serde_json::from_str(json).unwrap();
        assert_eq!(ev.surface, "Passwords extension");
        assert_eq!(ev.released_at, 1_795_828_320);
        let row = ev.row_text(EST);
        assert_eq!(row.date, "27 Nov");
        assert_eq!(row.year, "2026");
        assert_eq!(row.surface, "Passwords extension");
        assert_eq!(row.peer, "Grok Bot");
    }

    #[test]
    fn history_round_trips_through_serde() {
        let mut r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        r.push_release(event(1_795_828_320));
        let back: CredentialRecord = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back.release_history, r.release_history);
        assert_eq!(back.last_used_at, 1_795_828_320);
    }

    // ---- local date and year ---------------------------------------------

    #[test]
    fn row_text_is_date_over_year_and_surface_over_peer() {
        // 28 Nov 2026 01:12 UTC is still the evening of 27 Nov on the US east coast.
        let ev = event(1_795_828_320);
        assert_eq!(
            ev.row_text(EST),
            ReleaseRowText {
                date: "27 Nov".into(),
                year: "2026".into(),
                surface: "Chrome extension".into(),
                peer: "Grok Bot".into(),
            }
        );
        // The same instant in UTC is the 28th, which is what the earlier build showed.
        let utc = ev.row_text(0);
        assert_eq!((utc.date.as_str(), utc.year.as_str()), ("28 Nov", "2026"));
    }

    #[test]
    fn date_rolls_over_midnight_in_both_directions() {
        // 01:12 UTC, 5 h behind: previous day. 23:00 UTC, 5 h ahead: next day.
        assert_eq!(local_date(1_795_828_320, EST).day, 27);
        let late = 1_795_828_320 - 2 * 3600 - 12 * 60 + 22 * 3600; // 28 Nov 21:00 UTC
        assert_eq!(local_date(late, 5 * 3600).day, 29);
        assert_eq!(local_date(late, 0).day, 28);
    }

    #[test]
    fn year_follows_the_local_clock_not_utc() {
        // 1 Jan 2027 00:30 UTC is still New Year's Eve 2026 in New York.
        let d = event(1_798_763_400).local_date(EST).unwrap();
        assert_eq!((d.day, d.month, d.year), (31, 12, 2026));
        // 31 Dec 2026 23:30 UTC is already 1 Jan 2027 in Tokyo (+9).
        let d = event(1_798_759_800).local_date(9 * 3600).unwrap();
        assert_eq!((d.day, d.month, d.year), (1, 1, 2027));
        assert_eq!(d.year_line(), "2027");
        assert_eq!(d.day_month(), "1 Jan");
    }

    #[test]
    fn leap_day_and_century_non_leap_year() {
        let d = event(1_835_438_400).local_date(EST).unwrap(); // 29 Feb 2028 12:00 UTC
        assert_eq!((d.day, d.month, d.year), (29, 2, 2028));
        // 1 Mar 2028 02:00 UTC is still 29 Feb in New York.
        let d = event(1_835_488_800).local_date(EST).unwrap();
        assert_eq!((d.day, d.month, d.year), (29, 2, 2028));
        // 2100 is not a leap year: 28 Feb 23:00 UTC + 2 h is 1 Mar.
        let d = event(4_107_538_800).local_date(2 * 3600).unwrap();
        assert_eq!((d.day, d.month, d.year), (1, 3, 2100));
    }

    #[test]
    fn daylight_saving_uses_the_offset_the_caller_found_for_that_instant() {
        // New York 8 Mar 2026: 06:59 UTC is 01:59 EST, 07:01 UTC is 03:01 EDT.
        assert_eq!(event(1_772_953_140).local_date(EST).unwrap().day, 8);
        assert_eq!(event(1_772_953_260).local_date(EDT).unwrap().day, 8);
        // Across the November change, late evening still lands on the right day.
        let dec = event(1_795_828_320);
        assert_eq!(dec.local_date(EST).unwrap().day, 27);
        assert_eq!(dec.local_date(EDT).unwrap().day, 27);
    }

    #[test]
    fn every_month_has_its_short_name() {
        let names: Vec<String> = (1..=12)
            .map(|m| LocalDate { year: 2026, month: m, day: 5 }.day_month())
            .collect();
        assert_eq!(
            names,
            ["5 Jan", "5 Feb", "5 Mar", "5 Apr", "5 May", "5 Jun", "5 Jul", "5 Aug", "5 Sep", "5 Oct", "5 Nov", "5 Dec"]
        );
    }

    #[test]
    fn civil_dates_match_reference_values_at_the_edges() {
        let at = |secs: i64| local_date(secs as u64, 0);
        assert_eq!(at(0), LocalDate { year: 1970, month: 1, day: 1 });
        assert_eq!(at(86_399), LocalDate { year: 1970, month: 1, day: 1 });
        assert_eq!(at(86_400), LocalDate { year: 1970, month: 1, day: 2 });
        assert_eq!(at(951_782_400), LocalDate { year: 2000, month: 2, day: 29 });
        assert_eq!(at(253_402_300_799), LocalDate { year: 9999, month: 12, day: 31 });
        // A stamp just after 1970 shown west of UTC lands before the epoch day.
        assert_eq!(local_date(3600, EST), LocalDate { year: 1969, month: 12, day: 31 });
    }

    #[test]
    fn stamps_from_an_unset_clock_have_no_date() {
        for secs in [0, 1, MIN_PLAUSIBLE_UNIX_SECS - 1, MAX_DISPLAY_UNIX_SECS + 1, u64::MAX] {
            let row = event(secs).row_text(EST);
            assert_eq!(row.date, "Unknown", "secs={secs}");
            assert_eq!(row.year, "", "secs={secs}");
            assert_eq!(row.surface, "Chrome extension");
        }
        assert!(event(MIN_PLAUSIBLE_UNIX_SECS).local_date(0).is_some());
        assert!(event(MAX_DISPLAY_UNIX_SECS).local_date(0).is_some());
    }

    #[test]
    fn extreme_offsets_do_not_panic() {
        let _ = local_date(MIN_PLAUSIBLE_UNIX_SECS, i32::MAX);
        let _ = local_date(MIN_PLAUSIBLE_UNIX_SECS, i32::MIN);
        let _ = local_date(u64::MAX, i32::MAX);
    }

    // ---- history list ----------------------------------------------------

    #[test]
    fn push_release_keeps_the_newest_fifty_in_order() {
        let mut r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        for i in 0..(MAX_RELEASE_HISTORY as u64 + 7) {
            r.push_release(event(MIN_PLAUSIBLE_UNIX_SECS + i));
        }
        assert_eq!(r.release_history.len(), MAX_RELEASE_HISTORY);
        assert_eq!(r.release_history[0].released_at, MIN_PLAUSIBLE_UNIX_SECS + 7);
        assert_eq!(
            r.release_history.last().unwrap().released_at,
            MIN_PLAUSIBLE_UNIX_SECS + MAX_RELEASE_HISTORY as u64 + 6
        );
        assert_eq!(r.last_used_at, MIN_PLAUSIBLE_UNIX_SECS + MAX_RELEASE_HISTORY as u64 + 6);
    }

    #[test]
    fn exactly_fifty_is_kept_and_the_fifty_first_drops_the_oldest() {
        let mut r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        for i in 0..MAX_RELEASE_HISTORY as u64 {
            r.push_release(event(MIN_PLAUSIBLE_UNIX_SECS + i));
        }
        assert_eq!(r.release_history.len(), 50);
        assert_eq!(r.release_history[0].released_at, MIN_PLAUSIBLE_UNIX_SECS);
        r.push_release(event(MIN_PLAUSIBLE_UNIX_SECS + 50));
        assert_eq!(r.release_history.len(), 50);
        assert_eq!(r.release_history[0].released_at, MIN_PLAUSIBLE_UNIX_SECS + 1);
    }

    #[test]
    fn restored_history_is_capped_and_cleaned() {
        let mut r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        for i in 0..200u64 {
            r.release_history.push(ReleaseEvent {
                surface: format!("\u{202E}evil{i}\u{0007}"),
                peer_name: "n".repeat(10_000),
                peer_qid: "q".repeat(10_000),
                released_at: MIN_PLAUSIBLE_UNIX_SECS + i,
            });
        }
        r.sanitize_release_history();
        assert_eq!(r.release_history.len(), MAX_RELEASE_HISTORY);
        assert_eq!(r.release_history[0].released_at, MIN_PLAUSIBLE_UNIX_SECS + 150);
        for ev in &r.release_history {
            assert!(!ev.surface.contains('\u{202E}') && !ev.surface.contains('\u{0007}'));
            assert_eq!(ev.peer_name.len(), MAX_HISTORY_NAME_BYTES);
            assert_eq!(ev.peer_qid.len(), MAX_HISTORY_QID_BYTES);
        }
    }

    // ---- text sanitizing -------------------------------------------------

    #[test]
    fn sanitizer_removes_controls_and_bidi_tricks_and_trims() {
        assert_eq!(sanitize_display_text("  Chrome\textension\n ", 128), "Chrome extension");
        assert_eq!(sanitize_display_text("a\u{2028}b\u{2029}c\u{0007}d", 128), "abcd");
        assert_eq!(sanitize_display_text("a\u{202E}b\u{200B}c\u{2066}d\u{FEFF}", 128), "abcd");
        assert_eq!(sanitize_display_text("   ", 128), "");
        assert_eq!(sanitize_display_text("", 128), "");
    }

    #[test]
    fn sanitizer_truncates_on_a_character_boundary() {
        // 'é' is two bytes: 5 of them are 10 bytes, a 9-byte cap keeps 4.
        let out = sanitize_display_text("ééééé", 9);
        assert_eq!(out, "éééé");
        assert!(out.len() <= 9);
        assert_eq!(sanitize_display_text("日本語日本語", 7), "日本");
        assert_eq!(sanitize_display_text("abc", 0), "");
    }

    #[test]
    fn sanitizer_keeps_ordinary_non_ascii_names() {
        assert_eq!(sanitize_display_text("Grok Bot 🤖 — café", 128), "Grok Bot 🤖 — café");
    }

    #[test]
    fn no_rows_means_nothing_shown_and_no_arrow() {
        for presses in [0, 1, 99] {
            assert_eq!(release_rows_shown(0, presses), 0);
            assert!(!release_rows_have_more(0, presses));
        }
    }

    #[test]
    fn one_row_is_shown_with_no_arrow() {
        assert_eq!(release_rows_shown(1, 0), 1);
        assert!(!release_rows_have_more(1, 0));
        assert_eq!(release_rows_shown(1, 3), 1);
    }

    #[test]
    fn two_rows_start_with_one_and_one_press_shows_both() {
        assert_eq!(release_rows_shown(2, 0), 1);
        assert!(release_rows_have_more(2, 0));
        assert_eq!(release_rows_shown(2, 1), 2);
        assert!(!release_rows_have_more(2, 1));
    }

    #[test]
    fn batch_boundary_six_rows_fit_exactly_in_the_first_press() {
        // 1 + 5 = 6: the arrow goes away on the press that shows the last row.
        assert_eq!(release_rows_shown(6, 0), 1);
        assert!(release_rows_have_more(6, 0));
        assert_eq!(release_rows_shown(6, 1), 6);
        assert!(!release_rows_have_more(6, 1));
        // 7 rows need a second press for the last one.
        assert_eq!(release_rows_shown(7, 1), 6);
        assert!(release_rows_have_more(7, 1));
        assert_eq!(release_rows_shown(7, 2), 7);
        assert!(!release_rows_have_more(7, 2));
    }

    #[test]
    fn a_full_fifty_entry_history_opens_in_steps_of_five_never_all_at_once() {
        let total = MAX_RELEASE_HISTORY;
        let mut seen = vec![release_rows_shown(total, 0)];
        let mut presses = 0;
        while release_rows_have_more(total, presses) {
            presses += 1;
            seen.push(release_rows_shown(total, presses));
        }
        assert_eq!(seen, [1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 50]);
        assert_eq!(presses, 10);
        // Each press adds at most one batch.
        assert!(seen.windows(2).all(|w| w[1] - w[0] <= RELEASE_ROWS_PER_PRESS));
        // And the arrow stays gone however many more presses arrive.
        assert_eq!(release_rows_shown(total, presses + 7), total);
        assert!(!release_rows_have_more(total, presses + 7));
    }

    #[test]
    fn absurd_press_counts_do_not_overflow() {
        assert_eq!(release_rows_shown(50, usize::MAX), 50);
        assert!(!release_rows_have_more(50, usize::MAX));
    }

    #[test]
    fn a_new_release_collapses_an_open_list_and_a_redraw_does_not() {
        fn ev(at: u64, peer: &str) -> ReleaseEvent {
            ReleaseEvent {
                surface: "Chrome extension".into(),
                peer_name: peer.into(),
                peer_qid: "abc".into(),
                released_at: at,
            }
        }
        let one = vec![ev(1_000, "Grok Bot")];
        let two = vec![ev(1_000, "Grok Bot"), ev(2_000, "Grok Bot")];
        assert!(!release_list_should_recollapse(&one, &one));
        assert!(!release_list_should_recollapse(&two, &two));
        assert!(release_list_should_recollapse(&[], &one));
        assert!(release_list_should_recollapse(&one, &two));
        // Newest is last in the stored vec; a cap drop keeps the length
        // but still changes the newest entry.
        let mut capped: Vec<_> = (0..50).map(|i| ev(1_000 + i, "Grok Bot")).collect();
        let same = capped.clone();
        assert!(!release_list_should_recollapse(&capped, &same));
        capped.remove(0);
        capped.push(ev(2_000, "Grok Bot"));
        assert!(release_list_should_recollapse(&same, &capped));
        // A later release that keeps the count but changes the newest row.
        let renamed = vec![ev(1_000, "Grok Bot"), ev(2_000, "Forge box")];
        assert!(release_list_should_recollapse(&two, &renamed));
    }
}
