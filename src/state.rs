// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! UI-side state: refresh helpers from keystore into Slint models.

use std::sync::{Arc, Mutex};

use slint_keyos_platform::slint::{ComponentHandle, ModelRc, VecModel};
use vaults_bridge_core::{release_list_should_recollapse, CredentialRecord, ReleaseEvent};
use vaults_bridge_keystore::Keystore;

use crate::{local_time, AppWindow, Callbacks, ReleaseRow, StoredCredential};

pub struct AppState {
    pub keystore: Arc<Mutex<Keystore>>,
    pub ui: slint_keyos_platform::slint::Weak<AppWindow>,
    pub search: String,
    /// History last pushed to the open details page, so a later refresh can
    /// tell a new release from a redraw of the same list.
    details_history: Mutex<(String, Vec<ReleaseEvent>)>,
}

impl AppState {
    pub fn new(keystore: Arc<Mutex<Keystore>>, ui: slint_keyos_platform::slint::Weak<AppWindow>) -> Self {
        Self { keystore, ui, search: String::new(), details_history: Mutex::new((String::new(), Vec::new())) }
    }

    pub fn set_search(&mut self, q: String) {
        self.search = q.to_lowercase();
    }

    pub fn refresh_credentials(&self) {
        let Some(ui) = self.ui.upgrade() else { return };
        let ks = self.keystore.lock().unwrap();
        let live = ks.live_count() as i32;
        let archived = ks.archived_count() as i32;
        let q = self.search.as_str();
        let cb = ui.global::<Callbacks>();
        let archive_mode = cb.get_archive_mode();
        // Only emit rows that match the current view. Including ghosts of
        // the other side and hiding them in slint keeps them in the layout
        // and the parent's `spacing` applies to every ghost — visible
        // cards then drift apart by N * spacing.
        let rows: Vec<StoredCredential> = ks
            .records()
            .iter()
            .filter(|r| r.archived == archive_mode && matches_search(r, q))
            .map(record_to_view)
            .collect();
        cb.set_credentials(ModelRc::new(VecModel::from(rows)));
        cb.set_live_count(live);
        cb.set_archived_count(archived);
        cb.set_next_default_color(ks.next_automatic_color());
        self.refresh_open_details(&cb, ks.records());
    }

    /// Keep an already-open details page in step with the vault. The list
    /// model is rebuilt above, but the details page reads
    /// `editing-release-history`, which was a snapshot from when the page
    /// was opened.
    fn refresh_open_details(&self, cb: &Callbacks, records: &[CredentialRecord]) {
        let editing = cb.get_editing_uuid();
        if editing.is_empty() {
            *self.details_history.lock().unwrap() = (String::new(), Vec::new());
            return;
        }
        let Some(rec) = records.iter().find(|r| r.id.to_string() == editing.as_str()) else {
            return;
        };
        let next = rec.release_history.clone();
        let recollapse = {
            let mut slot = self.details_history.lock().unwrap();
            let known = slot.0 == editing.as_str();
            let should = known && release_list_should_recollapse(&slot.1, &next);
            *slot = (editing.to_string(), next);
            should
        };
        cb.set_editing_release_history(ModelRc::new(VecModel::from(history_rows(rec))));
        if recollapse {
            cb.set_editing_release_presses(0);
        }
    }
}

fn matches_search(r: &CredentialRecord, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    r.label.to_lowercase().contains(q)
        || r.username.to_lowercase().contains(q)
        || r.origin.to_lowercase().contains(q)
}

fn record_to_view(r: &CredentialRecord) -> StoredCredential {
    StoredCredential {
        uuid: r.id.to_string().into(),
        label: r.label.clone().into(),
        origin: r.origin.clone().into(),
        host: host_from_origin(&r.origin).into(),
        username: r.username.clone().into(),
        color: r.color,
        archived: r.archived,
        last_used: format_last_used(r.last_used_at).into(),
        release_history: ModelRc::new(VecModel::from(history_rows(r))),
    }
}

fn history_rows(r: &CredentialRecord) -> Vec<ReleaseRow> {
    r.release_history.iter().rev().map(release_row).collect()
}

/// One "Released to" row in the Prime's local time, using the zone offset that
/// applied on that day (so summer and winter entries both read correctly).
fn release_row(ev: &ReleaseEvent) -> ReleaseRow {
    let text = ev.row_text(local_time::utc_offset_seconds(ev.released_at));
    ReleaseRow {
        date: text.date.into(),
        year: text.year.into(),
        surface: text.surface.into(),
        peer: text.peer.into(),
    }
}

fn host_from_origin(origin: &str) -> String {
    let stripped =
        origin.strip_prefix("https://").or_else(|| origin.strip_prefix("http://")).unwrap_or(origin);
    stripped.to_string()
}

fn format_last_used(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let elapsed = now.saturating_sub(secs);
    if elapsed < 30 {
        "Just now".into()
    } else if elapsed < 60 {
        format!("{} seconds ago", elapsed)
    } else if elapsed < 3600 {
        let m = elapsed / 60;
        if m == 1 {
            "1 minute ago".into()
        } else {
            format!("{} minutes ago", m)
        }
    } else if elapsed < 86400 {
        let h = elapsed / 3600;
        if h == 1 {
            "1 hour ago".into()
        } else {
            format!("{} hours ago", h)
        }
    } else if elapsed < 604800 {
        let d = elapsed / 86400;
        if d == 1 {
            "Yesterday".into()
        } else {
            format!("{} days ago", d)
        }
    } else if elapsed < 2_592_000 {
        let w = elapsed / 604800;
        if w == 1 {
            "1 week ago".into()
        } else {
            format!("{} weeks ago", w)
        }
    } else {
        let mo = elapsed / 2_592_000;
        if mo == 1 {
            "1 month ago".into()
        } else {
            format!("{} months ago", mo)
        }
    }
}
