// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! UI-side state: refresh helpers from keystore into Slint models.

use std::sync::{Arc, Mutex};

use slint_keyos_platform::slint::{ComponentHandle, ModelRc, VecModel};
use vaults_bridge_core::CredentialRecord;
use vaults_bridge_keystore::Keystore;

use crate::{AppWindow, Callbacks, StoredCredential};

pub struct AppState {
    pub keystore: Arc<Mutex<Keystore>>,
    pub ui: slint_keyos_platform::slint::Weak<AppWindow>,
    pub search: String,
}

impl AppState {
    pub fn new(keystore: Arc<Mutex<Keystore>>, ui: slint_keyos_platform::slint::Weak<AppWindow>) -> Self {
        Self { keystore, ui, search: String::new() }
    }

    pub fn set_search(&mut self, q: String) { self.search = q.to_lowercase(); }

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
