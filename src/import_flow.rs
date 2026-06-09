// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! On-device CSV import.
//!
//! User flow (initiated from the kebab menu in the main page):
//!   1. `import_pick` — show the system file picker, filtered to .csv, reading the chosen file's bytes via
//!      `fs`.
//!   2. Parse via `vaults_bridge_import::parse`. On success, stash the parsed records and update
//!      `Callbacks.import_source` / `import_count` so the slint side renders the confirm modal. On failure,
//!      set `Callbacks.import_error` to a short message.
//!   3. `import_confirm` — commit the stashed records via `Keystore::import_many`, persist, refresh the list,
//!      set `Callbacks.import_imported` / `import_skipped` so the summary modal renders.
//!   4. `import_cancel` — drop the stashed records.
//!
//! Plaintext passwords from the parsed file live only inside this module
//! (in a `Zeroizing<String>` per record) and the keystore. They never
//! cross USB.

use std::sync::{Arc, Mutex};

use slint_keyos_platform::slint::{ComponentHandle, Weak};
#[cfg(target_os = "xous")]
use vaults_bridge_core::{
    engine::{MAX_LABEL_BYTES, MAX_ORIGIN_BYTES, MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES},
    Origin,
};
use vaults_bridge_keystore::{ImportItem, ImportPolicy};

use crate::{AppWindow, Callbacks};

/// Buffer for parsed records between picker → confirm. `None` when no
/// import is pending.
pub type PendingRecords = Arc<Mutex<Option<Vec<ImportItem>>>>;

#[cfg(target_os = "xous")]
const MAX_NOTES_BYTES: usize = 2048;

pub fn new_pending() -> PendingRecords { Arc::new(Mutex::new(None)) }

/// Hosted-simulator stub. The hosted target doesn't have access to the
/// system file picker. Surface a friendly error instead of failing
/// silently.
#[cfg(not(target_os = "xous"))]
pub fn pick_and_parse(_pending: &PendingRecords, ui_weak: &Weak<AppWindow>) {
    if let Some(ui) = ui_weak.upgrade() {
        ui.global::<Callbacks>().set_import_error("File import is only available on hardware.".into());
    }
}

#[cfg(target_os = "xous")]
pub fn pick_and_parse(pending: &PendingRecords, ui_weak: &Weak<AppWindow>) {
    use slint_keyos_platform::{
        fs,
        gui_server_api::navigation::filepicker::{
            AllowedExtensions, AllowedLocations, Location, SelectFileOptions,
        },
        navigation::select_file,
    };
    use vaults_bridge_import::{parse, ImportError};

    use crate::gui_permissions::GuiPermissions;

    let opts = SelectFileOptions::default()
        .with_allowed_extensions(AllowedExtensions::specific(&["csv", "txt"]))
        .with_allowed_locations(AllowedLocations::All)
        .with_dirs_allowed(true);

    let result = match select_file::<GuiPermissions>(opts) {
        Ok(Some(r)) => r,
        Ok(None) => return, // user cancelled
        Err(e) => {
            log::warn!("import: file picker failed: {e:?}");
            set_error(ui_weak, "File picker failed. Try again.");
            return;
        }
    };
    let Some((path, location)) = result.files().first().cloned() else {
        return;
    };
    let fs_location = match location {
        Location::Internal => fs::Location::User,
        Location::Airlock => fs::Location::Airlock,
        Location::External => fs::Location::Usb,
    };

    let bytes = match read_file_bytes(&path, fs_location) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("import: read failed: {e}");
            set_error(ui_weak, "Could not read the selected file.");
            return;
        }
    };

    // Cap the import at a sensible size. 4 MB is ~30k entries even with
    // long passwords + notes, well above any realistic export.
    if bytes.len() > 4 * 1024 * 1024 {
        set_error(ui_weak, "File is too large (4 MB max).");
        return;
    }

    let parsed = match parse(&bytes) {
        Ok(p) => p,
        Err(ImportError::UnrecognisedHeader) => {
            set_error(
                ui_weak,
                "Header row not recognised. Export from Google, Proton, 1Password, Bitwarden, Apple, or LastPass.",
            );
            return;
        }
        Err(e) => {
            log::warn!("import: parse failed: {e}");
            set_error(ui_weak, "Could not parse the file.");
            return;
        }
    };

    // For the generic fallback we can't credit a specific source — drop
    // the label so the UI shows just the count instead of "Generic CSV".
    let source_label = if parsed.source == vaults_bridge_import::Source::Generic {
        String::new()
    } else {
        parsed.source.label().to_string()
    };
    let count = parsed.records.len();
    let mut skipped_invalid = 0usize;
    let items: Vec<ImportItem> = parsed
        .records
        .into_iter()
        .filter_map(|r| {
            let origin = match Origin::parse(&r.origin) {
                Ok(o) => o.as_str().to_string(),
                Err(_) => {
                    skipped_invalid += 1;
                    return None;
                }
            };
            let username = r.username.trim().to_string();
            if username.is_empty()
                || r.password.is_empty()
                || origin.len() > MAX_ORIGIN_BYTES
                || username.len() > MAX_USERNAME_BYTES
                || r.label.len() > MAX_LABEL_BYTES
                || r.password.len() > MAX_PASSWORD_BYTES
                || r.notes.len() > MAX_NOTES_BYTES
            {
                skipped_invalid += 1;
                return None;
            }
            Some(ImportItem {
                origin,
                username,
                password: (*r.password).clone(),
                label: r.label,
                notes: r.notes,
            })
        })
        .collect();
    if items.is_empty() {
        set_error(ui_weak, "No usable passwords found in the selected file.");
        return;
    }
    if skipped_invalid > 0 {
        log::warn!("import: skipped {skipped_invalid} invalid row(s)");
    }
    *pending.lock().unwrap() = Some(items);

    if let Some(ui) = ui_weak.upgrade() {
        let cb = ui.global::<Callbacks>();
        cb.set_import_source(source_label.into());
        cb.set_import_count((count - skipped_invalid) as i32);
        cb.set_import_error("".into());
    }
}

#[cfg(target_os = "xous")]
fn read_file_bytes(path: &str, location: slint_keyos_platform::fs::Location) -> Result<Vec<u8>, String> {
    use std::io::Read;

    use slint_keyos_platform::fs::{FileSystem, OpenFlags};

    use crate::fs_permissions::FileSystemPermissions;

    let fs: FileSystem<FileSystemPermissions> = FileSystem::default();
    let mut file = fs
        .open_file(path.to_string(), location, OpenFlags { read: true, write: false, create: false })
        .map_err(|e| format!("open: {e:?}"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| format!("read: {e:?}"))?;
    Ok(buf)
}

/// Translate the slint-side policy index (0/1/2) into the typed enum.
pub fn policy_from_int(p: i32) -> ImportPolicy {
    match p {
        1 => ImportPolicy::Replace,
        2 => ImportPolicy::KeepBoth,
        _ => ImportPolicy::Skip,
    }
}

pub fn cancel(pending: &PendingRecords) { *pending.lock().unwrap() = None; }

#[cfg(target_os = "xous")]
fn set_error(ui_weak: &Weak<AppWindow>, msg: &str) {
    if let Some(ui) = ui_weak.upgrade() {
        ui.global::<Callbacks>().set_import_error(msg.into());
    }
}
