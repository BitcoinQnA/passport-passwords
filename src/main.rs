// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

mod backup_flow;
mod import_flow;
mod master_key;
mod persist;
mod state;
mod transport;

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use async_trait::async_trait;
use slint_keyos_platform::{
    app,
    slint::{ComponentHandle, SharedString},
};
use uuid::Uuid;
use vaults_bridge_core::{
    approval::{ApprovalAction, ApprovalDecision, ApprovalRequest, Approver, ArcApprover},
    engine::{
        Engine, EngineConfig, MAX_LABEL_BYTES, MAX_ORIGIN_BYTES, MAX_PASSWORD_BYTES,
        MAX_USERNAME_BYTES,
    },
    CredentialRecord, Origin,
};
use vaults_bridge_keystore::Keystore;
use zeroize::Zeroizing;

use crate::{
    backup_flow::PendingRestore, import_flow::PendingRecords, master_key::KeyOsAppSeedSource,
    persist::KeystoreStore, state::AppState,
};

app!("Passwords");

const WS_BIND: &str = "127.0.0.1:9876";
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

struct PendingApproval {
    id: u64,
    tx: oneshot::Sender<ApprovalDecision>,
}

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Passwords starting");

    let store = Arc::new(Mutex::new(KeystoreStore::open()));

    let master = match KeyOsAppSeedSource.fetch() {
        Ok(s) => s,
        Err(e) => {
            log::error!("master key fetch failed: {e:?}");
            ui.global::<Callbacks>()
                .set_server_status(format!("locked: {e:?}").into());
            ui.run().expect("UI running");
            return;
        }
    };

    let keystore = match persist::load_keystore(&store.lock().unwrap(), &master) {
        Ok(ks) => Arc::new(Mutex::new(ks)),
        Err(e) => {
            log::error!("keystore init failed: {e}");
            ui.global::<Callbacks>()
                .set_server_status(format!("keystore error: {e}").into());
            ui.run().expect("UI running");
            return;
        }
    };
    // Master is no longer needed: the keystore derived its AES key during
    // open()/new() and stores only the derived key. Drop the master now so
    // its zeroizing wrapper wipes the bytes; closures below must NOT
    // capture it.
    drop(master);

    let state = Arc::new(Mutex::new(AppState::new(keystore.clone(), ui.as_weak())));
    state.lock().unwrap().refresh_credentials();

    // Approval slot: drained on user tap.
    let pending_tx: Arc<Mutex<Option<PendingApproval>>> = Arc::new(Mutex::new(None));
    let next_approval_id = Arc::new(AtomicU64::new(1));

    {
        let pending_tx = pending_tx.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_approve(move || {
            if let Some(pending) = pending_tx.lock().unwrap().take() {
                let _ = pending.tx.send(ApprovalDecision::Approve);
            }
            clear_approval(&weak);
            if let Some(ui) = weak.upgrade() {
                ui.global::<Navigate>().invoke_backward();
            }
        });
    }
    {
        let pending_tx = pending_tx.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_reject(move || {
            if let Some(pending) = pending_tx.lock().unwrap().take() {
                let _ = pending.tx.send(ApprovalDecision::Reject);
            }
            clear_approval(&weak);
            if let Some(ui) = weak.upgrade() {
                ui.global::<Navigate>().invoke_backward();
            }
        });
    }

    // Search filter
    {
        let state = state.clone();
        ui.global::<Callbacks>()
            .on_search_changed(move |q: SharedString| {
                state.lock().unwrap().set_search(q.as_str().to_string());
                state.lock().unwrap().refresh_credentials();
            });
    }

    // Re-filter on archive-mode toggle (or any time the slint side wants
    // a fresh model snapshot).
    {
        let state = state.clone();
        ui.global::<Callbacks>().on_refresh_list(move || {
            state.lock().unwrap().refresh_credentials();
        });
    }

    // Validators
    ui.global::<Callbacks>()
        .on_validate_origin(|s: SharedString| match Origin::parse(s.as_str()) {
            _ if s.as_str().len() > MAX_ORIGIN_BYTES => "Origin too long".into(),
            Ok(_) => SharedString::new(),
            Err(e) => format!("{e}").into(),
        });
    ui.global::<Callbacks>()
        .on_validate_label(|s: SharedString| {
            if s.as_str().len() > MAX_LABEL_BYTES {
                "Label too long".into()
            } else {
                SharedString::new()
            }
        });

    // Save new credential
    {
        let keystore = keystore.clone();
        let state = state.clone();
        let store = store.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_save_new(
            move |origin: SharedString,
                  username: SharedString,
                  password: SharedString,
                  label: SharedString,
                  color: i32| {
                if let Err(msg) = validate_new_fields(
                    origin.as_str(),
                    username.as_str(),
                    password.as_str(),
                    label.as_str(),
                ) {
                    set_editing_error(&weak, msg);
                    return;
                }
                let canonical = match Origin::parse(origin.as_str()) {
                    Ok(o) => o.as_str().to_string(),
                    Err(e) => {
                        set_editing_error(&weak, &format!("{e}"));
                        return;
                    }
                };
                let mut rec = CredentialRecord::new(
                    canonical,
                    username.as_str().into(),
                    password.as_str().into(),
                );
                rec.label = label.as_str().into();
                rec.color = color;
                {
                    let mut ks = keystore.lock().unwrap();
                    let snapshot = ks.snapshot();
                    ks.add(rec);
                    if let Err(e) = persist_keystore(&ks, &store) {
                        log::warn!("persist failed: {e}");
                        ks.restore_snapshot(snapshot);
                        set_editing_error(&weak, "Could not save password. Try again.");
                        return;
                    }
                }
                state.lock().unwrap().refresh_credentials();
                if let Some(ui) = weak.upgrade() {
                    ui.global::<Callbacks>().set_editing_error("".into());
                    ui.global::<Navigate>().invoke_backward();
                }
            },
        );
    }

    // Edit existing
    {
        let keystore = keystore.clone();
        let state = state.clone();
        let store = store.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_edit_save(
            move |uuid: SharedString,
                  label: SharedString,
                  color: i32,
                  username: SharedString,
                  password: SharedString| {
                let Some(id) = parse_uuid(&uuid) else { return };
                if let Err(msg) =
                    validate_edit_fields(label.as_str(), username.as_str(), password.as_str())
                {
                    set_editing_error(&weak, msg);
                    return;
                }
                {
                    let mut ks = keystore.lock().unwrap();
                    let snapshot = ks.snapshot();
                    // If password is empty, keep the current one (the UI starts
                    // edit mode with an empty password field for safety; user
                    // only types if they want to change it).
                    let new_password = if password.is_empty() {
                        ks.get(id).map(|r| r.password.clone()).unwrap_or_default()
                    } else {
                        password.as_str().to_string()
                    };
                    if let Err(e) = ks.edit(
                        id,
                        label.as_str().into(),
                        color,
                        username.as_str().into(),
                        new_password,
                    ) {
                        log::warn!("edit failed: {e}");
                        return;
                    }
                    if let Err(e) = persist_keystore(&ks, &store) {
                        log::warn!("persist failed: {e}");
                        ks.restore_snapshot(snapshot);
                        set_editing_error(&weak, "Could not save changes. Try again.");
                        return;
                    }
                }
                state.lock().unwrap().refresh_credentials();
                if let Some(ui) = weak.upgrade() {
                    ui.global::<Navigate>().invoke_backward();
                }
            },
        );
    }

    // Archive / restore
    for (cb_setter, archived_value) in [("archive", true), ("restore", false)] {
        let _ = (cb_setter, archived_value);
    }
    {
        let keystore = keystore.clone();
        let state = state.clone();
        let store = store.clone();
        ui.global::<Callbacks>()
            .on_archive(move |uuid: SharedString| {
                if let Some(id) = parse_uuid(&uuid) {
                    let mut ks = keystore.lock().unwrap();
                    let snapshot = ks.snapshot();
                    let _ = ks.set_archived(id, true);
                    if let Err(e) = persist_keystore(&ks, &store) {
                        log::warn!("archive persist failed: {e}");
                        ks.restore_snapshot(snapshot);
                        return;
                    }
                    drop(ks);
                    state.lock().unwrap().refresh_credentials();
                }
            });
    }
    {
        let keystore = keystore.clone();
        let state = state.clone();
        let store = store.clone();
        ui.global::<Callbacks>()
            .on_restore(move |uuid: SharedString| {
                if let Some(id) = parse_uuid(&uuid) {
                    let mut ks = keystore.lock().unwrap();
                    let snapshot = ks.snapshot();
                    let _ = ks.set_archived(id, false);
                    if let Err(e) = persist_keystore(&ks, &store) {
                        log::warn!("restore persist failed: {e}");
                        ks.restore_snapshot(snapshot);
                        return;
                    }
                    drop(ks);
                    state.lock().unwrap().refresh_credentials();
                }
            });
    }

    // Delete forever
    {
        let keystore = keystore.clone();
        let state = state.clone();
        let store = store.clone();
        ui.global::<Callbacks>()
            .on_delete_forever(move |uuid: SharedString| {
                if let Some(id) = parse_uuid(&uuid) {
                    let mut ks = keystore.lock().unwrap();
                    let snapshot = ks.snapshot();
                    if let Err(e) = ks.delete_forever(id) {
                        log::warn!("delete_forever failed: {e}");
                        return;
                    }
                    if let Err(e) = persist_keystore(&ks, &store) {
                        log::warn!("delete_forever persist failed: {e}");
                        ks.restore_snapshot(snapshot);
                        return;
                    }
                    drop(ks);
                    state.lock().unwrap().refresh_credentials();
                }
            });
    }

    // Bulk import (file picker + parse + commit)
    let pending: PendingRecords = import_flow::new_pending();
    {
        let pending = pending.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_pick(move || {
            import_flow::pick_and_parse(&pending, &weak);
        });
    }
    {
        let pending = pending.clone();
        let keystore = keystore.clone();
        let store = store.clone();
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_import_confirm(move |policy: i32| {
                let policy = import_flow::policy_from_int(policy);
                let Some(items) = pending.lock().unwrap().take() else {
                    return;
                };
                let summary = {
                    let mut ks = keystore.lock().unwrap();
                    let snapshot = ks.snapshot();
                    let summary = ks.import_many(items, policy);
                    if summary.imported > 0 || summary.replaced > 0 {
                        if let Err(e) = persist_keystore(&ks, &store) {
                            ks.restore_snapshot(snapshot);
                            if let Some(ui) = weak.upgrade() {
                                ui.global::<Callbacks>().set_import_error(
                                    "Import could not be saved. Try again.".into(),
                                );
                            }
                            log::warn!("import persist failed: {e}");
                            return;
                        }
                    }
                    summary
                };
                state.lock().unwrap().refresh_credentials();
                if let Some(ui) = weak.upgrade() {
                    let cb = ui.global::<Callbacks>();
                    cb.set_import_imported(summary.imported as i32);
                    cb.set_import_skipped(summary.skipped as i32);
                    cb.set_import_replaced(summary.replaced as i32);
                    // Summary modal renders when any counter is > 0; clear
                    // the in-flight count so the policy modal doesn't re-show.
                    cb.set_import_count(0);
                }
            });
    }
    {
        let pending = pending.clone();
        ui.global::<Callbacks>().on_import_cancel(move || {
            import_flow::cancel(&pending);
        });
    }

    // Encrypted backup / restore.
    let pending_restore: PendingRestore = backup_flow::new_pending_restore();
    {
        let keystore = keystore.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_backup_export(move |passphrase: SharedString| {
                let passphrase = Zeroizing::new(passphrase.as_str().as_bytes().to_vec());
                backup_flow::export_encrypted_backup(&keystore, passphrase.as_slice(), &weak);
            });
    }
    {
        let pending_restore = pending_restore.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_backup_restore_pick(move |passphrase: SharedString| {
                let passphrase = Zeroizing::new(passphrase.as_str().as_bytes().to_vec());
                backup_flow::pick_restore_backup(&pending_restore, passphrase.as_slice(), &weak);
            });
    }
    {
        let pending_restore = pending_restore.clone();
        let keystore = keystore.clone();
        let store = store.clone();
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_backup_restore_confirm(move || {
            let Some(records) = pending_restore.lock().unwrap().take() else {
                return;
            };
            let count = records.len();
            {
                let mut ks = keystore.lock().unwrap();
                let snapshot = ks.snapshot();
                ks.replace_records(records);
                if let Err(e) = persist_keystore(&ks, &store) {
                    log::warn!("backup restore persist failed: {e}");
                    ks.restore_snapshot(snapshot);
                    if let Some(ui) = weak.upgrade() {
                        let cb = ui.global::<Callbacks>();
                        cb.set_backup_restore_count(0);
                        cb.set_backup_error("Backup could not be saved. Try again.".into());
                    }
                    return;
                }
            }
            state.lock().unwrap().refresh_credentials();
            if let Some(ui) = weak.upgrade() {
                let cb = ui.global::<Callbacks>();
                cb.set_backup_restore_count(0);
                backup_flow::set_success(
                    &weak,
                    &format!("Restored {count} passwords from encrypted backup."),
                );
            }
        });
    }
    {
        let pending_restore = pending_restore.clone();
        ui.global::<Callbacks>().on_backup_cancel(move || {
            backup_flow::cancel_restore(&pending_restore);
        });
    }

    // Change color (from details page)
    {
        let keystore = keystore.clone();
        let state = state.clone();
        let store = store.clone();
        ui.global::<Callbacks>()
            .on_change_color(move |uuid: SharedString, color: i32| {
                let Some(id) = parse_uuid(&uuid) else { return };
                let mut ks = keystore.lock().unwrap();
                let snapshot = ks.snapshot();
                if let Err(e) = ks.set_color(id, color) {
                    log::warn!("set_color failed: {e}");
                    return;
                }
                if let Err(e) = persist_keystore(&ks, &store) {
                    log::warn!("set_color persist failed: {e}");
                    ks.restore_snapshot(snapshot);
                    return;
                }
                drop(ks);
                state.lock().unwrap().refresh_credentials();
            });
    }

    // Reveal password
    {
        let keystore = keystore.clone();
        ui.global::<Callbacks>()
            .on_reveal_password(move |uuid: SharedString| -> SharedString {
                let Some(id) = parse_uuid(&uuid) else {
                    return SharedString::new();
                };
                let ks = keystore.lock().unwrap();
                ks.get(id)
                    .map(|r| r.password.as_str().into())
                    .unwrap_or_default()
            });
    }

    // On-device strong-password generator for the manual add/edit flow.
    ui.global::<Callbacks>()
        .on_generate_strong(|| -> SharedString {
            vaults_bridge_core::engine::generate_password(
                24,
                &vaults_bridge_protocol::CharsetHint::default(),
            )
            .into()
        });

    // Approver wired into engine
    let approver: ArcApprover = Arc::new(SlintApprover {
        ui_weak: ui.as_weak(),
        pending_tx: pending_tx.clone(),
        next_id: next_approval_id.clone(),
    });

    // Hook fired by the engine after store_credential / generate_password
    // mutations. Persists the keystore to disk and re-renders the UI list.
    let on_write = {
        let keystore = keystore.clone();
        let store = store.clone();
        let state_for_refresh = state.clone();
        Arc::new(
            move || -> Result<(), vaults_bridge_core::engine::PersistError> {
                {
                    let ks = keystore.lock().unwrap();
                    persist_keystore(&ks, &store).map_err(|e| {
                        log::warn!("engine on_write persist failed: {e}");
                        vaults_bridge_core::engine::PersistError
                    })?;
                }
                let state = state_for_refresh.clone();
                let _ = slint_keyos_platform::slint::invoke_from_event_loop(move || {
                    state.lock().unwrap().refresh_credentials();
                });
                Ok(())
            },
        ) as vaults_bridge_core::engine::OnWriteHook
    };

    let engine = Arc::new(Engine::new(
        keystore.clone(),
        approver,
        EngineConfig::default(),
        on_write,
    ));

    let engine_for_server = engine.clone();
    let weak_for_status = ui.as_weak();
    thread::Builder::new()
        .name("passwords-transport".into())
        .spawn(move || run_transport(engine_for_server, weak_for_status))
        .expect("spawn transport thread");

    // Status banner poll
    let weak_for_banner = ui.as_weak();
    let banner = slint_keyos_platform::slint::Timer::default();
    let mut last = String::new();
    banner.start(
        slint_keyos_platform::slint::TimerMode::Repeated,
        Duration::from_millis(500),
        move || {
            let cur = transport::status()
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            if cur != last {
                last = cur.clone();
                if let Some(ui) = weak_for_banner.upgrade() {
                    ui.global::<Callbacks>().set_server_status(cur.into());
                }
            }
        },
    );
    std::mem::forget(banner);

    ui.run().expect("UI running");
}

#[cfg(not(target_os = "xous"))]
fn run_transport(
    engine: Arc<Engine<Keystore>>,
    weak: slint_keyos_platform::slint::Weak<AppWindow>,
) {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("tokio build failed: {e}");
            return;
        }
    };
    rt.block_on(async move {
        if let Err(e) = transport::serve(engine, WS_BIND).await {
            let msg = format!("ws error: {e}");
            log::error!("{msg}");
            let _ = slint_keyos_platform::slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    ui.global::<Callbacks>().set_server_status(msg.into());
                }
            });
        }
    });
}

#[cfg(target_os = "xous")]
fn run_transport(
    engine: Arc<Engine<Keystore>>,
    weak: slint_keyos_platform::slint::Weak<AppWindow>,
) {
    use slint_keyos_platform::futures_lite::future::block_on;
    if let Err(e) = block_on(transport::serve(engine, WS_BIND)) {
        let msg = format!("usb error: {e}");
        log::error!("{msg}");
        let _ = slint_keyos_platform::slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                ui.global::<Callbacks>().set_server_status(msg.into());
            }
        });
    }
}

struct SlintApprover {
    ui_weak: slint_keyos_platform::slint::Weak<AppWindow>,
    pending_tx: Arc<Mutex<Option<PendingApproval>>>,
    next_id: Arc<AtomicU64>,
}

#[async_trait]
impl Approver for SlintApprover {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        let (tx, rx) = oneshot::channel();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // If a prior approval is still pending (host pipelined a second
        // request before the user tapped), reject it explicitly so its
        // future resolves cleanly. Without this, the prior sender is
        // silently dropped and its OneshotFuture observes Disconnected.
        if let Some(old) = self
            .pending_tx
            .lock()
            .unwrap()
            .replace(PendingApproval { id, tx })
        {
            let _ = old.tx.send(ApprovalDecision::Reject);
        }

        {
            let pending_tx = self.pending_tx.clone();
            let weak = self.ui_weak.clone();
            thread::spawn(move || {
                thread::sleep(APPROVAL_TIMEOUT);
                let timed_out = {
                    let mut slot = pending_tx.lock().unwrap();
                    if slot.as_ref().map(|p| p.id) == Some(id) {
                        let pending = slot.take().unwrap();
                        let _ = pending.tx.send(ApprovalDecision::Timeout);
                        true
                    } else {
                        false
                    }
                };
                if timed_out {
                    let _ = slint_keyos_platform::slint::invoke_from_event_loop(move || {
                        if let Some(ui) = weak.upgrade() {
                            let mut s = ui.global::<Callbacks>().get_approval();
                            s.active = false;
                            ui.global::<Callbacks>().set_approval(s);
                            ui.global::<Navigate>().invoke_backward();
                        }
                    });
                }
            });
        }

        let weak = self.ui_weak.clone();
        let r = req.clone();
        let title = r.action.title().to_string();
        let action_verb = action_verb(r.action).to_string();
        let scheduled = slint_keyos_platform::slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                ui.global::<Callbacks>().set_approval(crate::ApprovalState {
                    active: true,
                    title: title.into(),
                    action_verb: action_verb.into(),
                    origin: r.origin.into(),
                    username: r.username.into(),
                });
                ui.global::<Navigate>()
                    .invoke_approval(NavigateOptions::default());
            }
        });
        if scheduled.is_err() {
            let mut slot = self.pending_tx.lock().unwrap();
            if slot.as_ref().map(|p| p.id) == Some(id) {
                *slot = None;
            }
            return ApprovalDecision::Reject;
        }
        match rx.await {
            Ok(v) => v,
            Err(_) => {
                // Slot was overwritten by a second request, or the UI
                // tore down before the user tapped. Treat as a rejection
                // rather than panicking — a panic here aborts the tokio
                // worker and may force a device reboot.
                ApprovalDecision::Reject
            }
        }
    }

    fn cancel_pending(&self) -> bool {
        let cancelled = self
            .pending_tx
            .lock()
            .unwrap()
            .take()
            .map(|pending| pending.tx.send(ApprovalDecision::Reject).is_ok())
            .unwrap_or(false);
        if cancelled {
            let weak = self.ui_weak.clone();
            let _ = slint_keyos_platform::slint::invoke_from_event_loop(move || {
                if let Some(ui) = weak.upgrade() {
                    let mut s = ui.global::<Callbacks>().get_approval();
                    s.active = false;
                    ui.global::<Callbacks>().set_approval(s);
                    ui.global::<Navigate>().invoke_backward();
                }
            });
        }
        cancelled
    }
}

fn clear_approval(ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>) {
    if let Some(ui) = ui_weak.upgrade() {
        let mut s = ui.global::<Callbacks>().get_approval();
        s.active = false;
        ui.global::<Callbacks>().set_approval(s);
    }
}

fn set_editing_error(ui_weak: &slint_keyos_platform::slint::Weak<AppWindow>, msg: &str) {
    if let Some(ui) = ui_weak.upgrade() {
        ui.global::<Callbacks>().set_editing_error(msg.into());
    }
}

fn validate_new_fields(
    origin: &str,
    username: &str,
    password: &str,
    label: &str,
) -> Result<(), &'static str> {
    if origin.trim().is_empty() {
        return Err("Website is required.");
    }
    if origin.len() > MAX_ORIGIN_BYTES {
        return Err("Website is too long.");
    }
    validate_edit_fields(label, username, password)?;
    if password.is_empty() {
        return Err("Password is required.");
    }
    Ok(())
}

fn validate_edit_fields(label: &str, username: &str, password: &str) -> Result<(), &'static str> {
    if label.len() > MAX_LABEL_BYTES {
        return Err("Label is too long.");
    }
    if username.trim().is_empty() {
        return Err("Username is required.");
    }
    if username.len() > MAX_USERNAME_BYTES {
        return Err("Username is too long.");
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("Password is too long.");
    }
    Ok(())
}

fn parse_uuid(s: &SharedString) -> Option<Uuid> {
    Uuid::parse_str(s.as_str()).ok()
}

fn action_verb(action: ApprovalAction) -> &'static str {
    match action {
        ApprovalAction::Release => "release",
        ApprovalAction::Save => "save",
        ApprovalAction::Update => "update",
        ApprovalAction::RestoreAndUpdate => "restore",
        ApprovalAction::Generate => "generate",
        ApprovalAction::GenerateAndUpdate => "generate",
        ApprovalAction::GenerateAndRestore => "generate",
        ApprovalAction::Import => "import",
    }
}

/// Seal the keystore and hand the blob to the FileBacked-backed
/// `KeystoreStore`. The store handles atomic write itself.
fn persist_keystore(ks: &Keystore, store: &Arc<Mutex<KeystoreStore>>) -> anyhow::Result<()> {
    let blob = ks.seal().map_err(|e| anyhow::anyhow!("{e}"))?;
    store.lock().unwrap().write(blob)
}
