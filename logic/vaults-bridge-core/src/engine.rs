// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Protocol engine: routes parsed `Request`s to the credential store +
//! approver + session and returns a `Response`. Generic over the
//! `CredentialStore` so the core crate stays free of any storage dep.

use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};
use vaults_bridge_protocol::{
    CharsetHint, CredentialSummary as WireCredentialSummary, ErrorCode, ErrorPayload,
    EstablishSessionParams, EstablishSessionResult, GeneratePasswordParams, GeneratePasswordResult,
    ListCredentialsParams, ListCredentialsResult, ListOriginsResult, Method,
    ReleaseCredentialParams, ReleaseCredentialResult, Request, Response, ResponseBody, StoreAction,
    StoreCredentialParams, StoreCredentialResult,
};
use zeroize::Zeroizing;

use crate::{
    approval::{ApprovalAction, ApprovalDecision, ApprovalRequest, ArcApprover},
    origin::Origin,
    record::{
        sanitize_display_text, ReleaseEvent, MAX_HISTORY_NAME_BYTES, MAX_HISTORY_QID_BYTES,
    },
    session::{Session, SessionError},
    store::{CredentialStore, ExistingCredential},
};

pub const SESSION_INFO: &[u8] = b"vaults-bridge v1 session";
pub const DEFAULT_IDLE_MS: u64 = 15 * 60 * 1000;

/// Password generation policy. Hints from the host are clamped to these.
pub const MIN_GENERATED_LENGTH: u32 = 16;
pub const MAX_GENERATED_LENGTH: u32 = 64;
pub const DEFAULT_GENERATED_LENGTH: u32 = 24;

/// Per-field input length caps applied at the engine boundary. Keeps an
/// adversarial host from forcing the keystore to grow without bound or
/// dragging serialization into pathological territory.
pub const MAX_ORIGIN_BYTES: usize = 512;
pub const MAX_USERNAME_BYTES: usize = 256;
pub const MAX_LABEL_BYTES: usize = 128;
pub const MAX_PASSWORD_BYTES: usize = 512;
pub const MAX_CLIENT_NAME_BYTES: usize = MAX_HISTORY_NAME_BYTES;

/// The paired peer that asked for a release, as the Prime knows it.
/// Filled in by the QLv2 transport from the authenticated QID, never from
/// the requester's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePeer {
    pub name: String,
    pub qid: String,
}

fn surface_from_client_name(client_name: Option<&str>) -> String {
    let name = client_name
        .map(|s| sanitize_display_text(s, MAX_CLIENT_NAME_BYTES))
        .unwrap_or_default();
    if name.is_empty() {
        "Unknown app".into()
    } else {
        name
    }
}

fn peer_fields(peer: Option<&ReleasePeer>) -> (String, String) {
    match peer {
        Some(p) => {
            let name = sanitize_display_text(&p.name, MAX_CLIENT_NAME_BYTES);
            let qid = sanitize_display_text(&p.qid, MAX_HISTORY_QID_BYTES);
            (
                if name.is_empty() {
                    "Unknown peer".into()
                } else {
                    name
                },
                qid,
            )
        }
        None => ("Unknown peer".into(), String::new()),
    }
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub idle_ms: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            idle_ms: DEFAULT_IDLE_MS,
        }
    }
}

/// Returned by an `OnWriteHook` when persistence fails. Engine maps this
/// to `ErrorCode::Internal` so the host knows the mutation didn't actually
/// reach disk and can refuse to surface "Saved" UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistError;

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("persist failed")
    }
}

impl std::error::Error for PersistError {}

pub type OnWriteHook = Arc<dyn Fn() -> Result<(), PersistError> + Send + Sync>;

pub struct Engine<S: CredentialStore> {
    store: Arc<Mutex<S>>,
    session: Mutex<Session>,
    approver: ArcApprover,
    cfg: EngineConfig,
    /// Fired after every successful credential mutation by the engine
    /// (store_credential, generate_password). On-device this persists
    /// the encrypted keystore to disk and refreshes the Slint model.
    /// Tests pass a no-op.
    on_write: OnWriteHook,
}

impl<S: CredentialStore + 'static> Engine<S> {
    pub fn new(
        store: Arc<Mutex<S>>,
        approver: ArcApprover,
        cfg: EngineConfig,
        on_write: OnWriteHook,
    ) -> Self {
        Self {
            store,
            session: Mutex::new(Session::new()),
            approver,
            cfg,
            on_write,
        }
    }

    /// Convenience for tests: no-op `on_write` hook.
    pub fn new_in_memory(store: Arc<Mutex<S>>, approver: ArcApprover, cfg: EngineConfig) -> Self {
        Self::new(store, approver, cfg, Arc::new(|| Ok(())))
    }

    pub async fn handle(&self, req: Request, now_ms: u64) -> Response {
        self.handle_from(req, now_ms, None).await
    }

    /// Like [`handle`], with the Prime's view of the paired peer for a release.
    pub async fn handle_from(
        &self,
        req: Request,
        now_ms: u64,
        peer: Option<ReleasePeer>,
    ) -> Response {
        let id = req.id.clone();
        match self.dispatch(req, now_ms, peer).await {
            Ok(body) => Response::Ok { id, result: body },
            Err((code, message)) => Response::Err {
                id,
                error: ErrorPayload {
                    code: code as i32,
                    message,
                },
            },
        }
    }

    async fn dispatch(
        &self,
        req: Request,
        now_ms: u64,
        peer: Option<ReleasePeer>,
    ) -> Result<ResponseBody, (ErrorCode, String)> {
        match req.method {
            Method::Ping => Ok(ResponseBody::Pong { pong: true }),

            Method::EstablishSession(EstablishSessionParams { host_pubkey }) => {
                let mut s = self.session.lock().unwrap();
                let device_pubkey = s
                    .accept(&host_pubkey, SESSION_INFO, now_ms)
                    .map_err(map_session_err)?;
                Ok(ResponseBody::EstablishSession(EstablishSessionResult {
                    device_pubkey,
                }))
            }

            Method::ListOrigins => {
                self.gate_active_session(now_ms)?;
                let store = self.store.lock().unwrap();
                let mut origins = store.list_origins();
                origins.sort();
                Ok(ResponseBody::ListOrigins(ListOriginsResult { origins }))
            }

            Method::ListCredentials(ListCredentialsParams { origin }) => {
                self.gate_active_session(now_ms)?;
                let canonical = canonicalize_origin(&origin)?;
                let store = self.store.lock().unwrap();
                let mut credentials: Vec<WireCredentialSummary> = store
                    .list_credentials_for_origin(&canonical)
                    .into_iter()
                    .map(|c| WireCredentialSummary {
                        username: c.username,
                        label: c.label,
                        last_used_at: c.last_used_at,
                    })
                    .collect();
                credentials.sort_by(|a, b| {
                    b.last_used_at
                        .cmp(&a.last_used_at)
                        .then_with(|| a.username.cmp(&b.username))
                });
                Ok(ResponseBody::ListCredentials(ListCredentialsResult {
                    credentials,
                }))
            }

            Method::ReleaseCredential(ReleaseCredentialParams {
                origin,
                username_hint,
                client_name,
                request_nonce,
            }) => self
                .handle_release(
                    origin,
                    username_hint,
                    client_name,
                    request_nonce,
                    now_ms,
                    peer,
                )
                .await
                .map(ResponseBody::ReleaseCredential),

            Method::StoreCredential(p) => self
                .handle_store(p, now_ms)
                .await
                .map(ResponseBody::StoreCredential),

            Method::GeneratePassword(p) => self
                .handle_generate(p, now_ms)
                .await
                .map(ResponseBody::GeneratePassword),

            Method::Cancel => {
                self.approver.cancel_pending();
                Ok(ResponseBody::Empty {})
            }
        }
    }

    async fn handle_release(
        &self,
        origin: String,
        username_hint: Option<String>,
        client_name: Option<String>,
        request_nonce: u64,
        now_ms: u64,
        peer: Option<ReleasePeer>,
    ) -> Result<ReleaseCredentialResult, (ErrorCode, String)> {
        let canonical = canonicalize_origin(&origin)?;
        if let Some(h) = &username_hint {
            check_str_len("username_hint", h, MAX_USERNAME_BYTES)?;
        }

        self.gate_session(request_nonce, now_ms)?;

        // Wrap the chosen plaintext in Zeroizing so the heap-allocated
        // copy is wiped when this scope ends, including on the early-
        // return paths below.
        let (username, password_plain) = {
            let store = self.store.lock().unwrap();
            let candidates = store.find_by_origin(&canonical);
            if candidates.is_empty() {
                return Err((ErrorCode::UnknownOrigin, "no records for origin".into()));
            }
            let chosen = match &username_hint {
                Some(h) => candidates
                    .iter()
                    .find(|r| r.username == *h)
                    .cloned()
                    .ok_or_else(|| {
                        (
                            ErrorCode::UnknownOrigin,
                            "no matching username for origin".into(),
                        )
                    })?,
                None if candidates.len() == 1 => candidates[0].clone(),
                None => {
                    return Err((
                        ErrorCode::MultipleMatches,
                        "multiple credentials match this origin".into(),
                    ));
                }
            };
            (chosen.username, Zeroizing::new(chosen.password))
        };

        let decision = self
            .approver
            .request(ApprovalRequest {
                action: ApprovalAction::Release,
                origin: canonical.clone(),
                username: username.clone(),
                request_nonce,
            })
            .await;
        if decision == ApprovalDecision::Reject {
            return Err((ErrorCode::UserRejected, "user rejected".into()));
        }
        if decision == ApprovalDecision::Timeout {
            return Err((ErrorCode::Timeout, "approval timed out".into()));
        }

        let mut s = self.session.lock().unwrap();
        let password_sealed = s
            .seal(password_plain.as_bytes(), now_ms)
            .map_err(map_session_err)?;
        drop(s);

        let (peer_name, peer_qid) = peer_fields(peer.as_ref());
        let event = ReleaseEvent {
            surface: surface_from_client_name(client_name.as_deref()),
            peer_name,
            peer_qid,
            released_at: now_ms / 1000,
        };
        {
            let mut store = self.store.lock().unwrap();
            let _ = store.record_release(&canonical, &username, event);
        }
        // Persist so the history survives a restart. If this fails, the
        // release itself already happened (the user approved it), so still
        // return the sealed password.
        let _ = (self.on_write)();

        Ok(ReleaseCredentialResult {
            username,
            password_sealed,
        })
    }

    async fn handle_store(
        &self,
        p: StoreCredentialParams,
        now_ms: u64,
    ) -> Result<StoreCredentialResult, (ErrorCode, String)> {
        let StoreCredentialParams {
            origin,
            username,
            label,
            password_sealed,
            request_nonce,
        } = p;
        let canonical = canonicalize_origin(&origin)?;
        if username.is_empty() {
            return Err((ErrorCode::InvalidRequest, "username is required".into()));
        }
        check_str_len("username", &username, MAX_USERNAME_BYTES)?;
        if let Some(l) = &label {
            check_str_len("label", l, MAX_LABEL_BYTES)?;
        }

        self.gate_session(request_nonce, now_ms)?;

        // Decrypt password under session key BEFORE prompting, so we fail
        // fast on a malformed payload without bothering the user.
        let password_plain: Zeroizing<String> = {
            let mut s = self.session.lock().unwrap();
            let bytes = s.open(&password_sealed, now_ms).map_err(map_session_err)?;
            let plain = String::from_utf8(bytes)
                .map_err(|_| (ErrorCode::InvalidRequest, "password is not utf-8".into()))?;
            Zeroizing::new(plain)
        };
        if password_plain.len() > MAX_PASSWORD_BYTES {
            return Err((ErrorCode::InvalidRequest, "password too long".into()));
        }

        // Probe existing state to decide which approval action.
        let existing = self.store.lock().unwrap().probe(&canonical, &username);
        let (action, store_action) = match existing {
            ExistingCredential::None => (ApprovalAction::Save, StoreAction::Saved),
            ExistingCredential::Live => (ApprovalAction::Update, StoreAction::Updated),
            ExistingCredential::Archived => (
                ApprovalAction::RestoreAndUpdate,
                StoreAction::RestoredAndUpdated,
            ),
        };

        let decision = self
            .approver
            .request(ApprovalRequest {
                action,
                origin: canonical.clone(),
                username: username.clone(),
                request_nonce,
            })
            .await;
        if decision == ApprovalDecision::Reject {
            return Err((ErrorCode::UserRejected, "user rejected".into()));
        }
        if decision == ApprovalDecision::Timeout {
            return Err((ErrorCode::Timeout, "approval timed out".into()));
        }

        self.commit_store_mutation(|store| {
            store
                .upsert(canonical, username, (*password_plain).clone(), label)
                .map_err(|_| (ErrorCode::Internal, "store backend".into()))
        })?;

        Ok(StoreCredentialResult {
            action: store_action,
        })
    }

    async fn handle_generate(
        &self,
        p: GeneratePasswordParams,
        now_ms: u64,
    ) -> Result<GeneratePasswordResult, (ErrorCode, String)> {
        let GeneratePasswordParams {
            origin,
            username,
            label,
            length,
            charset,
            request_nonce,
        } = p;
        let canonical = canonicalize_origin(&origin)?;
        if username.is_empty() {
            return Err((ErrorCode::InvalidRequest, "username is required".into()));
        }
        check_str_len("username", &username, MAX_USERNAME_BYTES)?;
        if let Some(l) = &label {
            check_str_len("label", l, MAX_LABEL_BYTES)?;
        }

        self.gate_session(request_nonce, now_ms)?;

        let len = length
            .unwrap_or(DEFAULT_GENERATED_LENGTH)
            .clamp(MIN_GENERATED_LENGTH, MAX_GENERATED_LENGTH);
        let charset = charset.unwrap_or_default();
        if !(charset.letters || charset.digits || charset.symbols) {
            return Err((
                ErrorCode::BadPolicy,
                "at least one charset class must be enabled".into(),
            ));
        }

        // Probe existing record to label the approval card correctly.
        let existing = self.store.lock().unwrap().probe(&canonical, &username);
        let (action, store_action) = match existing {
            ExistingCredential::None => (ApprovalAction::Generate, StoreAction::Saved),
            ExistingCredential::Live => (ApprovalAction::GenerateAndUpdate, StoreAction::Updated),
            ExistingCredential::Archived => (
                ApprovalAction::GenerateAndRestore,
                StoreAction::RestoredAndUpdated,
            ),
        };

        let decision = self
            .approver
            .request(ApprovalRequest {
                action,
                origin: canonical.clone(),
                username: username.clone(),
                request_nonce,
            })
            .await;
        if decision == ApprovalDecision::Reject {
            return Err((ErrorCode::UserRejected, "user rejected".into()));
        }
        if decision == ApprovalDecision::Timeout {
            return Err((ErrorCode::Timeout, "approval timed out".into()));
        }

        let password = Zeroizing::new(generate_password(len as usize, &charset));

        self.commit_store_mutation(|store| {
            store
                .upsert(canonical, username, (*password).clone(), label)
                .map_err(|_| (ErrorCode::Internal, "store backend".into()))
        })?;

        let mut s = self.session.lock().unwrap();
        let password_sealed = s
            .seal(password.as_bytes(), now_ms)
            .map_err(map_session_err)?;

        Ok(GeneratePasswordResult {
            password_sealed,
            action: store_action,
        })
    }

    fn gate_session(&self, request_nonce: u64, now_ms: u64) -> Result<(), (ErrorCode, String)> {
        let mut s = self.session.lock().unwrap();
        if s.check_idle(now_ms, self.cfg.idle_ms) {
            return Err((ErrorCode::SessionExpired, "session idle timeout".into()));
        }
        s.accept_nonce(request_nonce, now_ms)
            .map_err(map_session_err)
    }

    fn gate_active_session(&self, now_ms: u64) -> Result<(), (ErrorCode, String)> {
        let mut s = self.session.lock().unwrap();
        if !s.is_active() {
            return Err((ErrorCode::SessionExpired, "session not active".into()));
        }
        if s.check_idle(now_ms, self.cfg.idle_ms) {
            return Err((ErrorCode::SessionExpired, "session idle timeout".into()));
        }
        Ok(())
    }

    fn commit_store_mutation<T>(
        &self,
        mutate: impl FnOnce(&mut S) -> Result<T, (ErrorCode, String)>,
    ) -> Result<T, (ErrorCode, String)> {
        let snapshot;
        let result;
        {
            let mut store = self.store.lock().unwrap();
            snapshot = store.snapshot();
            result = mutate(&mut store)?;
        }

        // Persistence MUST succeed before we tell the host "saved".
        // Otherwise the user's UI says "Saved" but a power-cycle reveals
        // the credential never reached disk. If persistence fails, restore
        // the in-memory view too so UI state cannot drift from durable state.
        if (self.on_write)().is_err() {
            self.store.lock().unwrap().restore_snapshot(snapshot);
            return Err((ErrorCode::Internal, "persist failed".into()));
        }

        Ok(result)
    }
}

fn canonicalize_origin(input: &str) -> Result<String, (ErrorCode, String)> {
    if input.len() > MAX_ORIGIN_BYTES {
        return Err((ErrorCode::InvalidRequest, "origin too long".into()));
    }
    // Accept any well-formed origin and use the canonical form as the
    // match key. We deliberately don't require strict equality with the
    // input — browsers normalize differently than `url`, and forcing the
    // host to replicate our exact rules is brittle.
    let parsed =
        Origin::parse(input).map_err(|_| (ErrorCode::InvalidRequest, "invalid origin".into()))?;
    Ok(parsed.as_str().to_string())
}

fn check_str_len(name: &'static str, s: &str, max: usize) -> Result<(), (ErrorCode, String)> {
    if s.len() > max {
        return Err((ErrorCode::InvalidRequest, format!("{name} too long")));
    }
    Ok(())
}

fn map_session_err(e: SessionError) -> (ErrorCode, String) {
    // Map to a fixed set of public messages. SessionError's Display is
    // fine for logs (and contains the nonce-reuse counters which are
    // useful telemetry on the device) but we don't echo it to the host.
    let (code, message) = match e {
        SessionError::NonceReused { .. } => (ErrorCode::NonceReused, "nonce reused"),
        SessionError::Expired => (ErrorCode::SessionExpired, "session expired"),
        SessionError::NotActive => (ErrorCode::SessionExpired, "session not active"),
        SessionError::InvalidPubkey => (ErrorCode::InvalidRequest, "invalid public key"),
        SessionError::BadHex => (ErrorCode::InvalidRequest, "invalid hex"),
        SessionError::SealFailed => (ErrorCode::Internal, "seal failed"),
        SessionError::OpenFailed => (ErrorCode::Internal, "open failed"),
    };
    (code, message.into())
}

/// Generate a strong random password using `OsRng` with rejection
/// sampling for an unbiased distribution over the configured alphabet.
/// Exposed publicly so the on-device manual add flow can offer a
/// "Generate" button that produces a value identical in shape to what
/// `generate_password` returns.
pub fn generate_password(len: usize, hint: &CharsetHint) -> String {
    let mut alphabet: Vec<u8> = Vec::with_capacity(96);
    let mut classes: Vec<&[u8]> = Vec::with_capacity(3);
    if hint.letters {
        classes.push(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
        alphabet.extend_from_slice(classes.last().unwrap());
    }
    if hint.digits {
        classes.push(b"0123456789");
        alphabet.extend_from_slice(classes.last().unwrap());
    }
    if hint.symbols {
        // Common symbols accepted by most password forms. Excludes
        // backtick, backslash, quote, and space which trip up parsers.
        classes.push(b"!@#$%^&*()-_=+[]{};:,.<>/?");
        alphabet.extend_from_slice(classes.last().unwrap());
    }
    if len == 0 || alphabet.is_empty() {
        return String::new();
    }

    let mut bytes = Vec::with_capacity(len);
    for class in classes.iter().take(len) {
        bytes.push(pick_byte(class));
    }
    while bytes.len() < len {
        bytes.push(pick_byte(&alphabet));
    }
    shuffle(&mut bytes);

    bytes.into_iter().map(char::from).collect()
}

fn pick_byte(alphabet: &[u8]) -> u8 {
    let n = alphabet.len() as u32;
    loop {
        let mut b = [0u8; 1];
        OsRng.fill_bytes(&mut b);
        // Reject samples that would bias the distribution: 256 % n samples
        // at the top of the byte range get discarded.
        let limit = 256 - (256 % n);
        if (b[0] as u32) < limit {
            return alphabet[(b[0] as u32 % n) as usize];
        }
    }
}

fn shuffle(bytes: &mut [u8]) {
    if bytes.len() < 2 {
        return;
    }
    for i in (1..bytes.len()).rev() {
        let j = random_index(i + 1);
        bytes.swap(i, j);
    }
}

fn random_index(upper_exclusive: usize) -> usize {
    let n = upper_exclusive as u32;
    loop {
        let mut b = [0u8; 4];
        OsRng.fill_bytes(&mut b);
        let v = u32::from_le_bytes(b);
        let limit = u32::MAX - (u32::MAX % n);
        if v < limit {
            return (v % n) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    };

    use vaults_bridge_protocol::{EstablishSessionParams, StoreCredentialParams};

    use super::*;
    use crate::{
        approval::{ApprovalDecision, AutoApprove},
        record::CredentialRecord,
        session::Session,
        store::{
            CredentialMatch, CredentialStore, CredentialSummary, ExistingCredential, StoreError,
        },
    };

    #[derive(Default)]
    struct TestStore {
        records: Vec<CredentialRecord>,
    }

    impl CredentialStore for TestStore {
        type Snapshot = Vec<CredentialRecord>;

        fn list_origins(&self) -> Vec<String> {
            self.records.iter().map(|r| r.origin.clone()).collect()
        }

        fn list_credentials_for_origin(&self, origin: &str) -> Vec<CredentialSummary> {
            self.records
                .iter()
                .filter(|r| r.origin == origin)
                .map(|r| CredentialSummary {
                    username: r.username.clone(),
                    label: r.label.clone(),
                    last_used_at: r.last_used_at,
                })
                .collect()
        }

        fn find_by_origin(&self, origin: &str) -> Vec<CredentialMatch> {
            self.records
                .iter()
                .filter(|r| r.origin == origin)
                .map(|r| CredentialMatch {
                    username: r.username.clone(),
                    password: r.password.clone(),
                })
                .collect()
        }

        fn snapshot(&self) -> Self::Snapshot {
            self.records.clone()
        }

        fn restore_snapshot(&mut self, snapshot: Self::Snapshot) {
            self.records = snapshot;
        }

        fn probe(&self, origin: &str, username: &str) -> ExistingCredential {
            match self
                .records
                .iter()
                .find(|r| r.origin == origin && r.username == username)
            {
                None => ExistingCredential::None,
                Some(r) if r.archived => ExistingCredential::Archived,
                Some(_) => ExistingCredential::Live,
            }
        }

        fn upsert(
            &mut self,
            origin: String,
            username: String,
            password: String,
            label: Option<String>,
        ) -> Result<(), StoreError> {
            let mut rec = CredentialRecord::new(origin, username, password);
            rec.label = label.unwrap_or_default();
            self.records.push(rec);
            Ok(())
        }

        fn record_release(
            &mut self,
            origin: &str,
            username: &str,
            event: crate::record::ReleaseEvent,
        ) -> Result<(), StoreError> {
            if let Some(rec) = self
                .records
                .iter_mut()
                .find(|r| !r.archived && r.origin == origin && r.username == username)
            {
                rec.push_release(event);
            }
            Ok(())
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match Pin::new(&mut future).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    fn establish(engine: &Engine<TestStore>) -> Session {
        establish_at(engine, 1_000)
    }

    fn establish_at(engine: &Engine<TestStore>, now_ms: u64) -> Session {
        let mut host = Session::new();
        let (host_pub, host_secret) = host.begin_host();
        let resp = block_on(engine.handle(
            Request {
                id: "hs".into(),
                method: Method::EstablishSession(EstablishSessionParams {
                    host_pubkey: hex::encode(host_pub),
                }),
            },
            now_ms,
        ));
        let Response::Ok {
            result: ResponseBody::EstablishSession(result),
            ..
        } = resp
        else {
            panic!("handshake failed");
        };
        host.complete_host(host_secret, &result.device_pubkey, SESSION_INFO, now_ms)
            .unwrap();
        host
    }

    #[test]
    fn generate_respects_charset_letters_only() {
        let pw = generate_password(
            32,
            &CharsetHint {
                letters: true,
                digits: false,
                symbols: false,
            },
        );
        assert_eq!(pw.len(), 32);
        assert!(pw.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn generate_respects_charset_digits_only() {
        let pw = generate_password(
            16,
            &CharsetHint {
                letters: false,
                digits: true,
                symbols: false,
            },
        );
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_default_includes_all_classes_eventually() {
        let pw = generate_password(64, &CharsetHint::default());
        assert!(pw.chars().any(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn generate_default_guarantees_enabled_classes() {
        let pw = generate_password(24, &CharsetHint::default());
        assert!(pw.chars().any(|c| c.is_ascii_alphabetic()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| "!@#$%^&*()-_=+[]{};:,.<>/?".contains(c)));
    }

    #[test]
    fn generate_empty_when_no_classes_enabled() {
        let pw = generate_password(
            24,
            &CharsetHint {
                letters: false,
                digits: false,
                symbols: false,
            },
        );
        assert!(pw.is_empty());
    }

    #[test]
    fn store_rolls_back_when_persist_fails() {
        let store = Arc::new(Mutex::new(TestStore::default()));
        let engine = Engine::new(
            store.clone(),
            Arc::new(AutoApprove),
            EngineConfig::default(),
            Arc::new(|| Err(PersistError)),
        );
        let mut host = establish(&engine);
        let sealed = host.seal(b"secret", 1_100).unwrap();

        let resp = block_on(engine.handle(
            Request {
                id: "store".into(),
                method: Method::StoreCredential(StoreCredentialParams {
                    origin: "https://example.com".into(),
                    username: "alice".into(),
                    label: None,
                    password_sealed: sealed,
                    request_nonce: 1,
                }),
            },
            1_200,
        ));

        let Response::Err { error, .. } = resp else {
            panic!("store unexpectedly succeeded");
        };
        assert_eq!(error.code, ErrorCode::Internal as i32);
        assert!(store.lock().unwrap().records.is_empty());
    }

    #[test]
    fn release_without_hint_rejects_multiple_matches() {
        let store = Arc::new(Mutex::new(TestStore {
            records: vec![
                CredentialRecord::new("https://example.com".into(), "alice".into(), "a".into()),
                CredentialRecord::new("https://example.com".into(), "bob".into(), "b".into()),
            ],
        }));
        let engine = Engine::new_in_memory(store, Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);

        let resp = block_on(engine.handle(
            Request {
                id: "release".into(),
                method: Method::ReleaseCredential(ReleaseCredentialParams {
                    origin: "https://example.com".into(),
                    username_hint: None,
                    client_name: None,
                    request_nonce: 1,
                }),
            },
            1_200,
        ));

        let Response::Err { error, .. } = resp else {
            panic!("release unexpectedly succeeded");
        };
        assert_eq!(error.code, ErrorCode::MultipleMatches as i32);
    }

    fn release_req(client_name: Option<&str>, nonce: u64) -> Request {
        Request {
            id: "release".into(),
            method: Method::ReleaseCredential(ReleaseCredentialParams {
                origin: "https://example.com".into(),
                username_hint: Some("alice".into()),
                client_name: client_name.map(|s| s.into()),
                request_nonce: nonce,
            }),
        }
    }

    #[test]
    fn successful_release_records_surface_peer_and_time() {
        let store = Arc::new(Mutex::new(TestStore {
            records: vec![CredentialRecord::new(
                "https://example.com".into(),
                "alice".into(),
                "secret".into(),
            )],
        }));
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish_at(&engine, 1_795_803_300_000);
        let peer = ReleasePeer {
            name: "Grok Bot".into(),
            qid: "c3a640a62bc3c1e56ea1542fe7b0cff4".into(),
        };
        let resp = block_on(engine.handle_from(
            release_req(Some("Chrome extension"), 1),
            1_795_803_300_000,
            Some(peer),
        ));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let rec = store.lock().unwrap().records[0].clone();
        assert_eq!(rec.release_history.len(), 1);
        let ev = &rec.release_history[0];
        assert_eq!(ev.surface, "Chrome extension");
        assert_eq!(ev.peer_name, "Grok Bot");
        assert_eq!(ev.peer_qid, "c3a640a62bc3c1e56ea1542fe7b0cff4");
        assert_eq!(ev.released_at, 1_795_803_300);
        assert_eq!(rec.last_used_at, 1_795_803_300);
        assert_eq!(ev.row_text(0).date, "27 Nov");
    }

    #[test]
    fn rejected_release_does_not_record_history() {
        let store = Arc::new(Mutex::new(TestStore {
            records: vec![CredentialRecord::new(
                "https://example.com".into(),
                "alice".into(),
                "secret".into(),
            )],
        }));
        let engine = Engine::new_in_memory(
            store.clone(),
            Arc::new(crate::approval::AutoReject),
            EngineConfig::default(),
        );
        let _host = establish(&engine);
        let resp = block_on(engine.handle_from(
            release_req(Some("Chrome extension"), 1),
            1_200,
            Some(ReleasePeer {
                name: "Grok Bot".into(),
                qid: "abc".into(),
            }),
        ));
        let Response::Err { error, .. } = resp else {
            panic!("expected reject, got {resp:?}");
        };
        assert_eq!(error.code, ErrorCode::UserRejected as i32);
        assert!(store.lock().unwrap().records[0].release_history.is_empty());
    }

    #[test]
    fn timed_out_release_does_not_record_history() {
        struct AutoTimeout;
        #[async_trait::async_trait]
        impl crate::approval::Approver for AutoTimeout {
            async fn request(&self, _req: crate::approval::ApprovalRequest) -> ApprovalDecision {
                ApprovalDecision::Timeout
            }
        }
        let store = Arc::new(Mutex::new(TestStore {
            records: vec![CredentialRecord::new(
                "https://example.com".into(),
                "alice".into(),
                "secret".into(),
            )],
        }));
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoTimeout), EngineConfig::default());
        let _host = establish(&engine);
        let resp = block_on(engine.handle(release_req(Some("Chrome extension"), 1), 1_200));
        let Response::Err { error, .. } = resp else {
            panic!("expected timeout, got {resp:?}");
        };
        assert_eq!(error.code, ErrorCode::Timeout as i32);
        assert!(store.lock().unwrap().records[0].release_history.is_empty());
    }

    #[test]
    fn missing_client_name_records_unknown_app() {
        let store = Arc::new(Mutex::new(TestStore {
            records: vec![CredentialRecord::new(
                "https://example.com".into(),
                "alice".into(),
                "secret".into(),
            )],
        }));
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);
        let resp = block_on(engine.handle(release_req(None, 1), 1_200));
        assert!(matches!(resp, Response::Ok { .. }));
        let ev = &store.lock().unwrap().records[0].release_history[0];
        assert_eq!(ev.surface, "Unknown app");
        assert_eq!(ev.peer_name, "Unknown peer");
        assert!(ev.peer_qid.is_empty());
    }

    // ---- more release history behavior -----------------------------------

    fn one_alice_store() -> Arc<Mutex<TestStore>> {
        Arc::new(Mutex::new(TestStore {
            records: vec![CredentialRecord::new(
                "https://example.com".into(),
                "alice".into(),
                "secret".into(),
            )],
        }))
    }

    fn peer(name: &str) -> Option<ReleasePeer> {
        Some(ReleasePeer { name: name.into(), qid: "c3a640a62bc3c1e56ea1542fe7b0cff4".into() })
    }

    #[test]
    fn each_release_keeps_the_peer_name_the_prime_knew_at_that_moment() {
        // The transport looks the name up per request, so a rename between two
        // releases shows up as two different names in the history.
        let store = one_alice_store();
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);
        for (nonce, name) in [(1, "Forge box"), (2, "Grok Bot")] {
            let resp = block_on(engine.handle_from(
                release_req(Some("Chrome extension"), nonce),
                1_200,
                peer(name),
            ));
            assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        }
        let history = store.lock().unwrap().records[0].release_history.clone();
        let names: Vec<&str> = history.iter().map(|e| e.peer_name.as_str()).collect();
        assert_eq!(names, ["Forge box", "Grok Bot"]);
        assert!(history.iter().all(|e| e.surface == "Chrome extension"));
    }

    #[test]
    fn requester_text_is_cleaned_and_capped_before_it_is_stored() {
        let store = one_alice_store();
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);
        let long = format!("\u{202E}Chrome\u{0007} extension{}", "x".repeat(1_000));
        let resp = block_on(engine.handle_from(
            release_req(Some(&long), 1),
            1_200,
            Some(ReleasePeer { name: "  Grok\nBot ".into(), qid: "q".repeat(500) }),
        ));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let ev = store.lock().unwrap().records[0].release_history[0].clone();
        assert!(ev.surface.starts_with("Chrome extension"), "{:?}", ev.surface);
        assert!(!ev.surface.contains('\u{202E}') && !ev.surface.contains('\u{0007}'));
        assert_eq!(ev.surface.len(), MAX_CLIENT_NAME_BYTES);
        assert_eq!(ev.peer_name, "Grok Bot");
        assert_eq!(ev.peer_qid.len(), MAX_HISTORY_QID_BYTES);
    }

    #[test]
    fn blank_names_become_unknown_app_and_unknown_peer() {
        let store = one_alice_store();
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);
        let resp = block_on(engine.handle_from(
            release_req(Some("   \u{200B}  "), 1),
            1_200,
            Some(ReleasePeer { name: " \t ".into(), qid: "abc".into() }),
        ));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let ev = store.lock().unwrap().records[0].release_history[0].clone();
        assert_eq!(ev.surface, "Unknown app");
        assert_eq!(ev.peer_name, "Unknown peer");
        assert_eq!(ev.peer_qid, "abc");
    }

    #[test]
    fn replayed_nonce_and_unknown_username_record_nothing() {
        let store = one_alice_store();
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);
        assert!(matches!(
            block_on(engine.handle_from(release_req(Some("Chrome extension"), 1), 1_200, peer("Grok Bot"))),
            Response::Ok { .. }
        ));
        // Same nonce again: refused before approval, nothing new recorded.
        assert!(matches!(
            block_on(engine.handle_from(release_req(Some("Chrome extension"), 1), 1_300, peer("Grok Bot"))),
            Response::Err { .. }
        ));
        // Username the vault does not hold.
        let mut bad = release_req(Some("Chrome extension"), 2);
        if let Method::ReleaseCredential(p) = &mut bad.method {
            p.username_hint = Some("mallory".into());
        }
        assert!(matches!(block_on(engine.handle_from(bad, 1_400, peer("Grok Bot"))), Response::Err { .. }));
        assert_eq!(store.lock().unwrap().records[0].release_history.len(), 1);
    }

    #[test]
    fn a_failed_save_does_not_take_back_a_release_the_user_approved() {
        let store = one_alice_store();
        let saves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = saves.clone();
        let engine = Engine::new(
            store.clone(),
            Arc::new(AutoApprove),
            EngineConfig::default(),
            Arc::new(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(PersistError)
            }),
        );
        let _host = establish(&engine);
        let resp = block_on(engine.handle_from(release_req(Some("Chrome extension"), 1), 1_200, peer("Grok Bot")));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 1, "release must ask to persist once");
        assert_eq!(store.lock().unwrap().records[0].release_history.len(), 1);
    }

    #[test]
    fn rejected_and_timed_out_releases_never_ask_to_persist() {
        struct Fixed(ApprovalDecision);
        #[async_trait::async_trait]
        impl crate::approval::Approver for Fixed {
            async fn request(&self, _req: crate::approval::ApprovalRequest) -> ApprovalDecision {
                self.0
            }
        }
        for decision in [ApprovalDecision::Reject, ApprovalDecision::Timeout] {
            let store = one_alice_store();
            let saves = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counter = saves.clone();
            let engine = Engine::new(
                store.clone(),
                Arc::new(Fixed(decision)),
                EngineConfig::default(),
                Arc::new(move || {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                }),
            );
            let _host = establish(&engine);
            let resp = block_on(engine.handle_from(release_req(Some("Chrome extension"), 1), 1_200, peer("Grok Bot")));
            assert!(matches!(resp, Response::Err { .. }));
            assert_eq!(saves.load(std::sync::atomic::Ordering::SeqCst), 0, "{decision:?}");
            let rec = store.lock().unwrap().records[0].clone();
            assert!(rec.release_history.is_empty(), "{decision:?}");
            assert_eq!(rec.last_used_at, rec.created_at, "{decision:?}");
        }
    }

    #[test]
    fn the_password_never_appears_in_the_stored_history() {
        let store = one_alice_store();
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);
        block_on(engine.handle_from(release_req(Some("Chrome extension"), 1), 1_200, peer("Grok Bot")));
        let json = serde_json::to_string(&store.lock().unwrap().records[0].release_history).unwrap();
        assert!(!json.contains("secret"));
    }

    #[test]
    fn history_stays_at_fifty_through_the_engine() {
        let store = one_alice_store();
        let engine = Engine::new_in_memory(store.clone(), Arc::new(AutoApprove), EngineConfig::default());
        let _host = establish(&engine);
        for nonce in 1..=60u64 {
            let resp = block_on(engine.handle_from(
                release_req(Some("Chrome extension"), nonce),
                1_000 + nonce,
                peer("Grok Bot"),
            ));
            assert!(matches!(resp, Response::Ok { .. }), "nonce {nonce}: {resp:?}");
        }
        let rec = store.lock().unwrap().records[0].clone();
        assert_eq!(rec.release_history.len(), crate::record::MAX_RELEASE_HISTORY);
        // Entries are stamped in whole seconds from the request time.
        assert!(rec.release_history.windows(2).all(|w| w[0].released_at <= w[1].released_at));
    }
}
