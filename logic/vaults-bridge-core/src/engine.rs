// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Protocol engine: routes parsed `Request`s to the credential store +
//! approver + session and returns a `Response`. Generic over the
//! `CredentialStore` so the core crate stays free of any storage dep.

use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};
use vaults_bridge_protocol::{
    CharsetHint, CredentialSummary as WireCredentialSummary, ErrorCode, ErrorPayload, EstablishSessionParams,
    EstablishSessionResult, GeneratePasswordParams, GeneratePasswordResult, ListCredentialsParams,
    ListCredentialsResult, ListOriginsResult, Method, ReleaseCredentialParams, ReleaseCredentialResult,
    Request, Response, ResponseBody, StoreAction, StoreCredentialParams, StoreCredentialResult,
};
use zeroize::Zeroizing;

use crate::{
    approval::{ApprovalAction, ApprovalDecision, ApprovalRequest, ArcApprover},
    origin::Origin,
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

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub idle_ms: u64,
}

impl Default for EngineConfig {
    fn default() -> Self { Self { idle_ms: DEFAULT_IDLE_MS } }
}

/// Returned by an `OnWriteHook` when persistence fails. Engine maps this
/// to `ErrorCode::Internal` so the host knows the mutation didn't actually
/// reach disk and can refuse to surface "Saved" UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistError;

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("persist failed") }
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
        Self { store, session: Mutex::new(Session::new()), approver, cfg, on_write }
    }

    /// Convenience for tests: no-op `on_write` hook.
    pub fn new_in_memory(store: Arc<Mutex<S>>, approver: ArcApprover, cfg: EngineConfig) -> Self {
        Self::new(store, approver, cfg, Arc::new(|| Ok(())))
    }

    pub async fn handle(&self, req: Request, now_ms: u64) -> Response {
        let id = req.id.clone();
        match self.dispatch(req, now_ms).await {
            Ok(body) => Response::Ok { id, result: body },
            Err((code, message)) => Response::Err { id, error: ErrorPayload { code: code as i32, message } },
        }
    }

    async fn dispatch(&self, req: Request, now_ms: u64) -> Result<ResponseBody, (ErrorCode, String)> {
        match req.method {
            Method::Ping => Ok(ResponseBody::Pong { pong: true }),

            Method::EstablishSession(EstablishSessionParams { host_pubkey }) => {
                let mut s = self.session.lock().unwrap();
                let device_pubkey = s.accept(&host_pubkey, SESSION_INFO, now_ms).map_err(map_session_err)?;
                Ok(ResponseBody::EstablishSession(EstablishSessionResult { device_pubkey }))
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
                    b.last_used_at.cmp(&a.last_used_at).then_with(|| a.username.cmp(&b.username))
                });
                Ok(ResponseBody::ListCredentials(ListCredentialsResult { credentials }))
            }

            Method::ReleaseCredential(ReleaseCredentialParams { origin, username_hint, request_nonce }) => {
                self.handle_release(origin, username_hint, request_nonce, now_ms)
                    .await
                    .map(ResponseBody::ReleaseCredential)
            }

            Method::StoreCredential(p) => {
                self.handle_store(p, now_ms).await.map(ResponseBody::StoreCredential)
            }

            Method::GeneratePassword(p) => {
                self.handle_generate(p, now_ms).await.map(ResponseBody::GeneratePassword)
            }

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
        request_nonce: u64,
        now_ms: u64,
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
            let chosen =
                match &username_hint {
                    Some(h) => candidates.iter().find(|r| r.username == *h).cloned().ok_or_else(|| {
                        (ErrorCode::UnknownOrigin, "no matching username for origin".into())
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
        let password_sealed = s.seal(password_plain.as_bytes(), now_ms).map_err(map_session_err)?;

        Ok(ReleaseCredentialResult { username, password_sealed })
    }

    async fn handle_store(
        &self,
        p: StoreCredentialParams,
        now_ms: u64,
    ) -> Result<StoreCredentialResult, (ErrorCode, String)> {
        let StoreCredentialParams { origin, username, label, password_sealed, request_nonce } = p;
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
            ExistingCredential::Archived => {
                (ApprovalAction::RestoreAndUpdate, StoreAction::RestoredAndUpdated)
            }
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

        Ok(StoreCredentialResult { action: store_action })
    }

    async fn handle_generate(
        &self,
        p: GeneratePasswordParams,
        now_ms: u64,
    ) -> Result<GeneratePasswordResult, (ErrorCode, String)> {
        let GeneratePasswordParams { origin, username, label, length, charset, request_nonce } = p;
        let canonical = canonicalize_origin(&origin)?;
        if username.is_empty() {
            return Err((ErrorCode::InvalidRequest, "username is required".into()));
        }
        check_str_len("username", &username, MAX_USERNAME_BYTES)?;
        if let Some(l) = &label {
            check_str_len("label", l, MAX_LABEL_BYTES)?;
        }

        self.gate_session(request_nonce, now_ms)?;

        let len =
            length.unwrap_or(DEFAULT_GENERATED_LENGTH).clamp(MIN_GENERATED_LENGTH, MAX_GENERATED_LENGTH);
        let charset = charset.unwrap_or_default();
        if !(charset.letters || charset.digits || charset.symbols) {
            return Err((ErrorCode::BadPolicy, "at least one charset class must be enabled".into()));
        }

        // Probe existing record to label the approval card correctly.
        let existing = self.store.lock().unwrap().probe(&canonical, &username);
        let (action, store_action) = match existing {
            ExistingCredential::None => (ApprovalAction::Generate, StoreAction::Saved),
            ExistingCredential::Live => (ApprovalAction::GenerateAndUpdate, StoreAction::Updated),
            ExistingCredential::Archived => {
                (ApprovalAction::GenerateAndRestore, StoreAction::RestoredAndUpdated)
            }
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
        let password_sealed = s.seal(password.as_bytes(), now_ms).map_err(map_session_err)?;

        Ok(GeneratePasswordResult { password_sealed, action: store_action })
    }

    fn gate_session(&self, request_nonce: u64, now_ms: u64) -> Result<(), (ErrorCode, String)> {
        let mut s = self.session.lock().unwrap();
        if s.check_idle(now_ms, self.cfg.idle_ms) {
            return Err((ErrorCode::SessionExpired, "session idle timeout".into()));
        }
        s.accept_nonce(request_nonce, now_ms).map_err(map_session_err)
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
    let parsed = Origin::parse(input).map_err(|_| (ErrorCode::InvalidRequest, "invalid origin".into()))?;
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
        approval::AutoApprove,
        record::CredentialRecord,
        session::Session,
        store::{CredentialMatch, CredentialStore, CredentialSummary, ExistingCredential, StoreError},
    };

    #[derive(Default)]
    struct TestStore {
        records: Vec<CredentialRecord>,
    }

    impl CredentialStore for TestStore {
        type Snapshot = Vec<CredentialRecord>;

        fn list_origins(&self) -> Vec<String> { self.records.iter().map(|r| r.origin.clone()).collect() }

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
                .map(|r| CredentialMatch { username: r.username.clone(), password: r.password.clone() })
                .collect()
        }

        fn snapshot(&self) -> Self::Snapshot { self.records.clone() }

        fn restore_snapshot(&mut self, snapshot: Self::Snapshot) { self.records = snapshot; }

        fn probe(&self, origin: &str, username: &str) -> ExistingCredential {
            match self.records.iter().find(|r| r.origin == origin && r.username == username) {
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
        unsafe fn clone(_: *const ()) -> RawWaker { RawWaker::new(std::ptr::null(), &VTABLE) }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    fn establish(engine: &Engine<TestStore>) -> Session {
        let mut host = Session::new();
        let (host_pub, host_secret) = host.begin_host();
        let resp = block_on(engine.handle(
            Request {
                id: "hs".into(),
                method: Method::EstablishSession(EstablishSessionParams {
                    host_pubkey: hex::encode(host_pub),
                }),
            },
            1_000,
        ));
        let Response::Ok { result: ResponseBody::EstablishSession(result), .. } = resp else {
            panic!("handshake failed");
        };
        host.complete_host(host_secret, &result.device_pubkey, SESSION_INFO, 1_000).unwrap();
        host
    }

    #[test]
    fn generate_respects_charset_letters_only() {
        let pw = generate_password(32, &CharsetHint { letters: true, digits: false, symbols: false });
        assert_eq!(pw.len(), 32);
        assert!(pw.chars().all(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn generate_respects_charset_digits_only() {
        let pw = generate_password(16, &CharsetHint { letters: false, digits: true, symbols: false });
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
        let pw = generate_password(24, &CharsetHint { letters: false, digits: false, symbols: false });
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
}
