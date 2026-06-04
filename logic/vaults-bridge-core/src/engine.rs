// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Protocol engine: routes parsed `Request`s to the credential store +
//! approver + session and returns a `Response`. Generic over the
//! `CredentialStore` so the core crate stays free of any storage dep.

use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};
use vaults_bridge_protocol::{
    CharsetHint, ErrorCode, ErrorPayload, EstablishSessionParams, EstablishSessionResult,
    GeneratePasswordParams, GeneratePasswordResult, ListOriginsResult, Method,
    ReleaseCredentialParams, ReleaseCredentialResult, Request, Response, ResponseBody, StoreAction,
    StoreCredentialParams, StoreCredentialResult,
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
        let id = req.id.clone();
        match self.dispatch(req, now_ms).await {
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

            Method::ReleaseCredential(ReleaseCredentialParams {
                origin,
                username_hint,
                request_nonce,
            }) => self
                .handle_release(origin, username_hint, request_nonce, now_ms)
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
            let chosen = match &username_hint {
                Some(h) => candidates
                    .iter()
                    .find(|r| r.username == *h)
                    .cloned()
                    .unwrap_or_else(|| candidates[0].clone()),
                None => candidates[0].clone(),
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

        let mut s = self.session.lock().unwrap();
        let password_sealed = s
            .seal(password_plain.as_bytes(), now_ms)
            .map_err(map_session_err)?;

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

        self.store
            .lock()
            .unwrap()
            .upsert(canonical, username, (*password_plain).clone(), label)
            .map_err(|_| (ErrorCode::Internal, "store backend".into()))?;

        // Persistence MUST succeed before we tell the host "saved".
        // Otherwise the user's UI says "Saved" but a power-cycle reveals
        // the credential never reached disk.
        (self.on_write)().map_err(|_| (ErrorCode::Internal, "persist failed".into()))?;

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

        let password = Zeroizing::new(generate_password(len as usize, &charset));

        self.store
            .lock()
            .unwrap()
            .upsert(canonical, username, (*password).clone(), label)
            .map_err(|_| (ErrorCode::Internal, "store backend".into()))?;

        (self.on_write)().map_err(|_| (ErrorCode::Internal, "persist failed".into()))?;

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
    if hint.letters {
        alphabet.extend(b'a'..=b'z');
        alphabet.extend(b'A'..=b'Z');
    }
    if hint.digits {
        alphabet.extend(b'0'..=b'9');
    }
    if hint.symbols {
        // Common symbols accepted by most password forms. Excludes
        // backtick, backslash, quote, and space which trip up parsers.
        alphabet.extend_from_slice(b"!@#$%^&*()-_=+[]{};:,.<>/?");
    }
    let n = alphabet.len() as u32;
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        OsRng.fill_bytes(&mut buf);
        for &b in buf.iter() {
            // Reject samples that would bias the distribution: 256 % n
            // samples at the top of the byte range get discarded.
            let limit: u32 = (256 - (256 % n)) as u32;
            if (b as u32) >= limit {
                continue;
            }
            let idx = (b as u32) % n;
            out.push(alphabet[idx as usize] as char);
            if out.len() == len {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
}