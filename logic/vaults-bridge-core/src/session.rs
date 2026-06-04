// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! ECDH X25519 session establishment + AES-256-GCM payload sealing.
//!
//! Lifecycle:
//!   Idle -> Handshaking -> Active -> Expired
//!
//! Active state is keyed by HKDF-SHA256 expansion of the X25519 shared
//! secret. The host and device each contribute an ephemeral keypair for
//! the handshake; private keys are zeroed on drop.
//!
//! AES-256-GCM (rather than ChaCha20-Poly1305) so the host side can
//! decrypt with WebCrypto's `AES-GCM` natively, no vendored JS crypto
//! needed. Same AEAD as the keystore-at-rest seal.
//!
//! Sessions track:
//!   - last activity (for idle-timeout)
//!   - highest accepted request nonce (for replay rejection)

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session is not active")]
    NotActive,
    #[error("invalid public key")]
    InvalidPubkey,
    #[error("seal failed")]
    SealFailed,
    #[error("open failed (likely tamper or wrong session)")]
    OpenFailed,
    #[error("hex decode failed")]
    BadHex,
    #[error("nonce reused: got {got}, last accepted {last}")]
    NonceReused { got: u64, last: u64 },
    #[error("session expired")]
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Handshaking,
    Active,
    Expired,
}

pub struct Session {
    state: SessionState,
    /// Symmetric AEAD key derived via HKDF from the X25519 shared secret.
    key: Option<[u8; 32]>,
    /// Highest accepted request nonce. Equals 0 before the first request.
    last_nonce: u64,
    /// Monotonic time of last activity (any successful seal/open or
    /// request-nonce acceptance). Source is caller-supplied; we don't
    /// pull a clock here so the crate stays platform-agnostic.
    last_activity_ms: u64,
}

impl Session {
    pub fn new() -> Self {
        Self {
            state: SessionState::Idle,
            key: None,
            last_nonce: 0,
            last_activity_ms: 0,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn last_nonce(&self) -> u64 {
        self.last_nonce
    }

    pub fn last_activity_ms(&self) -> u64 {
        self.last_activity_ms
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, SessionState::Active)
    }

    /// Device side: given the host's ephemeral pubkey, generate our own
    /// ephemeral keypair, derive the session key, and return our pubkey.
    /// `info` is the HKDF info string; pin it across host and device.
    pub fn accept(
        &mut self,
        host_pubkey_hex: &str,
        info: &[u8],
        now_ms: u64,
    ) -> Result<String, SessionError> {
        self.state = SessionState::Handshaking;
        let host_pk = parse_pubkey(host_pubkey_hex)?;
        let device_secret = EphemeralSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&device_secret);
        let shared = device_secret.diffie_hellman(&host_pk);
        // Reject all-zero shared secret: a peer who sent a low-order point
        // could otherwise force a known session key.
        if shared.as_bytes().iter().all(|b| *b == 0) {
            self.state = SessionState::Idle;
            return Err(SessionError::InvalidPubkey);
        }
        let key = derive_key(shared.as_bytes(), info);
        self.replace_key(key);
        self.last_nonce = 0;
        self.last_activity_ms = now_ms;
        self.state = SessionState::Active;
        Ok(hex::encode(device_public.as_bytes()))
    }

    /// Host side: generate our ephemeral keypair, return our pubkey for
    /// sending; once the device replies with its pubkey, call `complete_host`.
    pub fn begin_host(&mut self) -> ([u8; 32], EphemeralSecret) {
        self.state = SessionState::Handshaking;
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (*public.as_bytes(), secret)
    }

    pub fn complete_host(
        &mut self,
        secret: EphemeralSecret,
        device_pubkey_hex: &str,
        info: &[u8],
        now_ms: u64,
    ) -> Result<(), SessionError> {
        let device_pk = parse_pubkey(device_pubkey_hex)?;
        let shared = secret.diffie_hellman(&device_pk);
        if shared.as_bytes().iter().all(|b| *b == 0) {
            self.state = SessionState::Idle;
            return Err(SessionError::InvalidPubkey);
        }
        let key = derive_key(shared.as_bytes(), info);
        self.replace_key(key);
        self.last_nonce = 0;
        self.last_activity_ms = now_ms;
        self.state = SessionState::Active;
        Ok(())
    }

    /// Install a new session key, zeroizing any prior one in place rather
    /// than letting it sit on the heap until reallocated.
    fn replace_key(&mut self, key: [u8; 32]) {
        if let Some(mut old) = self.key.take() {
            old.zeroize();
        }
        self.key = Some(key);
    }

    /// Accept a request nonce. Must be strictly greater than the last
    /// accepted nonce. Touches the idle timer on success.
    pub fn accept_nonce(&mut self, nonce: u64, now_ms: u64) -> Result<(), SessionError> {
        if !matches!(self.state, SessionState::Active) {
            return Err(SessionError::NotActive);
        }
        if nonce <= self.last_nonce {
            return Err(SessionError::NonceReused {
                got: nonce,
                last: self.last_nonce,
            });
        }
        self.last_nonce = nonce;
        self.last_activity_ms = now_ms;
        Ok(())
    }

    /// Transition to Expired if the idle timer has exceeded the threshold.
    /// Returns true if the call expired the session.
    pub fn check_idle(&mut self, now_ms: u64, idle_threshold_ms: u64) -> bool {
        if !matches!(self.state, SessionState::Active) {
            return false;
        }
        if now_ms.saturating_sub(self.last_activity_ms) >= idle_threshold_ms {
            self.expire();
            return true;
        }
        false
    }

    pub fn seal(&mut self, plaintext: &[u8], now_ms: u64) -> Result<String, SessionError> {
        if !matches!(self.state, SessionState::Active) {
            return Err(SessionError::NotActive);
        }
        let key = self.key.ok_or(SessionError::NotActive)?;
        let cipher = Aes256Gcm::new((&key).into());
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SessionError::SealFailed)?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        self.last_activity_ms = now_ms;
        Ok(hex::encode(out))
    }

    pub fn open(&mut self, sealed_hex: &str, now_ms: u64) -> Result<Vec<u8>, SessionError> {
        if !matches!(self.state, SessionState::Active) {
            return Err(SessionError::NotActive);
        }
        let key = self.key.ok_or(SessionError::NotActive)?;
        let raw = hex::decode(sealed_hex).map_err(|_| SessionError::BadHex)?;
        if raw.len() < 12 + 16 {
            return Err(SessionError::OpenFailed);
        }
        let (nonce_bytes, ct) = raw.split_at(12);
        let cipher = Aes256Gcm::new((&key).into());
        let nonce = Nonce::from_slice(nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|_| SessionError::OpenFailed)?;
        self.last_activity_ms = now_ms;
        Ok(pt)
    }

    pub fn expire(&mut self) {
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }
        self.state = SessionState::Expired;
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(mut k) = self.key.take() {
            k.zeroize();
        }
    }
}

fn parse_pubkey(hex_str: &str) -> Result<PublicKey, SessionError> {
    let bytes = hex::decode(hex_str).map_err(|_| SessionError::BadHex)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| SessionError::InvalidPubkey)?;
    Ok(PublicKey::from(arr))
}

fn derive_key(shared: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 bytes is within HKDF-SHA256 output limit");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &[u8] = b"vaults-bridge v1 session";
    const IDLE_MS: u64 = 15 * 60 * 1000;

    fn handshake() -> (Session, Session) {
        let mut device = Session::new();
        let mut host = Session::new();
        let (host_pub, host_secret) = host.begin_host();
        let device_pub_hex = device.accept(&hex::encode(host_pub), INFO, 1_000).unwrap();
        host.complete_host(host_secret, &device_pub_hex, INFO, 1_000)
            .unwrap();
        (device, host)
    }

    #[test]
    fn host_and_device_round_trip_payload() {
        let (mut device, mut host) = handshake();
        let sealed = device.seal(b"hunter2", 1_500).unwrap();
        let opened = host.open(&sealed, 1_500).unwrap();
        assert_eq!(opened, b"hunter2");
    }

    #[test]
    fn nonce_must_increase_strictly() {
        let (mut device, _) = handshake();
        device.accept_nonce(1, 1_100).unwrap();
        device.accept_nonce(2, 1_200).unwrap();
        assert!(matches!(
            device.accept_nonce(2, 1_300),
            Err(SessionError::NonceReused { got: 2, last: 2 })
        ));
        assert!(matches!(
            device.accept_nonce(1, 1_300),
            Err(SessionError::NonceReused { got: 1, last: 2 })
        ));
        device.accept_nonce(3, 1_400).unwrap();
    }

    #[test]
    fn nonce_rejected_before_handshake() {
        let mut s = Session::new();
        assert_eq!(s.accept_nonce(1, 0).unwrap_err(), SessionError::NotActive);
    }

    #[test]
    fn idle_timeout_expires_session() {
        let (mut device, _) = handshake();
        assert!(!device.check_idle(2_000, IDLE_MS));
        assert_eq!(device.state(), SessionState::Active);
        let expired_at = 1_000 + IDLE_MS;
        assert!(device.check_idle(expired_at, IDLE_MS));
        assert_eq!(device.state(), SessionState::Expired);
        assert_eq!(
            device.seal(b"x", expired_at).unwrap_err(),
            SessionError::NotActive
        );
    }

    #[test]
    fn activity_extends_idle_timer() {
        let (mut device, _) = handshake();
        device.accept_nonce(1, 5_000).unwrap();
        let pre_expire = 5_000 + IDLE_MS - 1;
        assert!(!device.check_idle(pre_expire, IDLE_MS));
        let post_expire = 5_000 + IDLE_MS;
        assert!(device.check_idle(post_expire, IDLE_MS));
    }

    #[test]
    fn expire_zeroes_key_and_blocks_seal() {
        let (mut device, _) = handshake();
        device.expire();
        assert_eq!(device.state(), SessionState::Expired);
        assert!(device.seal(b"x", 0).is_err());
    }

    #[test]
    fn open_with_wrong_session_fails() {
        let (device, _) = handshake();
        let (_, mut other_host) = handshake();
        let mut device = device;
        let sealed = device.seal(b"hunter2", 1_500).unwrap();
        assert!(matches!(
            other_host.open(&sealed, 1_500),
            Err(SessionError::OpenFailed)
        ));
    }
}