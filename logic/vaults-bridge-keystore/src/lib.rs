// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Encrypted-at-rest credential storage.
//!
//! Layout: a single JSON blob containing a vector of records, sealed with
//! AES-256-GCM under a key derived via HKDF-SHA256 from a master secret. On
//! Prime that master is `security.app_seed()`; in tests and the simulator it
//! is supplied directly.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use vaults_bridge_core::{
    store::{CredentialMatch, CredentialSummary, ExistingCredential, StoreError},
    CredentialRecord, CredentialStore,
};
use zeroize::Zeroize;

const KEY_INFO: &[u8] = b"vaults-bridge keystore v1";
const BACKUP_MAGIC: &str = "vaults-bridge-backup";
const BACKUP_VERSION: u8 = 1;
const BACKUP_KDF_ITERATIONS: u32 = 200_000;
const BACKUP_SALT_BYTES: usize = 16;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct BackupFile {
    magic: String,
    version: u8,
    kdf: String,
    iterations: u32,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

/// One credential coming in from a bulk-import parser. We avoid taking
/// `vaults_bridge_import::ImportedRecord` directly here so the keystore
/// crate doesn't depend on the import crate.
pub struct ImportItem {
    pub origin: String,
    pub username: String,
    pub password: String,
    pub label: String,
    pub notes: String,
}

/// What to do when an incoming record matches an existing one on
/// `(origin, username)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportPolicy {
    /// Default: leave the existing record alone, drop the import.
    Skip,
    /// Overwrite password, label, notes on the matching record. Restores
    /// archived records to the live list.
    Replace,
    /// Insert the import alongside the existing record. The label is
    /// suffixed with " (imported)" so the user can disambiguate.
    KeepBoth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped: usize,
    pub replaced: usize,
}

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("seal failed")]
    SealFailed,
    #[error("open failed (wrong master or corrupt blob)")]
    OpenFailed,
    #[error("not found")]
    NotFound,
    #[error("not archived (delete only allowed on archived)")]
    NotArchived,
    #[error("backup passphrase is required")]
    BackupPassphraseRequired,
    #[error("backup format is not supported")]
    BackupUnsupported,
    #[error("backup is malformed")]
    BackupMalformed,
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

pub struct Keystore {
    records: Vec<CredentialRecord>,
    key: [u8; 32],
}

impl Keystore {
    pub fn new(master: &[u8]) -> Self {
        Self {
            records: Vec::new(),
            key: derive_key(master),
        }
    }

    pub fn open(master: &[u8], sealed: &[u8]) -> Result<Self, KeystoreError> {
        let key = derive_key(master);
        let raw = unseal(&key, sealed)?;
        let records: Vec<CredentialRecord> = serde_json::from_slice(&raw)?;
        Ok(Self { records, key })
    }

    pub fn seal(&self) -> Result<Vec<u8>, KeystoreError> {
        let raw = serde_json::to_vec(&self.records)?;
        seal(&self.key, &raw)
    }

    /// Export a portable encrypted backup. The backup is encrypted with a
    /// passphrase-derived key, not the device seed, so it can be restored
    /// onto replacement hardware if the user kept the passphrase.
    pub fn export_backup(&self, passphrase: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        if passphrase.is_empty() {
            return Err(KeystoreError::BackupPassphraseRequired);
        }
        let raw = serde_json::to_vec(&self.records)?;
        let mut salt = [0u8; BACKUP_SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let key = derive_backup_key(passphrase, &salt, BACKUP_KDF_ITERATIONS)?;
        let sealed = seal(&key, &raw)?;
        let (nonce, ciphertext) = sealed.split_at(12);
        let backup = BackupFile {
            magic: BACKUP_MAGIC.to_string(),
            version: BACKUP_VERSION,
            kdf: "pbkdf2-hmac-sha256".to_string(),
            iterations: BACKUP_KDF_ITERATIONS,
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        };
        serde_json::to_vec(&backup).map_err(KeystoreError::from)
    }

    /// Restore a portable backup into a new keystore under this device's
    /// master secret.
    pub fn open_backup(
        master: &[u8],
        passphrase: &[u8],
        backup: &[u8],
    ) -> Result<Self, KeystoreError> {
        let records = Self::records_from_backup(passphrase, backup)?;
        Ok(Self {
            records,
            key: derive_key(master),
        })
    }

    /// Decrypt a portable backup into credential records. The caller can then
    /// either inspect the count before restore or install the records into an
    /// already-open keystore, preserving that keystore's current device key.
    pub fn records_from_backup(
        passphrase: &[u8],
        backup: &[u8],
    ) -> Result<Vec<CredentialRecord>, KeystoreError> {
        if passphrase.is_empty() {
            return Err(KeystoreError::BackupPassphraseRequired);
        }
        let file: BackupFile = serde_json::from_slice(backup)?;
        if file.magic != BACKUP_MAGIC
            || file.version != BACKUP_VERSION
            || file.kdf != "pbkdf2-hmac-sha256"
            || file.iterations != BACKUP_KDF_ITERATIONS
        {
            return Err(KeystoreError::BackupUnsupported);
        }
        let salt = hex::decode(file.salt_hex).map_err(|_| KeystoreError::BackupMalformed)?;
        if salt.len() != BACKUP_SALT_BYTES {
            return Err(KeystoreError::BackupMalformed);
        }
        let nonce = hex::decode(file.nonce_hex).map_err(|_| KeystoreError::BackupMalformed)?;
        if nonce.len() != 12 {
            return Err(KeystoreError::BackupMalformed);
        }
        let ciphertext =
            hex::decode(file.ciphertext_hex).map_err(|_| KeystoreError::BackupMalformed)?;
        let key = derive_backup_key(passphrase, &salt, file.iterations)?;
        let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        let raw = unseal(&key, &sealed)?;
        serde_json::from_slice(&raw).map_err(KeystoreError::from)
    }

    /// Replace all records in this open keystore. The encryption key stays the
    /// current device key, so the next `seal()` writes a device-bound vault.
    pub fn replace_records(&mut self, records: Vec<CredentialRecord>) {
        self.records = records;
    }

    pub fn records(&self) -> &[CredentialRecord] {
        &self.records
    }

    /// Clone the in-memory records so a caller can roll back a batch
    /// mutation if the subsequent encrypted persistence write fails.
    pub fn snapshot(&self) -> Vec<CredentialRecord> {
        self.records.clone()
    }

    pub fn restore_snapshot(&mut self, records: Vec<CredentialRecord>) {
        self.records = records;
    }

    pub fn add(&mut self, r: CredentialRecord) {
        self.records.push(r);
    }

    pub fn get(&self, id: Uuid) -> Option<&CredentialRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    /// Update label, color, username, password (origin and id stay).
    pub fn edit(
        &mut self,
        id: Uuid,
        label: String,
        color: i32,
        username: String,
        password: String,
    ) -> Result<(), KeystoreError> {
        let rec = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(KeystoreError::NotFound)?;
        rec.label = label;
        rec.color = color;
        rec.username = username;
        rec.password = password;
        Ok(())
    }

    pub fn set_archived(&mut self, id: Uuid, archived: bool) -> Result<(), KeystoreError> {
        let rec = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(KeystoreError::NotFound)?;
        rec.archived = archived;
        Ok(())
    }

    pub fn set_color(&mut self, id: Uuid, color: i32) -> Result<(), KeystoreError> {
        let rec = self
            .records
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(KeystoreError::NotFound)?;
        rec.color = color;
        Ok(())
    }

    /// Bulk-insert imported credentials with a user-selected conflict
    /// policy. Returns per-bucket counts. One persist call upstream
    /// covers the whole batch — callers must trigger their `on_write`
    /// after this returns.
    pub fn import_many(&mut self, items: Vec<ImportItem>, policy: ImportPolicy) -> ImportSummary {
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut replaced = 0usize;
        for item in items {
            let pos = self
                .records
                .iter()
                .position(|r| r.origin == item.origin && r.username == item.username);
            match (pos, policy) {
                (Some(_), ImportPolicy::Skip) => {
                    skipped += 1;
                }
                (Some(idx), ImportPolicy::Replace) => {
                    let rec = &mut self.records[idx];
                    rec.password = item.password;
                    if !item.label.is_empty() {
                        rec.label = item.label;
                    }
                    if !item.notes.is_empty() {
                        rec.notes = Some(item.notes);
                    }
                    rec.archived = false;
                    replaced += 1;
                }
                (Some(_), ImportPolicy::KeepBoth) => {
                    let mut rec = CredentialRecord::new(item.origin, item.username, item.password);
                    rec.label = if item.label.is_empty() {
                        String::from("(imported)")
                    } else {
                        format!("{} (imported)", item.label)
                    };
                    if !item.notes.is_empty() {
                        rec.notes = Some(item.notes);
                    }
                    self.records.push(rec);
                    imported += 1;
                }
                (None, _) => {
                    let mut rec = CredentialRecord::new(item.origin, item.username, item.password);
                    rec.label = item.label;
                    if !item.notes.is_empty() {
                        rec.notes = Some(item.notes);
                    }
                    self.records.push(rec);
                    imported += 1;
                }
            }
        }
        ImportSummary {
            imported,
            skipped,
            replaced,
        }
    }

    /// Permanent delete; only allowed on archived records.
    pub fn delete_forever(&mut self, id: Uuid) -> Result<(), KeystoreError> {
        let pos = self
            .records
            .iter()
            .position(|r| r.id == id)
            .ok_or(KeystoreError::NotFound)?;
        if !self.records[pos].archived {
            return Err(KeystoreError::NotArchived);
        }
        self.records.remove(pos);
        Ok(())
    }

    pub fn live_count(&self) -> usize {
        self.records.iter().filter(|r| !r.archived).count()
    }

    pub fn archived_count(&self) -> usize {
        self.records.iter().filter(|r| r.archived).count()
    }

    /// Records by origin, including archived (for UI display).
    pub fn find_by_origin_records(&self, origin: &str) -> Vec<&CredentialRecord> {
        self.records.iter().filter(|r| r.origin == origin).collect()
    }
}

impl CredentialStore for Keystore {
    type Snapshot = Vec<CredentialRecord>;

    fn list_origins(&self) -> Vec<String> {
        // Engine path: only LIVE credentials are exposed to the host.
        let mut s: Vec<String> = self
            .records
            .iter()
            .filter(|r| !r.archived)
            .map(|r| r.origin.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        s.sort();
        s
    }

    fn list_credentials_for_origin(&self, origin: &str) -> Vec<CredentialSummary> {
        self.records
            .iter()
            .filter(|r| !r.archived && r.origin == origin)
            .map(|r| CredentialSummary {
                username: r.username.clone(),
                label: r.label.clone(),
                last_used_at: r.last_used_at,
            })
            .collect()
    }

    fn find_by_origin(&self, origin: &str) -> Vec<CredentialMatch> {
        // Fill path is exact-origin for public release: subdomains are
        // separate sites unless the user stores a credential for each one.
        self.records
            .iter()
            .filter(|r| !r.archived && r.origin == origin)
            .map(|r| CredentialMatch {
                username: r.username.clone(),
                password: r.password.clone(),
            })
            .collect()
    }

    fn snapshot(&self) -> Self::Snapshot {
        self.snapshot()
    }

    fn restore_snapshot(&mut self, snapshot: Self::Snapshot) {
        self.restore_snapshot(snapshot);
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
        // If a record matches (origin, username) regardless of archived state,
        // update it in place and clear archived. Otherwise add a new record.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Some(rec) = self
            .records
            .iter_mut()
            .find(|r| r.origin == origin && r.username == username)
        {
            rec.password = password;
            if let Some(l) = label {
                rec.label = l;
            }
            rec.archived = false;
            rec.last_used_at = now;
            return Ok(());
        }
        let mut rec = CredentialRecord::new(origin, username, password);
        if let Some(l) = label {
            rec.label = l;
        }
        rec.last_used_at = now;
        self.records.push(rec);
        Ok(())
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn derive_key(master: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(KEY_INFO, &mut out)
        .expect("32 bytes within HKDF output limit");
    out
}

fn derive_backup_key(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; 32], KeystoreError> {
    if iterations == 0 {
        return Err(KeystoreError::BackupMalformed);
    }
    let mut u = hmac_sha256(passphrase, &[salt, &[0, 0, 0, 1]].concat())?;
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(passphrase, &u)?;
        for (dst, src) in out.iter_mut().zip(u.iter()) {
            *dst ^= *src;
        }
    }
    Ok(out)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], KeystoreError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| KeystoreError::BackupMalformed)?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| KeystoreError::SealFailed)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn unseal(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if blob.len() < 12 + 16 {
        return Err(KeystoreError::OpenFailed);
    }
    let (nonce, ct) = blob.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| KeystoreError::OpenFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_records_through_seal_open() {
        let master = b"test-master-secret-32-bytes-long_";
        let mut ks = Keystore::new(master);
        ks.add(CredentialRecord::new(
            "https://github.com".into(),
            "qna".into(),
            "hunter2".into(),
        ));
        ks.add(CredentialRecord::new(
            "https://example.com".into(),
            "alice".into(),
            "p4ssw0rd".into(),
        ));
        let blob = ks.seal().unwrap();
        let ks2 = Keystore::open(master, &blob).unwrap();
        assert_eq!(ks2.records().len(), 2);
        assert_eq!(ks2.find_by_origin_records("https://github.com").len(), 1);
        let origins = ks2.list_origins();
        assert!(origins.contains(&"https://github.com".to_string()));
        assert_eq!(ks2.find_by_origin("https://github.com").len(), 1);
    }

    #[test]
    fn fill_matches_exact_origin_only() {
        let mut ks = Keystore::new(b"test-master-secret-32-bytes-long_");
        ks.add(CredentialRecord::new(
            "https://github.com".into(),
            "qna".into(),
            "hunter2".into(),
        ));

        assert_eq!(ks.find_by_origin("https://github.com").len(), 1);
        assert_eq!(ks.find_by_origin("https://gist.github.com").len(), 0);
        assert_eq!(
            ks.find_by_origin("https://api.deeply.nested.github.com")
                .len(),
            0
        );

        // Different registrable domain -> no match.
        assert_eq!(ks.find_by_origin("https://example.com").len(), 0);
        // Suffix-injection attack -> no match.
        assert_eq!(
            ks.find_by_origin("https://attacker.github.com.evil.com")
                .len(),
            0
        );
        // Scheme mismatch -> no match.
        assert_eq!(ks.find_by_origin("http://github.com").len(), 0);
    }

    #[test]
    fn fill_keeps_port_distinction_for_ip_and_localhost() {
        let mut ks = Keystore::new(b"test-master-secret-32-bytes-long_");
        ks.add(CredentialRecord::new(
            "http://127.0.0.1:8000".into(),
            "qna".into(),
            "p".into(),
        ));
        ks.add(CredentialRecord::new(
            "http://localhost:3000".into(),
            "qna".into(),
            "p".into(),
        ));

        assert_eq!(ks.find_by_origin("http://127.0.0.1:8000").len(), 1);
        assert_eq!(ks.find_by_origin("http://127.0.0.1:9000").len(), 0);
        assert_eq!(ks.find_by_origin("http://localhost:3000").len(), 1);
        assert_eq!(ks.find_by_origin("http://localhost:4000").len(), 0);
    }

    #[test]
    fn archived_credentials_are_hidden_from_engine_lookup() {
        let master = b"test-master-32-bytes-deterministic-";
        let mut ks = Keystore::new(master);
        let r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        let id = r.id;
        ks.add(r);
        ks.set_archived(id, true).unwrap();

        // Engine path filters archived
        assert_eq!(ks.list_origins().len(), 0);
        assert_eq!(ks.find_by_origin("https://x").len(), 0);

        // UI path still sees them
        assert_eq!(ks.find_by_origin_records("https://x").len(), 1);
        assert_eq!(ks.archived_count(), 1);
        assert_eq!(ks.live_count(), 0);
    }

    #[test]
    fn delete_forever_only_works_on_archived() {
        let mut ks = Keystore::new(b"k");
        let r = CredentialRecord::new("https://x".into(), "u".into(), "p".into());
        let id = r.id;
        ks.add(r);
        assert!(matches!(
            ks.delete_forever(id),
            Err(KeystoreError::NotArchived)
        ));
        ks.set_archived(id, true).unwrap();
        ks.delete_forever(id).unwrap();
        assert!(ks.records().is_empty());
    }

    #[test]
    fn wrong_master_fails_to_open() {
        let mut ks = Keystore::new(b"correct-master");
        ks.add(CredentialRecord::new(
            "https://x".into(),
            "u".into(),
            "p".into(),
        ));
        let blob = ks.seal().unwrap();
        assert!(Keystore::open(b"wrong-master", &blob).is_err());
    }

    #[test]
    fn backup_round_trips_to_new_master() {
        let mut ks = Keystore::new(b"old-master");
        ks.add(CredentialRecord::new(
            "https://example.com".into(),
            "alice".into(),
            "p4ss".into(),
        ));

        let backup = ks.export_backup(b"correct horse battery staple").unwrap();
        let restored =
            Keystore::open_backup(b"new-master", b"correct horse battery staple", &backup).unwrap();

        assert_eq!(restored.records().len(), 1);
        assert_eq!(restored.find_by_origin("https://example.com").len(), 1);
        let resealed = restored.seal().unwrap();
        assert!(Keystore::open(b"new-master", &resealed).is_ok());
        assert!(Keystore::open(b"old-master", &resealed).is_err());
    }

    #[test]
    fn backup_rejects_wrong_passphrase() {
        let mut ks = Keystore::new(b"old-master");
        ks.add(CredentialRecord::new(
            "https://example.com".into(),
            "alice".into(),
            "p4ss".into(),
        ));

        let backup = ks.export_backup(b"right").unwrap();
        assert!(Keystore::open_backup(b"new-master", b"wrong", &backup).is_err());
    }

    #[test]
    fn backup_records_can_replace_existing_keystore() {
        let mut original = Keystore::new(b"old-master");
        original.add(CredentialRecord::new(
            "https://example.com".into(),
            "alice".into(),
            "p4ss".into(),
        ));
        let backup = original.export_backup(b"passphrase").unwrap();

        let mut current = Keystore::new(b"current-master");
        current.add(CredentialRecord::new(
            "https://old.example".into(),
            "bob".into(),
            "old".into(),
        ));
        let records = Keystore::records_from_backup(b"passphrase", &backup).unwrap();
        current.replace_records(records);

        assert_eq!(current.records().len(), 1);
        assert_eq!(current.find_by_origin("https://example.com").len(), 1);
        let resealed = current.seal().unwrap();
        assert!(Keystore::open(b"current-master", &resealed).is_ok());
        assert!(Keystore::open(b"old-master", &resealed).is_err());
    }
}
