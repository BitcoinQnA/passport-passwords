// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Master-key source backed by KeyOS's `security.app_seed()`.
//!
//! On hardware the returned 32-byte secret is device-bound and only
//! accessible after PIN unlock. In hosted-mode simulators the security
//! server returns a deterministic seed from the app id; fine for dev.
//!
//! Mirrors `gui-app-nostr-signer/src/master_key.rs`. Different `KEY_INFO`
//! string gives a domain-separated key from any other app's keystore.

use zeroize::Zeroizing;

security::use_api!();

#[derive(Debug, thiserror::Error)]
pub enum MasterKeyError {
    #[error("security.app_seed() denied (not unlocked?)")]
    Denied,
}

pub struct KeyOsAppSeedSource;

impl KeyOsAppSeedSource {
    /// Wrapped in `Zeroizing` so the master is wiped when it goes out of
    /// scope. The keystore derives its disk-encryption key from this and
    /// keeps only the derived key; the master should be dropped as soon
    /// as the keystore is constructed.
    pub fn fetch(&self) -> Result<Zeroizing<[u8; 32]>, MasterKeyError> {
        let security = Security::default();
        let raw = security.app_seed().map_err(|_| MasterKeyError::Denied)?;
        Ok(Zeroizing::new(raw))
    }
}
