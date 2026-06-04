// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Keystore persistence.
//!
//! On Xous we store the encrypted blob via `FileBacked<Vec<u8>, Perms>`
//! at `fs::Location::AppData` — the same machinery every other shipping
//! KeyOS app uses (nostr-signer, etc). FileBacked handles the atomic
//! new/old/rename dance so a crash mid-write can't corrupt the keystore.
//!
//! On the hosted simulator we keep a std::fs layout under
//! `~/.passport-passwords/` so dev state on macOS round-trips across
//! `cargo run`s.

use vaults_bridge_keystore::Keystore;

// -----------------------------------------------------------------------
// On-device: FileBacked at Location::AppData
// -----------------------------------------------------------------------

#[cfg(target_os = "xous")]
mod imp {
    use file_backed::FileBacked;
    use vaults_bridge_keystore::Keystore;

    fs::use_api!();

    const KEYS_FILE: &str = "passwords.bin";

    type Perms = fs_permissions::FileSystemPermissions;

    pub struct KeystoreStore {
        backing: FileBacked<Vec<u8>, Perms>,
    }

    impl KeystoreStore {
        pub fn open() -> Self {
            let (backing, _restored) = FileBacked::new(KEYS_FILE, fs::Location::AppData);
            Self { backing }
        }

        pub fn bytes(&self) -> &[u8] { self.backing.as_slice() }

        /// Replace the on-disk blob. FileBacked's guard pattern writes
        /// immediately when the guard drops, atomically.
        pub fn write(&mut self, bytes: Vec<u8>) -> anyhow::Result<()> {
            let mut guard = self.backing.guard();
            *guard = bytes;
            Ok(())
        }
    }

    pub fn load_keystore(store: &KeystoreStore, master: &[u8; 32]) -> anyhow::Result<Keystore> {
        let bytes = store.bytes();
        if bytes.is_empty() {
            Ok(Keystore::new(master))
        } else {
            Keystore::open(master, bytes).map_err(|e| anyhow::anyhow!("{e}"))
        }
    }
}

// -----------------------------------------------------------------------
// Hosted simulator: std::fs under ~/.passport-passwords/
// -----------------------------------------------------------------------

#[cfg(not(target_os = "xous"))]
mod imp {
    use std::path::PathBuf;

    use vaults_bridge_keystore::Keystore;

    const DATA_SUBDIR: &str = ".passport-passwords";
    const KEYS_FILE: &str = "passwords.bin";

    fn data_dir() -> PathBuf {
        dirs::home_dir().map(|h| h.join(DATA_SUBDIR)).unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push(DATA_SUBDIR);
            p
        })
    }

    fn keys_path() -> PathBuf { data_dir().join(KEYS_FILE) }

    pub struct KeystoreStore;

    impl KeystoreStore {
        pub fn open() -> Self {
            let _ = std::fs::create_dir_all(data_dir());
            Self
        }

        pub fn write(&mut self, bytes: Vec<u8>) -> anyhow::Result<()> {
            use std::io::Write;
            std::fs::create_dir_all(data_dir())?;
            let path = keys_path();
            let tmp = path.with_extension("new");
            // Atomic rename: write tmp, fsync, then rename. Mirrors what
            // FileBacked does on-device.
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &path)?;
            Ok(())
        }
    }

    pub fn load_keystore(_store: &KeystoreStore, master: &[u8; 32]) -> anyhow::Result<Keystore> {
        let path = keys_path();
        if path.exists() {
            let bytes = std::fs::read(&path)?;
            Keystore::open(master, &bytes).map_err(|e| anyhow::anyhow!("{e}"))
        } else {
            Ok(Keystore::new(master))
        }
    }
}

pub use imp::{load_keystore, KeystoreStore};

#[allow(dead_code)]
type _Unused = Keystore;
