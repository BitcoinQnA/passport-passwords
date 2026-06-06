# Vaults Bridge Backup and Restore

Status: public-release hardening scope.

Vaults Bridge has a portable encrypted backup flow:

- `Keystore::export_backup(passphrase)` exports a JSON backup encrypted with
  AES-256-GCM.
- `Keystore::open_backup(master, passphrase, backup)` restores that backup onto
  the current device by re-sealing records under the current app seed.
- `Keystore::records_from_backup(passphrase, backup)` lets the already-open app
  decrypt a backup, show the record count, and then reseal under the current
  device key without retaining the app seed in memory.
- Backup keys are derived from the user passphrase with PBKDF2-HMAC-SHA256
  using a random salt and the iteration count recorded in the file.
- The KeyOS UI exposes export and restore from the main menu. Export asks for a
  passphrase plus confirmation, then writes `passport-passwords-backup.vbpw` to
  a selected directory. Restore asks for the passphrase, reads a selected
  `.vbpw`/`.json` backup, shows the number of passwords found, and asks how to
  handle matching site+username records before changing the current vault.

## Product Policy

- Backups are opt-in and should be shown as a high-risk action.
- The backup passphrase is unrecoverable. Foundation cannot restore a backup
  without it.
- If the device/app seed is lost and no portable backup exists, the vault is
  unrecoverable.
- Plaintext CSV export should not be part of the default public flow. If it is
  added later, it should sit behind multiple confirmations and never run over
  USB to the browser.

## UI Scope

The public UI now exposes:

- Export encrypted backup to Airlock or USB.
- Restore encrypted backup from Airlock or USB.
- Passphrase entry and confirmation on export.
- Passphrase entry on restore.
- A restore policy screen with Skip duplicates, Replace existing, and Keep both.

Restore preserves native backup metadata such as notes, color, archive state,
and timestamps. `Keep both` assigns a fresh record id and marks the restored
copy's label with `(restored)` when it conflicts with an existing login.
