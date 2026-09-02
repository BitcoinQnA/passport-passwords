# Vaults Bridge - Wire Protocol

Status: v0.1 draft. Normative for the browser extension and the KeyOS
app. Both sides implement this with types from
`vaults-bridge-protocol`.

## Layers

1. **Transport.** WebSocket in the hosted simulator. The planned hardware route
   is QLv2 over KeyOS's shared USB transport; see
   [`QLV2-MIGRATION.md`](QLV2-MIGRATION.md).
2. **Framing.** Newline-delimited JSON. Each request/response is one
   `\n`-terminated UTF-8 JSON object. See
   [`vaults-bridge-protocol::frame`]. A QLv2 adapter may carry each JSON object
   as a message without exposing raw USB endpoints to the app.
3. **Messages.** JSON request/response. See
   [`vaults-bridge-protocol::message`].

## Transport

- The simulator listens on `ws://127.0.0.1:9876`.
- The Foundation SDK 1.0 hardware app is local-only and requests no raw USB
  permission.
- The future QLv2 adapter must preserve request boundaries, return responses to
  the originating browser session, and disconnect cleanly when the app closes.
- Transport code must not supply the website origin. The extension derives it
  from the requesting tab before constructing the protocol request.

## Framing

Every stream payload is a UTF-8 JSON object terminated by exactly one `\n`.
The receiver accumulates bytes into a line buffer, splits on `\n`, and parses
each non-empty line as a JSON message. Message-oriented transports may carry
one JSON object per message and use the same parser at the adapter boundary.

Implementation: `vaults_bridge_protocol::frame` (`fn frame`,
`struct LineSplitter`).

A line longer than 16 KiB is rejected; in practice Vaults Bridge
messages are well under 1 KiB.

## Messages

Envelope:

```
Request  = { "id": "...", "method": "<name>", "params": { ... } }
Response = { "id": "...", "result": { ... } }
         | { "id": "...", "error": { "code": int, "message": str } }
```

`id` is echoed verbatim in the response.

### Methods (v1 PoC)

| Method | Params | Result |
|---|---|---|
| `ping` | - | `{ "pong": true }` |
| `establish_session` | `{ "host_pubkey": "<hex>" }` | `{ "device_pubkey": "<hex>" }` |
| `list_origins` | - | `{ "origins": ["https://..."] }` |
| `list_credentials` | `{ "origin": "<strict>" }` | `{ "credentials": [{ "username": "...", "label": "...", "last_used_at": 0 }] }` |
| `release_credential` | `{ "origin": "<strict>", "username_hint": "<opt>", "request_nonce": <u64> }` | `{ "username": "...", "password_sealed": "<hex>" }` |
| `store_credential` | `{ "origin": "<strict>", "username": "...", "label": "<opt>", "password_sealed": "<hex>", "request_nonce": <u64> }` | `{ "action": "saved" \| "updated" \| "restored_and_updated" }` |
| `generate_password` | `{ "origin": "<strict>", "username": "...", "label": "<opt>", "length": "<opt>", "charset": "<opt>", "request_nonce": <u64> }` | `{ "password_sealed": "<hex>", "action": "saved" \| "updated" \| "restored_and_updated" }` |
| `cancel` | - | `{}` |

### Session

- `establish_session` performs an X25519 ECDH between an ephemeral host
  key and an ephemeral device key.
- The shared secret is HKDF-SHA256-expanded with info string
  `"vaults-bridge v1 session"` (empty salt) to derive a 32-byte
  AES-256-GCM key.
- `release_credential.password_sealed` is `iv || ciphertext_with_tag`,
  hex-encoded, encrypted under the session key (12-byte AES-GCM IV,
  16-byte tag appended to the ciphertext).
- AES-256-GCM (rather than ChaCha20-Poly1305) so the host-side browser
  extension can decrypt with WebCrypto's `AES-GCM` and `X25519`
  natively, no vendored JS crypto needed. AES-GCM is also what the
  on-device keystore-at-rest uses, so the app exercises one AEAD.
- The session lives for a configurable idle timeout (default 15 min).
  On expiry the device responds `session_expired` to the next request
  and the host re-handshakes.
- `request_nonce` is a host-side monotonic counter. The device rejects
  duplicates within a session.

### Origin coupling

Origins are strict origin strings: scheme + host + explicit non-default
port (no path, no query, no userinfo). Match is byte-for-byte after
normalisation (`vaults_bridge_core::origin::Origin::parse`). Public builds
do exact-origin matching: a credential saved for `https://github.com` does
not fill `https://gist.github.com` unless the user stores that origin too.

The browser extension's background worker derives the requesting tab's
origin via `sender.tab.url` for content-script requests and from the
active tab for popup requests. The page and content script never get to
choose the origin sent over USB. See `extension/background.js` (the
security gate at the top of the message router).

If more than one credential matches an origin, hosts should call
`list_credentials` and pass the selected `username` back as
`release_credential.username_hint`. A release request without a username
hint fails with `multiple_matches` when there is more than one matching
credential, so the host cannot silently choose the wrong account.

### Backups

The keystore crate supports portable encrypted backups with
`Keystore::export_backup(passphrase)` and
`Keystore::open_backup(master, passphrase, backup)`, plus
`Keystore::records_from_backup(passphrase, backup)` for an already-open app
vault. Backup files are JSON envelopes containing a PBKDF2-HMAC-SHA256
salt/iteration count and an AES-256-GCM ciphertext over the credential records.
The backup passphrase is independent of the device seed, so a backup can restore
to replacement hardware if the user kept the passphrase. The KeyOS UI stages
restore records, shows the count, and lets the user skip duplicates, replace
existing records, or keep both before commit.

### Error codes

| Code | Name | Meaning |
|---|---|---|
| 1 | `invalid_request` | Bad JSON, unknown fields. |
| 2 | `unknown_method` | Unrecognised method. |
| 3 | `unknown_origin` | No record matches the requested origin. |
| 4 | `user_rejected` | User declined the on-device approval. |
| 5 | `timeout` | User did not respond in time. |
| 6 | `not_unlocked` | Device locked; user must enter PIN. |
| 7 | `session_expired` | Session idle timer fired; re-handshake. |
| 8 | `nonce_reused` | Replay rejected. |
| 9 | `bad_policy` | Password generation policy is invalid. |
| 10 | `multiple_matches` | More than one credential matches; choose an account. |
| 99 | `internal` | Unexpected device-side failure. |
