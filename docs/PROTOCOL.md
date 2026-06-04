# Vaults Bridge - Wire Protocol

Status: v0.1 draft. Normative for the browser extension and the KeyOS
app. Both sides implement this with types from
`vaults-bridge-protocol`.

## Layers

1. **Transport.** WebUSB vendor-class interface (class/subclass/protocol
   `0xFF/0xFF/0xFF`), two 64-byte interrupt endpoints. Same shape as
   nostr-signer 1.3.
2. **Framing.** Newline-delimited JSON. Each request/response is one
   `\n`-terminated UTF-8 JSON object. Aligns with the Nostr Signer's
   WebUSB transport so Prime's `os/usbdev` facility is exercised the
   same way by both apps. See
   [`vaults-bridge-protocol::frame`].
3. **Messages.** JSON request/response. See
   [`vaults-bridge-protocol::message`].

## Transport

- USB vendor-class interface, registered by `gui-app-passwords` while
  the app is open and deregistered when it is hidden.
- WebUSB + MS OS 2.0 Platform Capability descriptors (BOS) so Chromium
  picks the device up via `navigator.usb.requestDevice` without driver
  install on macOS / Linux. Windows auto-bind via the MS OS 2.0
  descriptor *set* is a known gap (descriptor *capability* is
  exposed; Zadig is the workaround until the set lands).
- Coexistence with FIDO HID and (future) Nostr Signer's vendor
  interface: KeyOS is a one-foreground-app system, so Vaults Bridge's
  interface never competes with Nostr Signer's at runtime.

## Framing

Every payload is a UTF-8 JSON object terminated by exactly one `\n`.
The receiver accumulates bytes from the IN endpoint into a line buffer,
splits on `\n`, and parses each non-empty line as a JSON message. The
host writes payloads to the OUT endpoint in 64-byte chunks (matching
the interrupt endpoint max packet size).

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
| `release_credential` | `{ "origin": "<strict>", "username_hint": "<opt>", "request_nonce": <u64> }` | `{ "username": "...", "password_sealed": "<hex>" }` |
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

`release_credential.origin` is a strict origin string: scheme + host +
explicit non-default port (no path, no query, no userinfo). Match is
byte-for-byte after normalisation
(`vaults_bridge_core::origin::Origin::parse`). v1 explicitly does NOT
do fuzzy subdomain matching.

The browser extension's background worker derives the requesting tab's
origin via `sender.tab.url`, never trusting the content script. A
request where `tab origin != params.origin` is dropped before the
native USB call. See
`browser-extension/background.js` (the security gate at the top of
the message router).

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
| 99 | `internal` | Unexpected device-side failure. |
