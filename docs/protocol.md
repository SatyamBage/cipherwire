# Cipherwire protocol v2

This document describes the wire format implemented by `protocol.py`, `client.py`, `server.py`, and `app.js`. The relay is deliberately simple: it authenticates identities, maintains a public-key directory, and forwards signed ciphertext. All message confidentiality and sender authentication happen at the endpoints.

## Encoding rules

- JSON is UTF-8 text.
- Every binary field is **standard base64 with padding**.
- Base64 must be **canonical**: decoding and re-encoding it must produce the exact same string. Non-zero padding bits, missing padding, whitespace, and URL-safe spellings are rejected. This matters because message IDs are replay-cache keys.
- Identity IDs are 64 lowercase hexadecimal characters: `SHA-256(SPKI DER signing key)`.
- Public keys are base64 of DER `SubjectPublicKeyInfo`.
- RSA public keys must be 2048-8192 bits with public exponent 65537. The reference clients generate 3072-bit keys.
- The signing and encryption public keys of one identity must be different.

## Handshake

### 1. Server hello

```json
{"type":"HELLO","v":2,"challenge":"<base64 32 random bytes>"}
```

The challenge is fresh for every connection.

### 2. Client identify

```json
{
  "type": "IDENTIFY",
  "v": 2,
  "nickname": "Alice",
  "identity_id": "<64 hex>",
  "signing_key": "<base64 SPKI>",
  "encryption_key": "<base64 SPKI>",
  "signature": "<base64 RSA-PSS>"
}
```

The signature is RSA-PSS-SHA256 with salt length 32 over:

```text
"ZTCHAT/v2/identify\0"
|| challenge
|| identity_id bytes (32)
|| nickname UTF-8
|| SHA-256(signing_key DER)
|| SHA-256(encryption_key DER)
```

The server verifies the signature, checks `identity_id == SHA-256(signing_key DER)`, checks key sizes/exponent, and checks that the two keys differ. Nicknames are 1-32 characters from `[A-Za-z0-9_. -]`, must start with an alphanumeric, and are stripped of surrounding whitespace before signing.

An identity is bound to its first nickname and keys in the relay registry. Reconnecting with a different nickname or key is rejected. This is TOFU at the relay, not a PKI.

### 3. Authentication response

```json
{
  "type": "AUTH_OK",
  "v": 2,
  "identity_id": "<64 hex>",
  "peers": [ ...directory entries... ],
  "directory_complete": true
}
```

If the directory is large, the first chunk is in `AUTH_OK` and the rest arrive as `USER_LIST` packets. Each packet is kept well below the 64 KiB frame limit. Clients must handle multiple chunks. A peer entry is:

```json
{
  "identity_id": "<64 hex>",
  "nickname": "Bob",
  "signing_key": "<base64 SPKI>",
  "encryption_key": "<base64 SPKI>",
  "signing_fingerprint": "ABCD:EF01:...",
  "encryption_fingerprint": "1234:5678:..."
}
```

Fingerprints are the first 128 bits of SHA-256 over the DER key, displayed as eight uppercase hexadecimal groups. Clients recompute them from the keys and pin both. A changed fingerprint for an existing identity is rejected.

## Message envelope

```json
{
  "type": "MESSAGE",
  "v": 2,
  "message_id": "<base64 16 random bytes>",
  "sender_id": "<64 hex>",
  "recipient_id": "<64 hex>",
  "encrypted_key": "<base64 RSA-OAEP ciphertext>",
  "nonce": "<base64 12 random bytes>",
  "ciphertext": "<base64 AES-256-GCM ciphertext+tag>",
  "signature": "<base64 RSA-PSS>"
}
```

### Encryption

1. Generate a random 256-bit AES key and a random 96-bit nonce.
2. Wrap the AES key for the recipient's encryption key with RSA-OAEP-SHA256 and label `ZTCHAT/v2/AES-GCM`.
3. Compute the AAD:

```text
"ZTCHAT/v2/message-aad\0"
|| message_id (16)
|| sender_id bytes (32)
|| recipient_id bytes (32)
```

4. Encrypt the UTF-8 plaintext with AES-256-GCM using the nonce and AAD. The ciphertext includes the 16-byte tag.
5. Sign the transcript:

```text
"ZTCHAT/v2/message-signature\0"
|| AAD
|| SHA-256(encrypted_key)
|| nonce
|| SHA-256(ciphertext)
```

with RSA-PSS-SHA256 and salt length 32.

### Verification

A recipient must, in order:

1. Validate all base64 fields and lengths.
2. Check that `recipient_id` is its own identity.
3. Look up `sender_id` in its pinned directory and require `verified == true`.
4. Reject a `message_id` already in the replay cache.
5. Verify the sender's signature over the transcript.
6. RSA-OAEP-unwrap the AES key and require exactly 32 bytes.
7. AES-GCM-decrypt with the AAD; a tag failure is a protocol error.
8. Only then add the message ID to the replay cache and display the plaintext.

The relay performs the same structural checks and verifies the sender signature before forwarding. It rebuilds the forwarded packet from canonical decoded bytes, so unknown fields are not propagated and alternate base64 spellings cannot pass through.

## Other packets

- `LIST_USERS` (client to relay): request a fresh directory.
- `USER_LIST` (relay to client): directory chunk, with `directory_complete`.
- `USER_JOINED`: `{type, v, peer}` broadcast when a peer authenticates.
- `USER_LEFT`: `{type, v, identity_id, nickname}` broadcast on disconnect.
- `ERROR`: `{type, code, msg}`. Codes include `MALFORMED`, `AUTH_FAILED`, `IDENTIFY_TIMEOUT`, `IDENTITY_ONLINE`, `RATE_LIMIT`, `OFFLINE`, `DELIVERY_FAILED`, `UNSUPPORTED`, and `SERVER_BUSY`.

## Limits

| Limit | Value |
| --- | --- |
| WebSocket frame | 64 KiB |
| Plaintext | 32 KiB |
| AES-GCM ciphertext | 32 KiB + 16 bytes |
| RSA blob (wrapped key or signature) | 256-1024 bytes |
| RSA public key | 2048-8192 bits, exponent 65537 |
| Nickname | 1-32 ASCII characters |
| Directory chunk | 48 KiB target, below the frame limit |
| Replay cache | 4096 recent IDs per CLI/browser identity |
| Relay connections | `CHAT_MAX_CONNECTIONS` (default 256) |
| Relay identities | `CHAT_MAX_IDENTITIES` (default 10000) |

## Versioning

`v` is `2` for every packet in this document. A v3 protocol must use new domain-separation strings and packet versions; do not silently reinterpret v2 fields.

## Security notes

- v2 has no forward secrecy or post-compromise security. Long-term encryption-key compromise can expose captured ciphertext if the wrapped keys are also available.
- TOFU means the first key seen for an identity is pinned. Verify fingerprints out of band.
- The relay sees metadata and can drop, delay, or reorder packets. It cannot forge a valid message signature.
- There is no offline delivery or local history in v2.
