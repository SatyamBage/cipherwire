# Threat model

Cipherwire is an experimental relayed chat system. This document states what v2 tries to protect, what it does not protect, and which assumptions must hold.

## Assets

- Message plaintext.
- Long-term signing and encryption private keys.
- The binding between a human/contact and an identity ID plus two public-key fingerprints.
- The integrity of sender attribution.
- Availability of the relay and clients.
- Metadata that the relay necessarily observes.

## Adversaries

### Passive network attacker

Can observe and record TLS traffic. Assumes certificate validation and modern TLS. Cipherwire relies on the reverse proxy or direct TLS listener for transport security.

### Active network attacker

Can block, delay, replay, reorder, or modify traffic, but cannot break TLS or the cryptographic primitives. The relay and endpoint checks must reject modified or replayed envelopes.

### Malicious or compromised relay

Controls routing, the directory it sends, online status, and delivery. It can impersonate the service, drop messages, lie about who is online, and observe metadata. It must not be able to read plaintext or forge a message attributed to a pinned sender without that sender's signing key.

### Malicious peer

Has a valid identity and can send arbitrary packets, including malformed frames, oversized fields, non-canonical base64, replayed envelopes, and terminal escape sequences. It is untrusted until fingerprints are verified.

### Local attacker

Has access to the user's device, browser profile, or unlocked CLI session. This is largely out of scope. Password-protected PEM files and browser non-extractable private keys raise the cost but do not protect against malware, memory scraping, or an unlocked session.

### Web attacker

Runs a hostile website in the user's browser and tries to open a WebSocket to the relay, exfiltrate keys, or inject script. The relay only accepts browser connections from configured `CHAT_ALLOWED_ORIGINS`; the web client uses a strict CSP and `textContent` for all peer-controlled text.

## Guarantees

- **Confidentiality against the relay and network:** message plaintext is encrypted with a fresh AES-256-GCM key per message; the key is wrapped only for the recipient's encryption public key.
- **Sender authentication:** each envelope is signed by the sender's signing key over a transcript that binds message ID, sender, recipient, wrapped key, nonce, and ciphertext.
- **Recipient binding:** the AAD includes both identity IDs; a message addressed to another identity fails decryption.
- **Replay rejection:** canonical base64 plus a persisted recent-ID cache. The cache is per identity and bounded.
- **Key-change detection:** both public-key fingerprints are pinned locally. A changed key is rejected rather than silently accepted.
- **Relay cannot inject optional fields:** it reconstructs forwarded envelopes from validated canonical fields.
- **Basic DoS resistance:** frame and field limits, connection/identity caps, handshake timeout, per-session rate limiting, bounded directory chunks, browser queue/rate limits, and bounded local caches.
- **Terminal safety:** the CLI escapes control and bidirectional formatting characters before printing peer-controlled text.

## Non-guarantees

- **No forward secrecy.** Compromise of a long-term encryption private key can decrypt captured messages whose wrapped keys are also available.
- **No post-compromise security.** A compromised key stays compromised until the identity is replaced.
- **No audit.** The design and implementation have not been independently reviewed.
- **No metadata privacy.** The relay sees identity IDs, nicknames, public keys, online status, sender/recipient routing, timing, sizes, and IP addresses. Traffic analysis is out of scope.
- **No anonymity.** Identities are stable and linkable.
- **No offline delivery or history.** If the recipient is offline, the relay returns `OFFLINE`; messages are not queued. The browser keeps only in-memory conversation text and the CLI prints messages.
- **No multi-device sync.** A browser profile and a CLI `.keys` directory are separate identities.
- **No protection from a trusted-but-malicious contact.** Verification establishes key ownership, not intent.
- **No protection from endpoint compromise.** Malware, a hostile browser extension, a keylogger, or an unlocked session can read plaintext.
- **No defense against a relay that withholds service.** Availability is a single-relay property in v2.
- **No formal verification.** The protocol is intentionally small, but it has not been modeled in a proof assistant.

## Trust assumptions

1. TLS certificate validation works, and the user reaches the intended relay.
2. The browser's WebCrypto implementation, IndexedDB, and origin isolation are sound.
3. The operating system protects the CLI process and `.keys/` permissions.
4. The user compares **both** fingerprints through a channel the adversary does not control.
5. The relay's identity registry is not rolled back or replaced by an attacker with host access. TOFU has no transparency log.
6. Python, `cryptography`, `websockets`, the browser, and Caddy are kept patched.

## Important attack scenarios

### First-contact MITM

A malicious relay can present its own keys on first contact. The user must detect this by comparing both fingerprints out of band. Without that step, the relay can read and forge messages. This is inherent to TOFU.

### Relay key substitution after pinning

The client recomputes fingerprints and compares them to local pins. A substituted signing or encryption key is rejected. If the user's local pin store is lost, the next contact is first-contact again.

### Replay after reconnect

The CLI persists recent message IDs in `.keys/seen-message-ids-v2.json`; the browser stores them in `localStorage`. Canonical base64 prevents alternate spellings of the same ID from bypassing the cache. Clearing local state reopens the replay window for messages not otherwise known.

### Malicious frame flood

The relay caps connections, frames, identities, and per-session message rate. The browser has a packet queue cap and a token bucket. A determined attacker can still consume bandwidth or CPU; there is no global distributed DoS protection.

### Terminal escape injection

A peer can put ANSI escapes, control characters, or bidirectional overrides in a message. The CLI escapes these before printing. The browser uses `textContent`, not HTML injection.

### Origin abuse

A hostile page cannot open a browser WebSocket unless its origin is in `CHAT_ALLOWED_ORIGINS`. CLI clients send no Origin and are allowed. Configure the list exactly; do not use a wildcard in production.

### Static-hosting mix-up

When the web client is hosted separately, the user must enter the relay's `wss://` URL. The default URL is derived from the page host, which is correct for relay-hosted mode but wrong for a static host until edited. The relay must allow the static origin.

## Reporting

See [SECURITY.md](../SECURITY.md). Do not test against other people's deployments or data.
