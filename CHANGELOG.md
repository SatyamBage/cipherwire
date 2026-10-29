# Changelog

All notable changes are documented here. This project uses semantic versioning for tagged releases.

## [2.0.0] - 2026-10-30

### Security

- Replaced the insecure v1 demo protocol with signed v2 envelopes.
- Added separate RSA-3072 signing and encryption identities.
- Added RSA-PSS-SHA256 sender signatures and RSA-OAEP-SHA256 key wrapping.
- Added AES-256-GCM with a fresh key and nonce per message.
- Added strict canonical base64 validation in the relay, CLI, and browser. This closes the browser replay-cache bypass caused by alternate base64 spellings.
- Added persisted replay caches and bounded caches in both clients.
- Added peer public-key pinning with key-change rejection and manual fingerprint verification.
- Added browser RSA key-size and exponent validation.
- Added terminal control/bidirectional-character escaping to the CLI.
- Added connection, identity, frame, directory, peer, conversation, and queue limits.
- Added chunked directory delivery so large rooms cannot exceed the WebSocket frame limit.
- Added origin allow-listing, CSP, and hardening headers.
- Disabled WebSocket compression and made loopback binding the default.
- Added relay rate-limit notice throttling to avoid error amplification.
- Removed the legacy `.save` key script and expanded `.gitignore`.

### Added

- Shared `protocol.py` wire-format module.
- Browser client with IndexedDB key storage and `textContent`-only rendering.
- Static CSS, favicon, and separate-static-hosting support.
- Unit tests for canonicalization, replay, key validation, pinning, and crypto errors.
- Live relay handshake and delivery integration test.
- CI workflow, Dependabot config, security policy, threat model, protocol docs, and AWS EC2/Caddy deployment files.
- Apache-2.0 license and NOTICE.

### Changed

- Project name and UI branding to Cipherwire.
- Browser storage names moved to `cipherwire-v2`.
- Default relay bind address is `127.0.0.1`; use Caddy or set `CHAT_HOST` explicitly.
- CLI uses a daemon stdin reader so disconnects do not hang.

### Removed

- v1 plaintext demo mode, full-packet logging, and legacy key generation. The old code remains only in git history and is explicitly unsupported.
