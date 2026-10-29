# Cipherwire

**Experimental end-to-end encrypted chat over a minimal relay.**

Cipherwire is a small protocol-v2 relay, CLI client, and browser client. The relay forwards signed ciphertext and a public-key directory; it never receives message plaintext or private keys. Contacts are addressed by a SHA-256 identity derived from their signing key, and new contacts must be verified out of band before messages are accepted.

> [!WARNING]
> **The v1 code in this repository's git history is insecure and must not be deployed.** It had no message signatures, included a plaintext demo mode, and logged full packets. See [SECURITY-NOTICE.md](SECURITY-NOTICE.md). Any hostname committed in v1 history is retired.
>
> **v2 is experimental and has not been independently audited.** It has no forward secrecy or post-compromise security. Do not use it for life-critical, financial, or otherwise high-risk secrets.

[![CI](https://github.com/SatyamBage/cipherwire/actions/workflows/ci.yml/badge.svg)](https://github.com/SatyamBage/cipherwire/actions/workflows/ci.yml)

## What it does

- **End-to-end encryption:** a fresh AES-256-GCM key and nonce for every message.
- **Authenticated senders:** RSA-PSS-SHA256 signatures over the message ID, sender, recipient, wrapped key, nonce, and ciphertext.
- **Key wrapping:** RSA-OAEP-SHA256 with a domain-separated label.
- **Separate identities:** independent RSA-3072 signing and encryption key pairs.
- **Immutable addressing:** the identity ID is `SHA-256(SPKI signing key)`, so duplicate display names cannot collide.
- **TOFU pinning:** the CLI and browser pin both peer fingerprints and refuse a changed key. Fingerprints must be compared through another trusted channel.
- **Replay resistance:** strict canonical base64 plus a persisted recent-message-ID cache.
- **Small relay:** Python `websockets`, bounded frames, connection/identity limits, per-session rate limiting, and directory chunking so large rooms do not exceed the frame limit.
- **Two deployment modes:** the relay can serve the web client itself, or the static client can be hosted separately while connecting to a relay over `wss://`.

## Quick start

### 1. Run a relay locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# The relay serves the browser client on http://localhost:55555.
CHAT_ALLOWED_ORIGINS=http://localhost:55555 python server.py
```

Open <http://localhost:55555>. For a CLI identity in another terminal:

```bash
CHAT_ALLOW_INSECURE_LOCAL=1 CHAT_SERVER_URL=ws://localhost:55555 python client.py
```

`ws://` is accepted only for localhost and only when `CHAT_ALLOW_INSECURE_LOCAL=1` is set. Production clients require `wss://`.

### 2. Create a CLI identity

```bash
python setup_keys.py
```

The two private keys are written as password-encrypted PKCS#8 PEM files under `.keys/`. `.keys/` is ignored by git. Use a password manager and keep an offline backup; losing the keys loses the identity.

Connect to a relay:

```bash
CHAT_SERVER_URL=wss://chat.example.com python client.py
```

Useful commands: `/users`, `/trust <id-prefix>`, `@<name-or-id> <message>`, `/burn`, `/quit`.

### 3. Verify a contact

Compare **both** fingerprints shown by `/users` or the browser verification dialog through a different trusted channel (in person, a call, or a previously verified account). Then run `/trust <id-prefix>` in the CLI, or confirm the checkbox in the browser. A display name alone is never proof of identity.

## Security properties

| Property | v2 |
| --- | --- |
| Message confidentiality | AES-256-GCM per message |
| Sender authentication | RSA-PSS-SHA256 over a domain-separated transcript |
| Key agreement | RSA-OAEP-SHA256 wrapping of a random 256-bit key |
| Long-term keys | Separate RSA-3072 signing and encryption keys |
| Replay handling | Canonical base64 + persisted recent message IDs |
| Identity binding | SHA-256 of the signing public key |
| Trust model | TOFU with manual fingerprint verification |
| Forward secrecy | **No** |
| Post-compromise security | **No** |
| Independent audit | **No** |
| Offline delivery | **No** (roadmap) |
| Local message history | **No** (roadmap) |

The relay can see public keys, display names, identity IDs, who is online, sender/recipient routing metadata, message sizes, timing, and connection IP addresses. It cannot read message plaintext or private keys.

Read [docs/threat-model.md](docs/threat-model.md) and [docs/protocol.md](docs/protocol.md) before relying on the design.

## Deployment

The primary deployment target is a single AWS EC2 instance running the relay behind Caddy for automatic TLS and WebSocket reverse proxying. Port 55555 stays bound to loopback; only 80/443 are public.

- [AWS EC2 + Caddy guide](docs/deployment-aws.md)
- [Caddyfile](deploy/Caddyfile)
- [systemd unit](deploy/cipherwire.service)
- [environment example](deploy/cipherwire.env.example)

Placeholders such as `<DOMAIN>`, `<AWS_REGION>`, and `<INSTANCE_TYPE>` must be replaced. Do not expose the relay port directly to the internet.

### Separate static hosting

`index.html`, `styles.css`, `app.js`, and `favicon.svg` are relative-path static assets. They can be served from any static host:

1. Upload those four files.
2. Set the relay URL in the connect form to `wss://<RELAY_DOMAIN>`.
3. Set `CHAT_ALLOWED_ORIGINS=https://<STATIC_HOST>` on the relay.
4. Configure the static host to send a CSP with `script-src 'self'; style-src 'self'; connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*`.

The relay's own web server sends the stricter headers in `server.py` automatically.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
mypy
pytest -q
bandit -q -r protocol.py client.py server.py
pip-audit -r requirements.txt
```

Tests cover canonical base64, replay rejection, key-size/exponent validation, identity signatures, envelope signatures, invalid GCM tags, peer pinning, directory chunking, URL validation, terminal sanitization, and a live relay handshake/message-delivery path.

Project layout:

```text
server.py              relay, identity registry, static web server, limits
client.py              CLI identity, encryption, pinning, replay cache
protocol.py            shared wire format, canonicalization, signatures
app.js                 browser client (WebCrypto + IndexedDB)
index.html/styles.css  browser UI
setup_keys.py          CLI identity creation
tests/                 unit and relay integration tests
deploy/                Caddy, systemd, environment example
docs/                  protocol, threat model, AWS deployment
```

## Roadmap

- v3: X25519 double-ratchet style forward secrecy and post-compromise security.
- Offline delivery with explicit retention and abuse limits.
- Optional encrypted local history.
- Multi-device identity and key rotation.
- External security review and reproducible releases.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
