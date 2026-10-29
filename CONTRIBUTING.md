# Contributing

Cipherwire is an experimental security project. Small, well-tested changes are preferred.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

Run the checks before opening a pull request:

```bash
ruff check .
mypy
pytest -q
bandit -q -r protocol.py client.py server.py
pip-audit -r requirements.txt
```

## Rules

- Never commit `.keys/`, `.chat_state/`, private keys, passwords, tokens, or real message data.
- Add tests for protocol, crypto, parsing, or limit changes.
- Keep the relay and both clients byte-compatible. If you change a signed or encrypted transcript, update `protocol.py`, `client.py`, `app.js`, `docs/protocol.md`, and tests together.
- Do not weaken canonical base64, signature verification, replay checks, key pinning, CSP, or origin checks for convenience.
- Do not add a new cryptographic primitive without a clear design note and test vectors.
- Keep v1 compatibility out of v2. v1 is intentionally retired.

## Security reports

Do not open a public issue for a vulnerability. Use GitHub private vulnerability reporting as described in [SECURITY.md](SECURITY.md).

## Style

- Python: `ruff` and `mypy` must pass; target Python 3.11+.
- JavaScript: keep it dependency-free and browser-native; no `innerHTML` for peer-controlled data.
- Documentation: use placeholders such as `<DOMAIN>` and `<AWS_REGION>` in deployment examples.
