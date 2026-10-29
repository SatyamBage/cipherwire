# Security notice: v1 is insecure

The repository keeps its original git history for transparency. The **v1 code and any v1 deployment are insecure** and must not be used.

Known v1 problems:

- Messages were not signed, so the relay or a network attacker could alter or forge them.
- A plaintext demo mode existed.
- The relay logged full packets.
- One unencrypted RSA key pair was used for both signing and encryption.
- Identity binding and replay protection were missing or incomplete.
- Old setup instructions and tunnel hostnames were committed to history.

**Do not connect to any hostname found in v1 history. It is retired.** Do not reuse v1 keys, profiles, or `.keys/private.pem` with v2. Cipherwire v2 deliberately refuses to reuse the legacy key.

## Migrating from v1

1. Stop every v1 relay and client.
2. Delete old v1 keys and local state after taking any backup you need for records.
3. Create a fresh v2 identity with `python setup_keys.py` or the browser client.
4. Exchange and verify the new fingerprints through an independent channel.
5. Do not import v1 messages or keys into v2.

## v2 status

v2 fixes the v1 issues above, but it is still **experimental and not independently audited**. It provides no forward secrecy or post-compromise security. The relay sees routing metadata and public keys, but not plaintext. The trust model is TOFU: a new contact is untrusted until both fingerprints are compared out of band.

See [SECURITY.md](SECURITY.md) for reporting and [docs/threat-model.md](docs/threat-model.md) for the full model.
