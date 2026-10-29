from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import server
from client import (
    Identity,
    KnownPeers,
    Peer,
    ReplayCache,
    decrypt_envelope,
    encrypt_envelope,
    parse_peer,
    safe_terminal_text,
    validate_url,
)
from protocol import (
    MAX_RSA_BLOB_BYTES,
    OAEP_LABEL,
    PROTOCOL_VERSION,
    ProtocolError,
    b64d,
    b64e,
    canonical_public_key,
    fingerprint,
    identify_data,
    load_public_key,
    message_aad,
    message_signature_data,
    valid_nickname,
)

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def make_keypair(bits: int = 2048, exponent: int = 65537) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=exponent, key_size=bits)


def der(key: rsa.RSAPublicKey) -> bytes:
    return canonical_public_key(key)


@pytest.fixture(scope="module")
def alice() -> Identity:
    signing, encryption = make_keypair(), make_keypair()
    return Identity(signing, encryption, der(signing.public_key()), der(encryption.public_key()))


@pytest.fixture(scope="module")
def bob() -> Identity:
    signing, encryption = make_keypair(), make_keypair()
    return Identity(signing, encryption, der(signing.public_key()), der(encryption.public_key()))


def build_identity(signing: rsa.RSAPrivateKey, encryption: rsa.RSAPrivateKey) -> tuple[Identity, Peer, server.Identity]:
    signing_der = der(signing.public_key())
    encryption_der = der(encryption.public_key())
    identity = Identity(signing, encryption, signing_der, encryption_der)
    peer = Peer(
        identity.identity_id, "Peer", signing.public_key(), encryption.public_key(),
        fingerprint(signing_der), fingerprint(encryption_der), verified=True,
    )
    server_identity = server.Identity(identity.identity_id, "Peer", signing_der, encryption_der)
    return identity, peer, server_identity


def sign_identity(identity: Identity, nickname: str, challenge: bytes) -> dict[str, object]:
    signature = identity.signing_private.sign(
        identify_data(challenge, identity.identity_id, nickname, identity.signing_der, identity.encryption_der),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    return {
        "type": "IDENTIFY", "v": PROTOCOL_VERSION, "nickname": nickname,
        "identity_id": identity.identity_id,
        "signing_key": b64e(identity.signing_der), "encryption_key": b64e(identity.encryption_der),
        "signature": b64e(signature),
    }


def test_canonical_base64_accepts_only_one_spelling() -> None:
    data = os.urandom(16)
    encoded = b64e(data)
    assert b64d(encoded, "value", 16, 16) == data

    # Flip the unused low bits in the final quantum.  The bytes are unchanged,
    # but the encoding is not canonical and must be rejected.
    index = B64_ALPHABET.index(encoded[-3])
    noncanonical = encoded[:-3] + B64_ALPHABET[index | 1] + encoded[-2:]
    assert base64.b64decode(noncanonical, validate=True) == data
    with pytest.raises(ProtocolError, match="canonical"):
        b64d(noncanonical, "value", 16, 16)

    with pytest.raises(ProtocolError):
        b64d(encoded.rstrip("="), "value", 16, 16)
    with pytest.raises(ProtocolError):
        b64d(" " + encoded, "value", 16, 16)


def test_nickname_rejects_non_strings_and_control_characters() -> None:
    assert valid_nickname(" Alice ") == "Alice"
    for value in (None, 42, "", "-bad", "bad\nname", "x" * 33):
        with pytest.raises(ProtocolError):
            valid_nickname(value)


def test_public_key_limits() -> None:
    weak = make_keypair(1024)
    with pytest.raises(ProtocolError, match="2048-8192"):
        load_public_key(b64e(der(weak.public_key())), "weak")
    wrong_exponent = make_keypair(2048, exponent=3)
    with pytest.raises(ProtocolError, match="exponent"):
        load_public_key(b64e(der(wrong_exponent.public_key())), "exponent")


def test_parse_identity_round_trip(alice: Identity) -> None:
    challenge = os.urandom(32)
    parsed = server.parse_identity(sign_identity(alice, "Alice", challenge), challenge)
    assert parsed.identity_id == alice.identity_id
    assert parsed.nickname == "Alice"
    assert parsed.signing_der == alice.signing_der
    assert parsed.encryption_der == alice.encryption_der


def test_parse_identity_rejects_reused_key() -> None:
    signing = make_keypair()
    identity, _peer, _server_identity = build_identity(signing, signing)
    challenge = os.urandom(32)
    packet = sign_identity(identity, "Alice", challenge)
    with pytest.raises(ProtocolError, match="different"):
        server.parse_identity(packet, challenge)


def test_parse_identity_rejects_weak_key() -> None:
    signing = make_keypair(1024)
    encryption = make_keypair()
    identity = Identity(signing, encryption, der(signing.public_key()), der(encryption.public_key()))
    challenge = os.urandom(32)
    with pytest.raises(ProtocolError, match="2048-8192"):
        server.parse_identity(sign_identity(identity, "Weak", challenge), challenge)


def test_parse_envelope_canonicalizes_and_rejects_tampering(alice: Identity, bob: Identity) -> None:
    _alice, _alice_peer, alice_server = build_identity(alice.signing_private, alice.encryption_private)
    _bob, bob_peer, _bob_server = build_identity(bob.signing_private, bob.encryption_private)
    packet = encrypt_envelope("hello", alice, bob_peer)
    packet["optional"] = "must not be forwarded"
    parsed = server.parse_envelope(packet, alice_server)
    assert "optional" not in parsed
    assert parsed["message_id"] == packet["message_id"]

    forged = dict(packet)
    forged["sender_id"] = bob.identity_id
    with pytest.raises(ProtocolError, match="forged"):
        server.parse_envelope(forged, alice_server)

    bad_id = dict(packet)
    message_id = b64d(packet["message_id"], "id", 16, 16)
    encoded = b64e(message_id)
    index = B64_ALPHABET.index(encoded[-3])
    bad_id["message_id"] = encoded[:-3] + B64_ALPHABET[index | 1] + encoded[-2:]
    with pytest.raises(ProtocolError, match="canonical"):
        server.parse_envelope(bad_id, alice_server)


def test_decrypt_round_trip_and_replay(alice: Identity, bob: Identity, tmp_path) -> None:
    _alice, alice_peer, _alice_server = build_identity(alice.signing_private, alice.encryption_private)
    _bob, _bob_peer, _bob_server = build_identity(bob.signing_private, bob.encryption_private)
    replay = ReplayCache(tmp_path / "seen.json")
    packet = encrypt_envelope("hello", alice, _bob_peer)
    sender, plaintext = decrypt_envelope(packet, bob, {alice.identity_id: alice_peer}, replay)
    assert sender.identity_id == alice.identity_id
    assert plaintext == "hello"
    with pytest.raises(ProtocolError, match="replayed"):
        decrypt_envelope(packet, bob, {alice.identity_id: alice_peer}, replay)

    reloaded = ReplayCache(tmp_path / "seen.json")
    reloaded.load()
    assert reloaded.contains(b64d(packet["message_id"], "id", 16, 16))


def test_decrypt_rejects_invalid_tag_without_crashing(alice: Identity, bob: Identity, tmp_path) -> None:
    _alice, alice_peer, _alice_server = build_identity(alice.signing_private, alice.encryption_private)
    _bob, bob_peer, _bob_server = build_identity(bob.signing_private, bob.encryption_private)
    packet = encrypt_envelope("hello", alice, bob_peer)
    message_id = b64d(packet["message_id"], "id", 16, 16)
    ciphertext = bytearray(b64d(packet["ciphertext"], "ciphertext", 32 * 1024 + 16))
    ciphertext[-1] ^= 1
    packet["ciphertext"] = b64e(bytes(ciphertext))
    packet["signature"] = b64e(alice.signing_private.sign(
        message_signature_data(
            message_id, alice.identity_id, bob.identity_id,
            b64d(packet["encrypted_key"], "key", MAX_RSA_BLOB_BYTES),
            b64d(packet["nonce"], "nonce", 12, 12),
            bytes(ciphertext),
        ),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    ))
    replay = ReplayCache(tmp_path / "seen.json")
    with pytest.raises(ProtocolError, match="integrity"):
        decrypt_envelope(packet, bob, {alice.identity_id: alice_peer}, replay)


def test_peer_key_pinning_detects_changes(alice: Identity, tmp_path) -> None:
    _alice, alice_peer, _alice_server = build_identity(alice.signing_private, alice.encryption_private)
    known = KnownPeers(tmp_path / "known.json")
    assert known.observe(alice_peer) is False
    known.trust(alice_peer)
    assert known.observe(alice_peer) is True

    changed = Peer(
        alice_peer.identity_id, alice_peer.nickname, alice_peer.signing_key, make_keypair().public_key(),
        alice_peer.signing_fingerprint, "AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA:AAAA", verified=False,
    )
    with pytest.raises(ProtocolError, match="key changed"):
        known.observe(changed)


def test_parse_peer_rejects_weak_and_reused_keys(alice: Identity) -> None:
    weak = make_keypair(1024)
    weak_identity = Identity(weak, make_keypair(), der(weak.public_key()), b"")
    entry = {
        "identity_id": weak_identity.identity_id,
        "nickname": "Weak",
        "signing_key": b64e(weak_identity.signing_der),
        "encryption_key": b64e(der(weak_identity.encryption_private.public_key())),
    }
    known = KnownPeers(Path("/tmp/does-not-exist-cipherwire.json"))
    with pytest.raises(ProtocolError, match="2048-8192"):
        parse_peer(entry, known)

    same = make_keypair()
    same_identity = Identity(same, same, der(same.public_key()), der(same.public_key()))
    entry = {
        "identity_id": same_identity.identity_id,
        "nickname": "Same",
        "signing_key": b64e(same_identity.signing_der),
        "encryption_key": b64e(same_identity.encryption_der),
    }
    with pytest.raises(ProtocolError, match="differ"):
        parse_peer(entry, known)


def test_terminal_output_is_sanitized() -> None:
    assert "\x1b" not in safe_terminal_text("hello\x1b[31mred")
    assert "\\x1b" in safe_terminal_text("hello\x1b[31mred")
    assert "\u202e" not in safe_terminal_text("abc\u202edef")
    assert "\n    " in safe_terminal_text("line1\nline2")


def test_validate_url(monkeypatch) -> None:
    assert validate_url("wss://chat.example.com") == "wss://chat.example.com"
    with pytest.raises(ValueError, match="wss"):
        validate_url("ws://chat.example.com")
    monkeypatch.setenv("CHAT_ALLOW_INSECURE_LOCAL", "1")
    assert validate_url("ws://localhost:55555") == "ws://localhost:55555"
    with pytest.raises(ValueError, match="credentials"):
        validate_url("wss://user:pass@chat.example.com")


def test_directory_chunking(monkeypatch) -> None:
    signing = make_keypair()
    encryption = make_keypair()
    signing_der, encryption_der = der(signing.public_key()), der(encryption.public_key())
    fake_sessions = {
        f"{index:064x}": server.Session(
            object(), server.Identity(f"{index:064x}", f"user{index}", signing_der, encryption_der)
        )
        for index in range(1, 80)
    }
    monkeypatch.setattr(server, "sessions", fake_sessions)
    chunks = server.directory_chunks("")
    assert len(chunks) > 1
    assert all(len(json.dumps(chunk, separators=(",", ":")).encode()) <= server.DIRECTORY_CHUNK_BYTES for chunk in chunks)
    assert sum(len(chunk) for chunk in chunks) == 79


def test_encrypt_envelope_uses_oaep_label(alice: Identity, bob: Identity) -> None:
    _bob, bob_peer, _bob_server = build_identity(bob.signing_private, bob.encryption_private)
    packet = encrypt_envelope("hello", alice, bob_peer)
    session_key = bob.encryption_private.decrypt(
        b64d(packet["encrypted_key"], "key", MAX_RSA_BLOB_BYTES),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=OAEP_LABEL),
    )
    assert len(session_key) == 32
    assert b64d(packet["nonce"], "nonce", 12, 12)
    assert message_aad(b64d(packet["message_id"], "id", 16, 16), alice.identity_id, bob.identity_id)


def test_serialized_keys_are_spki() -> None:
    key = make_keypair()
    encoded = der(key.public_key())
    loaded = serialization.load_der_public_key(encoded)
    assert isinstance(loaded, rsa.RSAPublicKey)
    assert loaded.key_size == 2048
