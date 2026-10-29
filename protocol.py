"""Shared Cipherwire protocol-v2 primitives.

The relay and both clients must agree byte-for-byte on canonical encodings and
signed payloads.  Keeping those rules in one module avoids the kind of drift
that can silently weaken replay and signature checks.
"""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

APP_NAME = "Cipherwire"
VERSION = "2.0.0"
PROTOCOL_VERSION = 2

MAX_FRAME_BYTES = 64 * 1024
MAX_PLAINTEXT_BYTES = 32 * 1024
MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + 16
MAX_RSA_BLOB_BYTES = 1024
MIN_RSA_BITS = 2048
MAX_RSA_BITS = 8192
MIN_RSA_BLOB_BYTES = MIN_RSA_BITS // 8
OAEP_LABEL = b"ZTCHAT/v2/AES-GCM"
NICKNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,31}$")


class ProtocolError(ValueError):
    """A peer sent data that does not satisfy the protocol."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: Any, name: str, maximum: int, exact: int | None = None) -> bytes:
    """Decode strict, canonical base64.

    ``base64.b64decode(..., validate=True)`` still accepts non-zero padding bits
    and a few alternate spellings.  Re-encoding and comparing closes that gap,
    which matters because message IDs are used as replay-cache keys.
    """
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be base64")
    # Reject oversized input before allocating a decoded buffer.
    if len(value) > ((maximum + 2) // 3) * 4:
        raise ProtocolError(f"{name} has an invalid length")
    try:
        data = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ProtocolError(f"{name} is invalid base64") from exc
    if b64e(data) != value:
        raise ProtocolError(f"{name} is not canonical base64")
    if len(data) > maximum or (exact is not None and len(data) != exact):
        raise ProtocolError(f"{name} has an invalid length")
    return data


def valid_id(value: Any, name: str = "identity_id") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ProtocolError(f"{name} is invalid")
    return value


def valid_nickname(value: Any) -> str:
    if not isinstance(value, str):
        raise ProtocolError("nickname is invalid")
    value = value.strip()
    if not NICKNAME.fullmatch(value):
        raise ProtocolError("nickname must be 1-32 ASCII letters, digits, spaces, ., _, or -")
    return value


def canonical_public_key(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_key(encoded: Any, name: str) -> tuple[rsa.RSAPublicKey, bytes]:
    der = b64d(encoded, name, 8192)
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ProtocolError(f"{name} is not a public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ProtocolError(f"{name} must be an RSA public key")
    if not MIN_RSA_BITS <= key.key_size <= MAX_RSA_BITS or key.public_numbers().e != 65537:
        raise ProtocolError(
            f"{name} must be an RSA key of {MIN_RSA_BITS}-{MAX_RSA_BITS} bits with exponent 65537"
        )
    return key, canonical_public_key(key)


def client_id(signing_der: bytes) -> str:
    return hashlib.sha256(signing_der).hexdigest()


def fingerprint(der: bytes) -> str:
    # 128 display bits: enough for meaningful out-of-band comparisons.
    digest = hashlib.sha256(der).hexdigest().upper()[:32]
    return ":".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def identify_data(challenge: bytes, identity: str, nickname: str, signing_der: bytes, encryption_der: bytes) -> bytes:
    return b"ZTCHAT/v2/identify\0" + b"".join((
        challenge, bytes.fromhex(identity), nickname.encode("utf-8"),
        hashlib.sha256(signing_der).digest(), hashlib.sha256(encryption_der).digest(),
    ))


def message_aad(message_id: bytes, sender: str, recipient: str) -> bytes:
    return b"ZTCHAT/v2/message-aad\0" + message_id + bytes.fromhex(sender) + bytes.fromhex(recipient)


def message_signature_data(
    message_id: bytes,
    sender: str,
    recipient: str,
    wrapped_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    return b"ZTCHAT/v2/message-signature\0" + b"".join((
        message_aad(message_id, sender, recipient),
        hashlib.sha256(wrapped_key).digest(), nonce, hashlib.sha256(ciphertext).digest(),
    ))


def verify_signature(key: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    try:
        key.verify(
            signature, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
