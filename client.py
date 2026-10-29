"""Cipherwire protocol-v2 CLI client.

Security properties:
* separate, password-protected RSA signing and encryption identities;
* AES-256-GCM with a fresh key and nonce for each message;
* RSA-OAEP-SHA256 key wrapping and RSA-PSS-SHA256 sender signatures;
* immutable peer IDs, peer-key pinning, manual fingerprint verification, and
  replay detection.

This remains a store-and-forward-style hybrid RSA design. It does not provide
forward secrecy or post-compromise security; use a Signal-style X25519 ratchet
for a production messenger.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import json
import os
import re
import sys
import threading
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import websockets
from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from protocol import (
    APP_NAME,
    MAX_CIPHERTEXT_BYTES,
    MAX_FRAME_BYTES,
    MAX_PLAINTEXT_BYTES,
    MAX_RSA_BLOB_BYTES,
    MIN_RSA_BLOB_BYTES,
    OAEP_LABEL,
    PROTOCOL_VERSION,
    VERSION,
    ProtocolError,
    b64d,
    b64e,
    canonical_public_key,
    client_id,
    fingerprint,
    identify_data,
    load_public_key,
    message_aad,
    message_signature_data,
    valid_id,
    valid_nickname,
)

KEY_DIR = Path(__file__).resolve().parent / ".keys"
SIGNING_PRIVATE = KEY_DIR / "signing-private-v2.pem"
SIGNING_PUBLIC = KEY_DIR / "signing-public-v2.pem"
ENCRYPTION_PRIVATE = KEY_DIR / "encryption-private-v2.pem"
ENCRYPTION_PUBLIC = KEY_DIR / "encryption-public-v2.pem"
PROFILE_FILE = KEY_DIR / "profile-v2.json"
KNOWN_PEERS_FILE = KEY_DIR / "known-peers-v2.json"
REPLAY_FILE = KEY_DIR / "seen-message-ids-v2.json"
MAX_KNOWN_PEERS = 500
MAX_ONLINE_PEERS = 500
MAX_TERMINAL_CHARS = 8192
FINGERPRINT = re.compile(r"^(?:[0-9A-F]{4}:){7}[0-9A-F]{4}$")


class KeyChangedError(ProtocolError):
    pass


def public_der(key: rsa.RSAPublicKey) -> bytes:
    return canonical_public_key(key)


def load_public(encoded: Any, name: str) -> tuple[rsa.RSAPublicKey, bytes]:
    return load_public_key(encoded, name)


def identity_id(signing_der: bytes) -> str:
    return client_id(signing_der)


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "wb") as file:
        file.write(data)
    os.replace(temporary, path)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


@dataclass
class Identity:
    signing_private: rsa.RSAPrivateKey
    encryption_private: rsa.RSAPrivateKey
    signing_der: bytes
    encryption_der: bytes

    @property
    def identity_id(self) -> str:
        return client_id(self.signing_der)


def password_for_new_identity() -> bytes:
    while True:
        password = getpass.getpass("Create a password to protect this device's private keys: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            print("[!] Passwords did not match.")
        elif len(password) < 12:
            print("[!] Use at least 12 characters.")
        else:
            return password.encode("utf-8")


def write_identity_files(signing: rsa.RSAPrivateKey, encryption: rsa.RSAPrivateKey, password: bytes) -> Identity:
    atomic_write(
        SIGNING_PRIVATE,
        signing.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.BestAvailableEncryption(password)),
    )
    atomic_write(
        ENCRYPTION_PRIVATE,
        encryption.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.BestAvailableEncryption(password)),
    )
    signing_der, encryption_der = public_der(signing.public_key()), public_der(encryption.public_key())
    atomic_write(SIGNING_PUBLIC, signing.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    atomic_write(ENCRYPTION_PUBLIC, encryption.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return Identity(signing, encryption, signing_der, encryption_der)


def create_identity_files() -> Identity:
    if any(path.exists() for path in (SIGNING_PRIVATE, SIGNING_PUBLIC, ENCRYPTION_PRIVATE, ENCRYPTION_PUBLIC)):
        raise RuntimeError("A v2 identity already exists. Refusing to overwrite it.")
    print("[*] Creating separate 3072-bit RSA signing and encryption keys...")
    password = password_for_new_identity()
    identity = write_identity_files(
        rsa.generate_private_key(public_exponent=65537, key_size=3072),
        rsa.generate_private_key(public_exponent=65537, key_size=3072),
        password,
    )
    print(f"[+] Identity created: {identity.identity_id}")
    return identity


def load_identity() -> Identity:
    key_files = (SIGNING_PRIVATE, SIGNING_PUBLIC, ENCRYPTION_PRIVATE, ENCRYPTION_PUBLIC)
    if not any(path.exists() for path in key_files):
        if (KEY_DIR / "private.pem").exists():
            print("[*] Legacy v1 keys found. They are intentionally not reused for signing and encryption.")
        return create_identity_files()
    if not all(path.exists() for path in key_files):
        raise RuntimeError("Identity files are incomplete; restore them from a backup or use a fresh .keys directory.")

    password = getpass.getpass("Private-key password: ").encode("utf-8")
    try:
        signing = serialization.load_pem_private_key(SIGNING_PRIVATE.read_bytes(), password=password)
        encryption = serialization.load_pem_private_key(ENCRYPTION_PRIVATE.read_bytes(), password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise RuntimeError("Could not unlock private keys.") from exc
    if not isinstance(signing, rsa.RSAPrivateKey) or not isinstance(encryption, rsa.RSAPrivateKey):
        raise RuntimeError("Private keys are not RSA keys.")
    if signing.key_size != 3072 or encryption.key_size != 3072:
        raise RuntimeError("v2 identity keys must be 3072-bit RSA.")
    signing_der, encryption_der = public_der(signing.public_key()), public_der(encryption.public_key())
    if signing_der == encryption_der:
        raise RuntimeError("Signing and encryption keys must be different.")
    if SIGNING_PUBLIC.read_bytes() != signing.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise RuntimeError("Signing public key does not match its private key.")
    if ENCRYPTION_PUBLIC.read_bytes() != encryption.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise RuntimeError("Encryption public key does not match its private key.")
    return Identity(signing, encryption, signing_der, encryption_der)


def load_or_create_nickname() -> str:
    if PROFILE_FILE.exists():
        try:
            document = json.loads(PROFILE_FILE.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("profile must be a JSON object")
            return valid_nickname(document["nickname"])
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Profile is invalid: {exc}") from exc
    while True:
        try:
            nickname = valid_nickname(input("Choose a display name (it may be shared): "))
            break
        except ValueError as exc:
            print(f"[!] {exc}")
    atomic_write(PROFILE_FILE, json.dumps({"version": PROTOCOL_VERSION, "nickname": nickname}).encode("utf-8"))
    return nickname


class KnownPeers:
    """Public-key pins. New peers are *not* automatically trusted."""

    def __init__(self, path: Path):
        self.path = path
        self.records: dict[str, dict[str, Any]] = {}

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            if self.path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("file is too large")
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or document.get("version") != PROTOCOL_VERSION:
                raise ValueError("wrong format")
            peers = document.get("peers")
            if not isinstance(peers, dict) or len(peers) > MAX_KNOWN_PEERS:
                raise ValueError("wrong format or too many peers")
            records: dict[str, dict[str, Any]] = {}
            for peer_id, record in peers.items():
                valid_id(peer_id, "stored peer ID")
                if not isinstance(record, dict):
                    raise ValueError("stored peer record is invalid")
                nickname = valid_nickname(record.get("nickname"))
                signing_fingerprint = record.get("signing_fingerprint")
                encryption_fingerprint = record.get("encryption_fingerprint")
                verified = record.get("verified", False)
                if not isinstance(signing_fingerprint, str) or not FINGERPRINT.fullmatch(signing_fingerprint):
                    raise ValueError("stored signing fingerprint is invalid")
                if not isinstance(encryption_fingerprint, str) or not FINGERPRINT.fullmatch(encryption_fingerprint):
                    raise ValueError("stored encryption fingerprint is invalid")
                if not isinstance(verified, bool):
                    raise ValueError("stored verification flag is invalid")
                records[peer_id] = {
                    "nickname": nickname,
                    "signing_fingerprint": signing_fingerprint,
                    "encryption_fingerprint": encryption_fingerprint,
                    "verified": verified,
                }
            self.records = records
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, ProtocolError) as exc:
            raise RuntimeError(f"Known-peer file is invalid: {exc}") from exc

    def save(self) -> None:
        atomic_write(self.path, json.dumps({"version": PROTOCOL_VERSION, "peers": self.records}, sort_keys=True).encode("utf-8"))

    def observe(self, peer: Peer) -> bool:
        old = self.records.get(peer.identity_id)
        if old is None:
            if len(self.records) >= MAX_KNOWN_PEERS:
                raise ProtocolError("known-peer limit reached; remove old pins before adding more peers")
            self.records[peer.identity_id] = {
                "nickname": peer.nickname, "signing_fingerprint": peer.signing_fingerprint,
                "encryption_fingerprint": peer.encryption_fingerprint, "verified": False,
            }
            self.save()
            return False
        if old.get("signing_fingerprint") != peer.signing_fingerprint or old.get("encryption_fingerprint") != peer.encryption_fingerprint:
            raise KeyChangedError(f"key changed for {peer.nickname} [{peer.identity_id[:12]}]")
        return bool(old.get("verified"))

    def trust(self, peer: Peer) -> None:
        record = self.records.get(peer.identity_id)
        if record is None:
            raise ProtocolError("cannot trust a peer that has not been observed")
        record["verified"] = True
        record["nickname"] = peer.nickname
        self.save()


@dataclass
class Peer:
    identity_id: str
    nickname: str
    signing_key: rsa.RSAPublicKey
    encryption_key: rsa.RSAPublicKey
    signing_fingerprint: str
    encryption_fingerprint: str
    verified: bool = False


def parse_peer(entry: Any, known: KnownPeers) -> Peer:
    if not isinstance(entry, dict):
        raise ProtocolError("peer directory entry is invalid")
    peer_id = valid_id(entry.get("identity_id"))
    nickname = valid_nickname(entry.get("nickname", ""))
    signing_key, signing_der = load_public(entry.get("signing_key"), "peer signing_key")
    encryption_key, encryption_der = load_public(entry.get("encryption_key"), "peer encryption_key")
    if signing_der == encryption_der:
        raise ProtocolError("peer signing and encryption keys must differ")
    if peer_id != client_id(signing_der):
        raise ProtocolError("peer identity_id does not match its signing key")
    peer = Peer(peer_id, nickname, signing_key, encryption_key, fingerprint(signing_der), fingerprint(encryption_der))
    peer.verified = known.observe(peer)
    return peer


class ReplayCache:
    """Persist recent message IDs so a reconnect doesn't reopen a replay window."""

    def __init__(self, path: Path, limit: int = 4096):
        self.path = path
        self.limit = limit
        self.ids: OrderedDict[bytes, None] = OrderedDict()

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            if self.path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("file is too large")
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or document.get("version") != PROTOCOL_VERSION:
                raise ValueError("wrong format")
            values = document.get("message_ids")
            if not isinstance(values, list):
                raise ValueError("wrong format")
            for value in values[-self.limit:]:
                self.ids[b64d(value, "stored message ID", 16, 16)] = None
        except (OSError, ValueError, json.JSONDecodeError, ProtocolError) as exc:
            raise RuntimeError(f"Replay cache is invalid: {exc}") from exc

    def contains(self, message_id: bytes) -> bool:
        return message_id in self.ids

    def add(self, message_id: bytes) -> None:
        self.ids[message_id] = None
        self.ids.move_to_end(message_id)
        while len(self.ids) > self.limit:
            self.ids.popitem(last=False)
        atomic_write(
            self.path,
            json.dumps({"version": PROTOCOL_VERSION, "message_ids": [b64e(value) for value in self.ids]}).encode("utf-8"),
        )


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        raise ValueError("Server URLs must not contain embedded credentials.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Server URL has an invalid port.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Server URL has an invalid port.")
    if parsed.scheme == "wss" and parsed.hostname:
        return url
    local_hosts = {"localhost", "127.0.0.1", "::1", "[::1]"}
    if parsed.scheme == "ws" and parsed.hostname in local_hosts and os.environ.get("CHAT_ALLOW_INSECURE_LOCAL") == "1":
        print("[!] Using insecure ws:// only because CHAT_ALLOW_INSECURE_LOCAL=1 is set for local development.")
        return url
    raise ValueError("Use a certificate-validated wss:// URL. ws:// is allowed only for localhost with CHAT_ALLOW_INSECURE_LOCAL=1.")


def choose_server_url() -> str:
    configured = os.environ.get("CHAT_SERVER_URL")
    if configured:
        return validate_url(configured)
    return validate_url(input("Server URL (wss://host:port): ").strip())


def resolve_peer(peers: dict[str, Peer], query: str) -> Peer | None:
    query = query.strip().casefold()
    if not query:
        print("[!] Enter a display name or identity-ID prefix.")
        return None
    matches = [peer for peer in peers.values() if peer.identity_id.startswith(query)]
    if not matches:
        matches = [peer for peer in peers.values() if peer.nickname.casefold() == query]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        print(f"[!] No online peer matches '{query}'.")
    else:
        print("[!] That display name/ID prefix is ambiguous. Use a longer identity-ID prefix:")
        for peer in matches:
            print(f"    {peer.nickname} [{peer.identity_id[:12]}]")
    return None


def show_peers(peers: dict[str, Peer]) -> None:
    if not peers:
        print("[*] No other users are online.")
        return
    print("Online peers (compare both fingerprints out of band before /trust):")
    for peer in sorted(peers.values(), key=lambda item: (item.nickname.casefold(), item.identity_id)):
        status = "VERIFIED" if peer.verified else "UNVERIFIED"
        print(f"  {peer.nickname} [{peer.identity_id[:12]}]  {status}")
        print(f"    signing:    {peer.signing_fingerprint}")
        print(f"    encryption: {peer.encryption_fingerprint}")


def encrypt_envelope(plaintext: str, sender: Identity, recipient: Peer) -> dict[str, str | int]:
    plaintext_bytes = plaintext.encode("utf-8")
    if len(plaintext_bytes) > MAX_PLAINTEXT_BYTES:
        raise ProtocolError(f"message exceeds the {MAX_PLAINTEXT_BYTES // 1024} KB encrypted-message limit")
    message_id, nonce = os.urandom(16), os.urandom(12)
    session_key = AESGCM.generate_key(bit_length=256)
    wrapped_key = recipient.encryption_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=OAEP_LABEL),
    )
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext_bytes, message_aad(message_id, sender.identity_id, recipient.identity_id))
    signed = message_signature_data(message_id, sender.identity_id, recipient.identity_id, wrapped_key, nonce, ciphertext)
    signature = sender.signing_private.sign(
        signed, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size), hashes.SHA256(),
    )
    return {
        "type": "MESSAGE", "v": PROTOCOL_VERSION, "message_id": b64e(message_id),
        "sender_id": sender.identity_id, "recipient_id": recipient.identity_id,
        "encrypted_key": b64e(wrapped_key), "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext), "signature": b64e(signature),
    }


def decrypt_envelope(packet: dict[str, Any], recipient: Identity, peers: dict[str, Peer], replay: ReplayCache) -> tuple[Peer, str]:
    if packet.get("type") != "MESSAGE" or packet.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("not a v2 message")
    message_id = b64d(packet.get("message_id"), "message_id", 16, 16)
    sender_id, recipient_id = valid_id(packet.get("sender_id"), "sender_id"), valid_id(packet.get("recipient_id"), "recipient_id")
    if recipient_id != recipient.identity_id:
        raise ProtocolError("message was addressed to another identity")
    sender = peers.get(sender_id)
    if sender is None:
        raise ProtocolError("sender is absent from the trusted directory")
    if not sender.verified:
        raise ProtocolError(f"sender {sender.nickname} is unverified; compare fingerprints and run /trust {sender_id[:12]}")
    if replay.contains(message_id):
        raise ProtocolError("replayed message rejected")
    wrapped_key = b64d(packet.get("encrypted_key"), "encrypted_key", MAX_RSA_BLOB_BYTES)
    nonce = b64d(packet.get("nonce"), "nonce", 12, 12)
    ciphertext = b64d(packet.get("ciphertext"), "ciphertext", MAX_CIPHERTEXT_BYTES)
    signature = b64d(packet.get("signature"), "signature", MAX_RSA_BLOB_BYTES)
    if len(wrapped_key) < MIN_RSA_BLOB_BYTES:
        raise ProtocolError("encrypted_key has an invalid length")
    if len(signature) < MIN_RSA_BLOB_BYTES:
        raise ProtocolError("signature has an invalid length")
    if len(ciphertext) < 16:
        raise ProtocolError("ciphertext is too short")
    signed = message_signature_data(message_id, sender_id, recipient_id, wrapped_key, nonce, ciphertext)
    try:
        sender.signing_key.verify(
            signature, signed,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        session_key = recipient.encryption_private.decrypt(
            wrapped_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=OAEP_LABEL),
        )
        if len(session_key) != 32:
            raise ProtocolError("invalid AES key length")
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, message_aad(message_id, sender_id, recipient_id)).decode("utf-8")
    except (InvalidSignature, InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("signature or encryption integrity check failed") from exc
    replay.add(message_id)
    return sender, plaintext


async def send_json(ws: Any, packet: dict[str, Any]) -> None:
    encoded = json.dumps(packet, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_FRAME_BYTES:
        raise ProtocolError("outgoing packet is too large")
    await ws.send(encoded)


def safe_terminal_text(value: Any, limit: int = MAX_TERMINAL_CHARS) -> str:
    """Make relay/peer text safe to print in a terminal."""
    text = value if isinstance(value, str) else str(value)
    output: list[str] = []
    length = 0
    for char in text:
        code = ord(char)
        if char == "\n":
            rendered = "\n    "
        elif char == "\t":
            rendered = "    "
        elif code < 32 or 127 <= code < 160 or unicodedata.category(char) in ("Cf", "Cs"):
            rendered = f"\\x{code:02x}"
        else:
            rendered = char
        output.append(rendered)
        length += len(rendered)
        if length >= limit:
            output.append("…")
            break
    return "".join(output)


def ingest_peers(entries: Any, peers: dict[str, Peer], known: KnownPeers) -> None:
    if not isinstance(entries, list):
        raise ProtocolError("peer list is invalid")
    for entry in entries:
        peer = parse_peer(entry, known)
        if peer.identity_id not in peers and len(peers) >= MAX_ONLINE_PEERS:
            raise ProtocolError("online peer directory is full")
        peers[peer.identity_id] = peer
        if not peer.verified:
            print(f"[!] New, unverified peer: {peer.nickname} [{peer.identity_id[:12]}]. Run /users and compare fingerprints before /trust.")


async def receive_loop(ws: Any, identity: Identity, peers: dict[str, Peer], known: KnownPeers, replay: ReplayCache) -> None:
    async for raw in ws:
        try:
            if not isinstance(raw, str):
                raise ProtocolError("invalid server frame")
            try:
                frame_size = len(raw.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ProtocolError("server frame is not valid UTF-8") from exc
            if frame_size > MAX_FRAME_BYTES:
                raise ProtocolError("invalid server frame")
            packet = json.loads(raw)
            if not isinstance(packet, dict):
                raise ProtocolError("invalid server packet")
            packet_type = packet.get("type")
            if packet_type == "MESSAGE":
                sender, plaintext = decrypt_envelope(packet, identity, peers, replay)
                print(f"\n[secure] {sender.nickname} [{sender.identity_id[:12]}]: {safe_terminal_text(plaintext)}")
            elif packet_type == "USER_JOINED":
                peer = parse_peer(packet.get("peer"), known)
                if peer.identity_id not in peers and len(peers) >= MAX_ONLINE_PEERS:
                    raise ProtocolError("online peer directory is full")
                peers[peer.identity_id] = peer
                state = "verified" if peer.verified else "UNVERIFIED"
                print(f"\n[+] {peer.nickname} [{peer.identity_id[:12]}] joined ({state}).")
            elif packet_type == "USER_LEFT":
                departed = valid_id(packet.get("identity_id"))
                departed_peer = peers.get(departed)
                if departed_peer is not None:
                    del peers[departed]
                nickname = departed_peer.nickname if departed_peer else packet.get("nickname", "Peer")
                print(f"\n[-] {safe_terminal_text(nickname)} [{departed[:12]}] left.")
            elif packet_type == "USER_LIST":
                ingest_peers(packet.get("peers"), peers, known)
                show_peers(peers)
            elif packet_type == "ERROR":
                print(f"\n[server:{safe_terminal_text(packet.get('code', 'ERROR'), 64)}] {safe_terminal_text(packet.get('msg', 'Request failed.'))}")
            else:
                print("\n[!] Ignored unexpected server packet.")
        except (ProtocolError, KeyError, TypeError, json.JSONDecodeError) as exc:
            print(f"\n[!] Rejected server packet: {safe_terminal_text(exc)}")


def burn_local_identity() -> None:
    """Best-effort local deletion; overwriting cannot guarantee SSD/FS erasure."""
    legacy = (KEY_DIR / "private.pem", KEY_DIR / "public.pem")
    for path in (
        SIGNING_PRIVATE, SIGNING_PUBLIC, ENCRYPTION_PRIVATE, ENCRYPTION_PUBLIC,
        PROFILE_FILE, KNOWN_PEERS_FILE, REPLAY_FILE, *legacy,
    ):
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
    print("[!] Local identity, peer pins, and legacy v1 key files deleted. This cannot guarantee forensic erasure on all filesystems.")


class InputReader:
    """Read stdin on a daemon thread so disconnects do not hang on input()."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[str | None] = asyncio.Queue()
        self.loop = asyncio.get_running_loop()
        threading.Thread(target=self._read, name="cipherwire-stdin", daemon=True).start()

    def _read(self) -> None:
        while True:
            try:
                line = sys.stdin.readline()
            except (OSError, ValueError):
                line = ""
            if not line:
                self.loop.call_soon_threadsafe(self.queue.put_nowait, None)
                return
            self.loop.call_soon_threadsafe(self.queue.put_nowait, line.rstrip("\n"))

    async def read(self) -> str:
        value = await self.queue.get()
        if value is None:
            raise EOFError
        return value


async def send_loop(ws: Any, identity: Identity, peers: dict[str, Peer], known: KnownPeers) -> None:
    help_text = (
        "\nCommands:\n"
        "  /users                 list identities and fingerprints\n"
        "  /trust <id-prefix>     mark a peer trusted AFTER out-of-band comparison\n"
        "  @<name-or-id> message  send an authenticated encrypted message\n"
        "  /burn                  delete local key files and disconnect\n"
        "  /quit                  disconnect\n"
    )
    print(help_text)
    reader = InputReader()
    while True:
        try:
            line = (await reader.read()).strip()
        except EOFError:
            print("\n[*] End of input; disconnecting.")
            await ws.close()
            return
        if not line:
            continue
        if line == "/help":
            print(help_text)
        elif line == "/users":
            await send_json(ws, {"type": "LIST_USERS", "v": PROTOCOL_VERSION})
        elif line.startswith("/trust "):
            try:
                query = line.split(maxsplit=1)[1]
            except IndexError:
                print("[!] Usage: /trust <display-name-or-id-prefix>")
                continue
            peer = resolve_peer(peers, query)
            if peer:
                known.trust(peer)
                peer.verified = True
                print(f"[+] {peer.nickname} [{peer.identity_id[:12]}] is pinned as VERIFIED.")
        elif line == "/burn":
            print("Type BURN to delete local v2 keys: ", end="", flush=True)
            try:
                confirmation = (await reader.read()).strip()
            except EOFError:
                confirmation = ""
            if confirmation == "BURN":
                burn_local_identity()
                await ws.close()
                return
            print("[*] Burn cancelled.")
        elif line == "/quit":
            await ws.close()
            return
        elif line.startswith("@"):
            try:
                address, plaintext = line[1:].split(maxsplit=1)
            except ValueError:
                print("[!] Usage: @<display-name-or-id-prefix> <message>")
                continue
            peer = resolve_peer(peers, address)
            if peer is None:
                continue
            if not peer.verified:
                print(f"[!] {peer.nickname} is UNVERIFIED. Compare both fingerprints via another channel, then run /trust {peer.identity_id[:12]}.")
                continue
            if len(plaintext.encode("utf-8")) > MAX_PLAINTEXT_BYTES:
                print(f"[!] Message exceeds the {MAX_PLAINTEXT_BYTES // 1024} KB encrypted-message limit.")
                continue
            try:
                await send_json(ws, encrypt_envelope(plaintext, identity, peer))
                print(f"[secure] Sent to {peer.nickname} [{peer.identity_id[:12]}].")
            except (ProtocolError, ValueError) as exc:
                print(f"[!] Encryption failed: {exc}")
        else:
            print("[!] Use @<display-name-or-id-prefix> <message>; /help lists commands.")


async def chat(identity: Identity, nickname: str, server_url: str) -> None:
    known = KnownPeers(KNOWN_PEERS_FILE)
    known.load()
    peers: dict[str, Peer] = {}
    replay = ReplayCache(REPLAY_FILE)
    replay.load()
    async with websockets.connect(server_url, max_size=MAX_FRAME_BYTES, max_queue=16, ping_interval=20, ping_timeout=20) as ws:
        hello = json.loads(await asyncio.wait_for(ws.recv(), 15))
        if not isinstance(hello, dict) or hello.get("type") != "HELLO" or hello.get("v") != PROTOCOL_VERSION:
            raise ProtocolError("server did not speak protocol v2")
        challenge = b64d(hello.get("challenge"), "challenge", 32, 32)
        signature = identity.signing_private.sign(
            identify_data(challenge, identity.identity_id, nickname, identity.signing_der, identity.encryption_der),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        await send_json(ws, {
            "type": "IDENTIFY", "v": PROTOCOL_VERSION, "nickname": nickname, "identity_id": identity.identity_id,
            "signing_key": b64e(identity.signing_der), "encryption_key": b64e(identity.encryption_der),
            "signature": b64e(signature),
        })
        response = json.loads(await asyncio.wait_for(ws.recv(), 15))
        if not isinstance(response, dict):
            raise ProtocolError("invalid relay authentication response")
        if response.get("type") == "ERROR":
            raise ProtocolError(f"server rejected identity: {response.get('msg', 'unknown error')}")
        if response.get("type") != "AUTH_OK" or response.get("v") != PROTOCOL_VERSION or response.get("identity_id") != identity.identity_id:
            raise ProtocolError("invalid AUTH_OK")
        ingest_peers(response.get("peers"), peers, known)
        print(f"[+] Connected as {nickname} [{identity.identity_id[:12]}].")
        show_peers(peers)

        receive_task = asyncio.create_task(receive_loop(ws, identity, peers, known, replay))
        send_task = asyncio.create_task(send_loop(ws, identity, peers, known))
        done, pending = await asyncio.wait((receive_task, send_task), return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            if task.cancelled():
                continue
            exception = task.exception()
            if exception:
                raise exception


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} protocol-v2 CLI")
    parser.add_argument("--create-identity", action="store_true", help="create encrypted v2 key files, then exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        if args.create_identity:
            create_identity_files()
            return
        identity = load_identity()
        nickname = load_or_create_nickname()
        print(f"{APP_NAME} {VERSION}")
        print(f"Your identity ID: {identity.identity_id}")
        print(f"Signing fingerprint:    {fingerprint(identity.signing_der)}")
        print(f"Encryption fingerprint: {fingerprint(identity.encryption_der)}")
        asyncio.run(chat(identity, nickname, choose_server_url()))
    except (OSError, RuntimeError, ProtocolError, ValueError, EOFError, KeyboardInterrupt,
            websockets.exceptions.WebSocketException) as exc:
        print(f"[!] {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
