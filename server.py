"""Cipherwire protocol-v2 relay.

The relay only routes signed, end-to-end encrypted envelopes. Display names are
labels, not identities: an immutable SHA-256 ID derived from a client's signing
key addresses every peer, so duplicate display names never collide.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from websockets.datastructures import Headers
from websockets.http11 import Response
from websockets.typing import Origin

from protocol import (
    APP_NAME,
    MAX_CIPHERTEXT_BYTES,
    MAX_FRAME_BYTES,
    MAX_RSA_BLOB_BYTES,
    MIN_RSA_BLOB_BYTES,
    PROTOCOL_VERSION,
    VERSION,
    ProtocolError,
    b64d,
    b64e,
    client_id,
    fingerprint,
    identify_data,
    load_public_key,
    message_signature_data,
    valid_id,
    valid_nickname,
    verify_signature,
)


def env_int(name: str, default: int, minimum: int = 1, maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum or (maximum is not None and value > maximum):
        raise RuntimeError(f"{name} is outside the allowed range")
    return value


HOST = os.environ.get("CHAT_HOST", "127.0.0.1")
PORT = env_int("CHAT_PORT", 55555, 1, 65535)
MAX_CONNECTIONS = env_int("CHAT_MAX_CONNECTIONS", 256)
MAX_IDENTITIES = env_int("CHAT_MAX_IDENTITIES", 10000)
IDENTIFY_TIMEOUT = 15
SEND_TIMEOUT = 10
DIRECTORY_CHUNK_BYTES = 48 * 1024
STATE_DIR = Path(os.environ.get("CHAT_STATE_DIR", Path(__file__).resolve().parent / ".chat_state"))
IDENTITY_FILE = STATE_DIR / "identities-v2.json"

logging.getLogger("websockets").setLevel(logging.WARNING)


@dataclass(frozen=True)
class Identity:
    identity_id: str
    nickname: str
    signing_der: bytes
    encryption_der: bytes

    def signing_key(self) -> rsa.RSAPublicKey:
        key = serialization.load_der_public_key(self.signing_der)
        if not isinstance(key, rsa.RSAPublicKey):
            raise ProtocolError("stored signing key is not RSA")
        return key

    def directory_entry(self) -> dict[str, str]:
        return {
            "identity_id": self.identity_id,
            "nickname": self.nickname,
            "signing_key": b64e(self.signing_der),
            "encryption_key": b64e(self.encryption_der),
            "signing_fingerprint": fingerprint(self.signing_der),
            "encryption_fingerprint": fingerprint(self.encryption_der),
        }


class IdentityRegistry:
    """Persistent public-key bindings. This is TOFU, not a PKI."""

    def __init__(self, path: Path):
        self.path = path
        self.records: dict[str, Identity] = {}

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("wrong format")
            if document.get("version") != PROTOCOL_VERSION or not isinstance(document.get("identities"), dict):
                raise ValueError("wrong format")
            if len(document["identities"]) > MAX_IDENTITIES:
                raise ValueError("identity registry exceeds the configured limit")
            for identity, record in document["identities"].items():
                if not isinstance(record, dict):
                    raise ValueError("identity record is invalid")
                _sign, signing_der = load_public_key(record["signing_key"], "stored signing_key")
                _enc, encryption_der = load_public_key(record["encryption_key"], "stored encryption_key")
                if signing_der == encryption_der:
                    raise ValueError("stored signing and encryption keys must differ")
                if identity != client_id(signing_der):
                    raise ValueError("identity ID does not match signing key")
                self.records[identity] = Identity(identity, valid_nickname(record["nickname"]), signing_der, encryption_der)
        except (OSError, ValueError, KeyError, TypeError, ProtocolError) as exc:
            raise RuntimeError(f"Refusing to start with a corrupt identity registry: {exc}") from exc

    def add_or_validate(self, identity: Identity) -> None:
        existing = self.records.get(identity.identity_id)
        if existing is None:
            if len(self.records) >= MAX_IDENTITIES:
                raise ProtocolError("relay identity capacity reached")
            self.records[identity.identity_id] = identity
            self.save()
        elif existing != identity:
            raise ProtocolError("identity already exists with a different name or key; use the original identity")

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "version": PROTOCOL_VERSION,
            "identities": {
                identity: {
                    "nickname": record.nickname,
                    "signing_key": b64e(record.signing_der),
                    "encryption_key": b64e(record.encryption_der),
                }
                for identity, record in self.records.items()
            },
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.replace(temporary, self.path)


@dataclass
class RateLimiter:
    capacity: float = 20.0
    refill_per_second: float = 5.0
    tokens: float = 20.0
    updated: float = field(default_factory=time.monotonic)

    def allow(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.refill_per_second)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


@dataclass
class Session:
    websocket: Any
    identity: Identity
    limiter: RateLimiter = field(default_factory=RateLimiter)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_rate_notice: float = 0.0


registry = IdentityRegistry(IDENTITY_FILE)
sessions: dict[str, Session] = {}
connection_count = 0
connection_lock = asyncio.Lock()


async def send(websocket: Any, packet: dict[str, Any], lock: asyncio.Lock | None = None) -> bool:
    data = json.dumps(packet, separators=(",", ":"), ensure_ascii=False)
    if len(data.encode("utf-8")) > MAX_FRAME_BYTES:
        return False
    try:
        if lock:
            async with lock:
                await asyncio.wait_for(websocket.send(data), SEND_TIMEOUT)
        else:
            await asyncio.wait_for(websocket.send(data), SEND_TIMEOUT)
        return True
    except (TimeoutError, OSError, websockets.exceptions.WebSocketException):
        return False


async def send_session(session: Session, packet: dict[str, Any]) -> bool:
    return await send(session.websocket, packet, session.send_lock)


def packet_from(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise ProtocolError("frame is not text")
    try:
        encoded_size = len(raw.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ProtocolError("frame is not valid UTF-8") from exc
    if encoded_size > MAX_FRAME_BYTES:
        raise ProtocolError("frame is too large")
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolError("packet is not JSON") from exc
    if not isinstance(result, dict):
        raise ProtocolError("packet must be a JSON object")
    return result


def parse_identity(packet: dict[str, Any], challenge: bytes) -> Identity:
    if packet.get("type") != "IDENTIFY" or packet.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("expected protocol-v2 IDENTIFY")
    nickname = valid_nickname(packet.get("nickname"))
    identity = valid_id(packet.get("identity_id"))
    signing_key, signing_der = load_public_key(packet.get("signing_key"), "signing_key")
    _encryption_key, encryption_der = load_public_key(packet.get("encryption_key"), "encryption_key")
    if signing_der == encryption_der:
        raise ProtocolError("signing_key and encryption_key must be different")
    signature = b64d(packet.get("signature"), "signature", MAX_RSA_BLOB_BYTES)
    if len(signature) < MIN_RSA_BLOB_BYTES:
        raise ProtocolError("signature has an invalid length")
    if identity != client_id(signing_der):
        raise ProtocolError("identity_id does not match signing_key")
    if not verify_signature(signing_key, signature, identify_data(challenge, identity, nickname, signing_der, encryption_der)):
        raise ProtocolError("identity signature is invalid")
    return Identity(identity, nickname, signing_der, encryption_der)


def parse_envelope(packet: dict[str, Any], sender: Identity) -> dict[str, Any]:
    if packet.get("type") != "MESSAGE" or packet.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported packet type")
    sender_id = valid_id(packet.get("sender_id"), "sender_id")
    recipient_id = valid_id(packet.get("recipient_id"), "recipient_id")
    if sender_id != sender.identity_id:
        raise ProtocolError("sender_id cannot be forged")
    if sender_id == recipient_id:
        raise ProtocolError("sender and recipient must differ")
    message_id = b64d(packet.get("message_id"), "message_id", 16, 16)
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
    if not verify_signature(sender.signing_key(), signature, signed):
        raise ProtocolError("message signature is invalid")
    # Rebuild it from canonical bytes: optional caller fields are never propagated.
    return {
        "type": "MESSAGE", "v": PROTOCOL_VERSION,
        "message_id": b64e(message_id), "sender_id": sender_id, "recipient_id": recipient_id,
        "encrypted_key": b64e(wrapped_key), "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext), "signature": b64e(signature),
    }


def directory(except_id: str) -> list[dict[str, str]]:
    return [session.identity.directory_entry() for identity, session in sessions.items() if identity != except_id]


def directory_chunks(except_id: str) -> list[list[dict[str, str]]]:
    """Split the directory so no packet approaches the WebSocket frame limit."""
    chunks: list[list[dict[str, str]]] = []
    current: list[dict[str, str]] = []
    current_size = 2  # JSON array brackets
    for entry in directory(except_id):
        encoded = json.dumps(entry, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if current and current_size + len(encoded) + 1 > DIRECTORY_CHUNK_BYTES:
            chunks.append(current)
            current = []
            current_size = 2
        current.append(entry)
        current_size += len(encoded) + 1
    if current or not chunks:
        chunks.append(current)
    return chunks


async def send_directory(session: Session, except_id: str, auth_ok: bool = False) -> bool:
    chunks = directory_chunks(except_id)
    packet: dict[str, Any] = {
        "type": "AUTH_OK" if auth_ok else "USER_LIST",
        "v": PROTOCOL_VERSION,
        "peers": chunks[0],
        "directory_complete": len(chunks) == 1,
    }
    if auth_ok:
        packet["identity_id"] = session.identity.identity_id
    if not await send_session(session, packet):
        return False
    for index, chunk in enumerate(chunks[1:], start=1):
        if not await send_session(session, {
            "type": "USER_LIST", "v": PROTOCOL_VERSION, "peers": chunk,
            "directory_complete": index == len(chunks) - 1,
        }):
            return False
    return True


async def broadcast(packet: dict[str, Any], except_id: str | None = None) -> None:
    targets = [session for identity, session in sessions.items() if identity != except_id]
    await asyncio.gather(*(send_session(target, packet) for target in targets), return_exceptions=True)


async def handle_client(websocket: Any) -> None:
    global connection_count
    async with connection_lock:
        over_capacity = connection_count >= MAX_CONNECTIONS
        if not over_capacity:
            connection_count += 1
    if over_capacity:
        await send(websocket, {"type": "ERROR", "code": "SERVER_BUSY", "msg": "Relay is at capacity; try again later."})
        return

    session: Session | None = None
    announced = False
    try:
        challenge = os.urandom(32)
        if not await send(websocket, {"type": "HELLO", "v": PROTOCOL_VERSION, "challenge": b64e(challenge)}):
            return
        identity = parse_identity(packet_from(await asyncio.wait_for(websocket.recv(), IDENTIFY_TIMEOUT)), challenge)
        if identity.identity_id in sessions:
            await send(websocket, {"type": "ERROR", "code": "IDENTITY_ONLINE", "msg": "This identity is already connected."})
            return
        registry.add_or_validate(identity)
        session = Session(websocket, identity)
        sessions[identity.identity_id] = session

        if not await send_directory(session, identity.identity_id, auth_ok=True):
            return
        await broadcast({"type": "USER_JOINED", "v": PROTOCOL_VERSION, "peer": identity.directory_entry()}, identity.identity_id)
        announced = True
        print(f"[+] {identity.nickname} [{identity.identity_id[:12]}] connected")

        async for raw in websocket:
            try:
                if not session.limiter.allow():
                    # Do not turn a flood into an error-message amplifier.
                    now = time.monotonic()
                    if now - session.last_rate_notice >= 5:
                        session.last_rate_notice = now
                        await send_session(session, {"type": "ERROR", "code": "RATE_LIMIT", "msg": "Slow down."})
                    continue
                packet = packet_from(raw)
                if packet.get("type") == "MESSAGE":
                    envelope = parse_envelope(packet, session.identity)
                    recipient = sessions.get(envelope["recipient_id"])
                    if recipient is None:
                        await send_session(session, {"type": "ERROR", "code": "OFFLINE", "msg": "Recipient is offline."})
                    elif not await send_session(recipient, envelope):
                        await send_session(session, {"type": "ERROR", "code": "DELIVERY_FAILED", "msg": "Recipient could not receive the message."})
                    else:
                        print(f"[>] {session.identity.identity_id[:12]} -> {recipient.identity.identity_id[:12]} (encrypted)")
                elif packet.get("type") == "LIST_USERS" and packet.get("v") == PROTOCOL_VERSION:
                    if not await send_directory(session, session.identity.identity_id):
                        return
                else:
                    await send_session(session, {"type": "ERROR", "code": "UNSUPPORTED", "msg": "Unsupported packet."})
            except ProtocolError as exc:
                await send_session(session, {"type": "ERROR", "code": "MALFORMED", "msg": str(exc)})
    except TimeoutError:
        await send(websocket, {"type": "ERROR", "code": "IDENTIFY_TIMEOUT", "msg": "Identity handshake timed out."})
    except websockets.exceptions.ConnectionClosed:
        pass
    except ProtocolError as exc:
        await send(websocket, {"type": "ERROR", "code": "AUTH_FAILED", "msg": str(exc)})
    except Exception:
        logging.exception("Unexpected server error")
    finally:
        try:
            if session and sessions.get(session.identity.identity_id) is session:
                sessions.pop(session.identity.identity_id, None)
                print(f"[-] {session.identity.nickname} [{session.identity.identity_id[:12]}] disconnected")
                if announced:
                    await broadcast({
                        "type": "USER_LEFT", "v": PROTOCOL_VERSION,
                        "identity_id": session.identity.identity_id, "nickname": session.identity.nickname,
                    }, session.identity.identity_id)
        finally:
            async with connection_lock:
                connection_count -= 1


STATIC_FILES = {
    "/": (Path(__file__).resolve().parent / "index.html", "text/html; charset=utf-8"),
    "/index.html": (Path(__file__).resolve().parent / "index.html", "text/html; charset=utf-8"),
    "/app.js": (Path(__file__).resolve().parent / "app.js", "text/javascript; charset=utf-8"),
    "/styles.css": (Path(__file__).resolve().parent / "styles.css", "text/css; charset=utf-8"),
    "/favicon.svg": (Path(__file__).resolve().parent / "favicon.svg", "image/svg+xml"),
}
STATIC_CACHE: dict[Path, tuple[int, int, bytes]] = {}

SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    (
        "Content-Security-Policy",
        (
            "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
            "form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*; worker-src 'none'; manifest-src 'none'"
        ),
    ),
)


def static_body(path: Path) -> bytes | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    cached = STATIC_CACHE.get(path)
    if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]
    try:
        body = path.read_bytes()
    except OSError:
        return None
    STATIC_CACHE[path] = (stat.st_mtime_ns, stat.st_size, body)
    return body


def plain_response(status_code: int, reason: str, body: bytes) -> Response:
    headers = Headers([
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Cache-Control", "no-store"),
        *SECURITY_HEADERS,
    ])
    return Response(status_code=status_code, reason_phrase=reason, headers=headers, body=body)


def websocket_origins() -> list[Origin | None]:
    """Only explicitly approved web origins may open a browser WebSocket.

    CLI clients do not send an Origin header and remain represented by None.
    Set CHAT_ALLOWED_ORIGINS to comma-separated HTTPS origins, for example
    https://chat.example.com. This prevents a hostile website from opening a
    WebSocket in a logged-in user's browser context.
    """
    configured = [Origin(item.strip()) for item in os.environ.get("CHAT_ALLOWED_ORIGINS", "").split(",") if item.strip()]
    return [None, *configured]


async def process_request(connection: Any, request: Any) -> Response | None:
    if request.headers.get("Upgrade", "").lower() == "websocket":
        return None
    path = request.path.split("?", 1)[0]
    if path == "/healthz":
        body = json.dumps({"status": "ok", "app": APP_NAME, "version": VERSION}).encode("utf-8")
        return Response(
            status_code=200, reason_phrase="OK",
            headers=Headers([
                ("Content-Type", "application/json; charset=utf-8"),
                ("Cache-Control", "no-store"),
                *SECURITY_HEADERS,
            ]),
            body=body,
        )
    static = STATIC_FILES.get(path)
    if static is None:
        return plain_response(404, "Not Found", b"Not Found\n")
    file, content_type = static
    static_data = static_body(file)
    if static_data is None:
        return plain_response(404, "Not Found", b"Web client asset is missing.\n")
    return Response(
        status_code=200, reason_phrase="OK",
        headers=Headers([
            ("Content-Type", content_type),
            ("Cache-Control", "no-store"),
            *SECURITY_HEADERS,
        ]),
        body=static_data,
    )


def tls_context() -> ssl.SSLContext | None:
    certificate, private_key = os.environ.get("CHAT_TLS_CERT"), os.environ.get("CHAT_TLS_KEY")
    if not certificate and not private_key:
        return None
    if not certificate or not private_key:
        raise RuntimeError("Set both CHAT_TLS_CERT and CHAT_TLS_KEY, or neither.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certificate, private_key)
    return context


async def main() -> None:
    registry.load()
    context = tls_context()
    transport = "wss" if context else "ws behind a TLS-terminating reverse proxy"
    origins = websocket_origins()
    print(f"{APP_NAME} v{VERSION} relay on {HOST}:{PORT} ({transport})")
    print("The relay sees public keys and routing metadata, never message plaintext.")
    if len(origins) == 1:
        print("[!] Browser WebSockets are disabled until CHAT_ALLOWED_ORIGINS is configured.")
    else:
        print(f"[*] Browser origins allowed: {', '.join(origin for origin in origins if origin)}")
    print(f"[*] Limits: {MAX_CONNECTIONS} connections, {MAX_IDENTITIES} pinned identities")
    async with websockets.serve(
        handle_client, HOST, PORT, ssl=context, process_request=process_request, origins=origins,
        max_size=MAX_FRAME_BYTES, max_queue=16, ping_interval=20, ping_timeout=20, close_timeout=5,
        compression=None,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
