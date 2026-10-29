from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve

import server
from client import Identity, KnownPeers, ReplayCache, decrypt_envelope, encrypt_envelope, parse_peer
from protocol import MAX_FRAME_BYTES, PROTOCOL_VERSION, b64d, b64e, canonical_public_key, identify_data


def make_identity(nickname: str) -> Identity:
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encryption = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return Identity(
        signing, encryption,
        canonical_public_key(signing.public_key()), canonical_public_key(encryption.public_key()),
    )


async def identify(ws, identity: Identity, nickname: str) -> dict:
    hello = json.loads(await ws.recv())
    assert hello["type"] == "HELLO"
    challenge = b64d(hello["challenge"], "challenge", 32, 32)
    signature = identity.signing_private.sign(
        identify_data(challenge, identity.identity_id, nickname, identity.signing_der, identity.encryption_der),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    await ws.send(json.dumps({
        "type": "IDENTIFY", "v": PROTOCOL_VERSION, "nickname": nickname,
        "identity_id": identity.identity_id,
        "signing_key": b64e(identity.signing_der), "encryption_key": b64e(identity.encryption_der),
        "signature": b64e(signature),
    }))
    response = json.loads(await ws.recv())
    assert response["type"] == "AUTH_OK"
    assert response["identity_id"] == identity.identity_id
    return response


@pytest.mark.asyncio
async def test_relay_handshake_and_delivery(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(server, "registry", server.IdentityRegistry(tmp_path / "identities.json"))
    monkeypatch.setattr(server, "sessions", {})
    monkeypatch.setattr(server, "connection_count", 0)

    alice, bob = make_identity("Alice"), make_identity("Bob")
    known_a = KnownPeers(tmp_path / "known-a.json")
    known_b = KnownPeers(tmp_path / "known-b.json")
    replay = ReplayCache(tmp_path / "seen.json")

    async with serve(
        server.handle_client, "127.0.0.1", 0, process_request=server.process_request,
        origins=None, max_size=MAX_FRAME_BYTES, compression=None,
    ) as relay:
        port = relay.sockets[0].getsockname()[1]
        url = f"ws://127.0.0.1:{port}"
        async with connect(url, max_size=MAX_FRAME_BYTES) as ws_a:
            auth_a = await identify(ws_a, alice, "Alice")
            assert auth_a["peers"] == []

            async with connect(url, max_size=MAX_FRAME_BYTES) as ws_b:
                auth_b = await identify(ws_b, bob, "Bob")
                assert len(auth_b["peers"]) == 1
                peer_a = parse_peer(auth_b["peers"][0], known_b)
                known_b.trust(peer_a)
                peer_a.verified = True

                joined = json.loads(await ws_a.recv())
                assert joined["type"] == "USER_JOINED"
                peer_b = parse_peer(joined["peer"], known_a)
                known_a.trust(peer_b)
                peer_b.verified = True

                packet = encrypt_envelope("hello over the relay", alice, peer_b)
                await ws_a.send(json.dumps(packet))
                forwarded = json.loads(await ws_b.recv())
                assert forwarded["type"] == "MESSAGE"
                sender, plaintext = decrypt_envelope(forwarded, bob, {alice.identity_id: peer_a}, replay)
                assert sender.identity_id == alice.identity_id
                assert plaintext == "hello over the relay"
                with pytest.raises(Exception, match="replayed"):
                    decrypt_envelope(forwarded, bob, {alice.identity_id: peer_a}, replay)

                # The relay rejects non-canonical message IDs instead of forwarding them.
                bad = dict(packet)
                message_id = b64d(packet["message_id"], "id", 16, 16)
                encoded = b64e(message_id)
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                index = alphabet.index(encoded[-3])
                bad["message_id"] = encoded[:-3] + alphabet[index | 1] + encoded[-2:]
                await ws_a.send(json.dumps(bad))
                error = json.loads(await ws_a.recv())
                assert error["type"] == "ERROR"
                assert error["code"] == "MALFORMED"
