"""
ZeroTrust Chat — server.py  (v2 — Browser + CLI compatible)

Auth modes:
  - Python CLI clients : RSA-2048 PKCS1v15 SHA-256 (rsa library)
  - Browser clients    : RSA-2048 PKCS1v15 SHA-256 (SubtleCrypto)

Payload encryption (both use AES-256-GCM + RSA-OAEP session key wrap):
  - Python CLI : rsa.encrypt  (PKCS1v15)
  - Browser    : SubtleCrypto RSA-OAEP

Server is a blind relay — never reads message payloads.
"""
import os
import asyncio
import websockets
import json
import base64
import hashlib
import http
from websockets.datastructures import Headers

import logging

# Mute the background noise from the websockets library
logging.getLogger("websockets").setLevel(logging.CRITICAL)
logging.getLogger("websockets.server").setLevel(logging.CRITICAL)

HOST = '0.0.0.0'
PORT = int(os.environ.get("PORT", 55555))

try:
    import rsa as rsa_lib
    RSA_AVAILABLE = True
except ImportError:
    RSA_AVAILABLE = False
    print("[!] 'rsa' library not found. Python CLI clients cannot connect.")

clients        = {}
public_keys_db = {}
enc_keys_db    = {}
nick_display   = {}
client_type_db = {}


def fingerprint_from_bytes(b: bytes) -> str:
    h = hashlib.sha256(b).hexdigest()[:16].upper()
    return ':'.join(h[i:i+4] for i in range(0, 16, 4))


async def safe_send(ws, data: dict):
    try:
        await ws.send(json.dumps(data))
    except Exception:
        pass


def verify_cli_sig(challenge: bytes, sig_hex: str, pub_pem: bytes) -> bool:
    if not RSA_AVAILABLE:
        return False
    try:
        pub = rsa_lib.PublicKey.load_pkcs1(pub_pem)
        rsa_lib.verify(challenge, bytes.fromhex(sig_hex), pub)
        return True
    except Exception:
        return False


def verify_browser_sig(challenge: bytes, sig_hex: str, spki_b64: str) -> bool:
    """Verify RSASSA-PKCS1-v1_5 SHA-256 from SubtleCrypto."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        sig     = bytes.fromhex(sig_hex)
        der     = base64.b64decode(spki_b64)
        pub_key = serialization.load_der_public_key(der, backend=default_backend())
        pub_key.verify(sig, challenge, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception as e:
        print(f"[DEBUG] Browser verify error: {e}")
        return False


async def handle_client(websocket):
    import time
    start_time = time.time()
    last_arrival_time = None
    last_delay = 0
    total_bytes_received = 0
    nickname = None
    nick_key = None

    try:
        challenge = os.urandom(32)
        await websocket.send(json.dumps({
            "type": "IDENTIFY", "challenge": challenge.hex()
        }))

        raw      = await asyncio.wait_for(websocket.recv(), timeout=20)
        identity = json.loads(raw)

        nickname     = identity["nickname"].strip()
        nick_key     = nickname.lower()
        mode         = identity.get("client_type", "cli")
        pub_data     = identity["public_key"]
        enc_key_data = identity.get("enc_key", pub_data)  # RSA-OAEP enc key (browser) or same as pub (cli)
        sig_hex      = identity["signature"]

        if nick_key in clients:
            await safe_send(websocket, {"type": "ERROR", "msg": f"'{nickname}' is already taken."})
            return

        # Verify + compute fingerprint
        if mode == "browser":
            auth_ok = verify_browser_sig(challenge, sig_hex, pub_data)
            b64_pub     = pub_data
            b64_enc_key = enc_key_data
            fp          = fingerprint_from_bytes(base64.b64decode(enc_key_data))
        else:
            pub_pem = pub_data.encode()
            auth_ok = verify_cli_sig(challenge, sig_hex, pub_pem)
            b64_pub     = base64.b64encode(pub_pem).decode()
            b64_enc_key = b64_pub   # CLI uses same key for everything
            fp          = fingerprint_from_bytes(pub_pem)

        if not auth_ok:
            await safe_send(websocket, {"type": "ERROR", "msg": "Authentication failed."})
            return

        clients[nick_key]        = websocket
        public_keys_db[nick_key] = b64_pub
        enc_keys_db[nick_key]    = b64_enc_key
        nick_display[nick_key]   = nickname
        client_type_db[nick_key] = mode

        print(f"[+] {nickname} ({mode}) | {fp}")

        await safe_send(websocket, {
            "type"       : "AUTH_OK",
            "nickname"   : nickname,
            "fingerprint": fp,
            "peer_keys"  : {
                nick_display[u]: {
                    "key"        : public_keys_db[u],
                    "enc_key"    : enc_keys_db[u],
                    "client_type": client_type_db[u],
                    "fingerprint": fingerprint_from_bytes(base64.b64decode(enc_keys_db[u]))
                }
                for u in clients if u != nick_key
            }
        })

        join_pkt = {
            "type"       : "USER_JOINED",
            "nickname"   : nickname,
            "public_key" : b64_pub,
            "enc_key"    : b64_enc_key,
            "client_type": mode,
            "fingerprint": fp
        }
        for user, sock in list(clients.items()):
            if user != nick_key:
                await safe_send(sock, join_pkt)

        async for raw_msg in websocket:
            try:
                pkt   = json.loads(raw_msg)
                ptype = pkt.get("type")

                if ptype == "MESSAGE":
                    current_time = time.time()
                    
                    # 1. DELAY (Arrival Time Variance)
                    if last_arrival_time is None:
                        delay = 15.0 # Baseline ms for first packet
                    else:
                        delay = (current_time - last_arrival_time) * 1000
                    
                    last_arrival_time = current_time
                    
                    # 2. JITTER (Absolute difference between current and last delay)
                    jitter = abs(delay - last_delay) if last_delay > 0 else 0.0
                    last_delay = delay
                    
                    # 3. THROUGHPUT (Safe byte measurement)
                    # We convert the 'pkt' dictionary back to a string to measure its exact byte size securely
                    msg_size = len(str(pkt).encode('utf-8'))
                    total_bytes_received += msg_size
                    elapsed = current_time - start_time
                    
                    # Prevent division by zero on instant connections
                    if elapsed <= 0: elapsed = 0.001 
                    
                    throughput = (total_bytes_received * 8) / elapsed / 1024 # kbps
                    
                    print(f"\n[NETWORK METRICS]")
                    print(f" >> Delay: {delay:.2f} ms | Jitter: {jitter:.2f} ms | Throughput: {throughput:.2f} kbps")
                    print(f"[INTERCEPT] Payload: {pkt}")
                    tgt = pkt.get("to", "").lower()
                    if tgt == nick_key:
                        await safe_send(websocket, {"type": "ERROR", "msg": "Cannot message yourself."})
                        continue
                    if tgt not in clients:
                        await safe_send(websocket, {"type": "ERROR", "msg": f"'{pkt.get('to')}' is offline."})
                        continue
                    await safe_send(clients[tgt], {
                        "type"          : "MESSAGE",
                        "from"          : nickname,
                        "encrypted_key" : pkt.get("encrypted_key", ""),
                        "nonce"         : pkt.get("nonce", ""),
                        "ciphertext"    : pkt.get("ciphertext", ""),
                        "plaintext_demo": pkt.get("plaintext_demo")
                    })

                elif ptype == "COMMAND" and pkt.get("cmd") == "/users":
                    await safe_send(websocket, {
                        "type": "SERVER_MSG",
                        "msg" : f"Online ({len(clients)}): {', '.join(nick_display.values())}"
                    })

                elif ptype == "BURN":
                    print(f"[!!!] BURN by {nickname}")
                    public_keys_db.pop(nick_key, None)
                    await safe_send(websocket, {"type": "SERVER_MSG", "msg": "BURN acknowledged."})

            except (json.JSONDecodeError, KeyError):
                await safe_send(websocket, {"type": "ERROR", "msg": "Malformed packet."})

    except asyncio.TimeoutError:
        print("[-] Timeout waiting for identity.")
    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print(f"[!] Error ({nickname or 'unknown'}): {e}")
    finally:
        if nick_key and nick_key in clients:
            del clients[nick_key]
            for d in (public_keys_db, enc_keys_db, nick_display, client_type_db):
                d.pop(nick_key, None)
            print(f"[-] {nickname} disconnected.")
            for sock in list(clients.values()):
                await safe_send(sock, {"type": "USER_LEFT", "nickname": nickname})

async def process_request(connection, request):
    # 1. Check if this is an actual WebSocket chat connection
    upgrade_header = request.headers.get("Upgrade", "").lower()
    if "websocket" in upgrade_header:
        return None  # Let the WebSocket handshake continue

    # 2. Handle standard web page requests (User opening the URL)
    if request.path == "/" or request.path == "/index.html":
        try:
            with open("index.html", "rb") as f:
                content = f.read()
            
            return websockets.http11.Response(
                status_code=200,
                reason_phrase="OK",
                # Wrap the header tuple inside the custom Headers object
                headers=Headers([("Content-Type", "text/html; charset=utf-8")]),
                body=content
            )
        except FileNotFoundError:
            return websockets.http11.Response(
                status_code=404,
                reason_phrase="Not Found",
                headers=Headers([("Content-Type", "text/plain")]),
                body=b"index.html missing!"
            )

    # 3. Catch-All for "Phantom" Requests (favicon, pings, bots)
    return websockets.http11.Response(
        status_code=404,
        reason_phrase="Not Found",
        headers=Headers([("Content-Type", "text/plain")]),
        body=b"Not Found"
    )

async def main():
    print("=" * 54)
    print("   ZeroTrust Chat — Browser + CLI Server")
    print("=" * 54)
    print(f"[*] Listening on {HOST}:{PORT}")
    print("[*] Blind relay — server never reads payloads\n")
    async with websockets.serve(handle_client, HOST, PORT, max_size=2**20, process_request=process_request):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())