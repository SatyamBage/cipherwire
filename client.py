"""
ZeroTrust Chat — client.py
Transport  : WebSocket (asyncio + websockets library)
Auth       : RSA-2048 Challenge-Response
Encryption : AES-256-GCM per message, session key RSA-wrapped
Compatible : Linux, Android/Termux, Windows
"""

import asyncio
import websockets
import rsa
import json
import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Config — change SERVER_URL to your Cloudflare tunnel URL ─────────────────
SERVER_URL = "wss://disciplines-briefing-inserted-accepted.trycloudflare.com"  
# SERVER_URL = "wss://your-name.trycloudflare.com"   # ← internet deployment

# ── Load RSA Identity ─────────────────────────────────────────────────────────
try:
    with open('.keys/public.pem',  'rb') as f: pub_data  = f.read()
    with open('.keys/private.pem', 'rb') as f: priv_data = f.read()
    public_key  = rsa.PublicKey.load_pkcs1(pub_data)
    private_key = rsa.PrivateKey.load_pkcs1(priv_data)
except FileNotFoundError:
    print("[!] Keys not found. Run setup_keys.py first.")
    exit(1)

# ── State ─────────────────────────────────────────────────────────────────────
peer_keys          = {}     # nickname.lower() -> rsa.PublicKey
peer_fingerprints  = {}     # nickname.lower() -> fingerprint string
encryption_enabled = True
my_nickname        = ""

# ── Helpers ───────────────────────────────────────────────────────────────────

def fingerprint(pub_pem_bytes: bytes) -> str:
    h = hashlib.sha256(pub_pem_bytes).hexdigest()[:16].upper()
    return ':'.join(h[i:i+4] for i in range(0, 16, 4))

def encrypt_message(plaintext: str, target: str):
    """Returns (encrypted_key_b64, nonce_b64, ciphertext_b64) or raises."""
    target_pub = peer_keys[target.lower()]

    session_key = AESGCM.generate_key(bit_length=256)   # True 256-bit
    aesgcm      = AESGCM(session_key)
    nonce       = os.urandom(12)                         # 96-bit GCM nonce
    ciphertext  = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    enc_key     = rsa.encrypt(session_key, target_pub)

    # Volatile key — wipe from memory immediately
    session_key = os.urandom(32)
    del session_key

    return (
        base64.b64encode(enc_key).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(ciphertext).decode()
    )

def decrypt_message(enc_key_b64: str, nonce_b64: str, ct_b64: str) -> str:
    """Decrypts and authenticates. Raises on tamper/bad key."""
    session_key = rsa.decrypt(base64.b64decode(enc_key_b64), private_key)
    aesgcm      = AESGCM(session_key)
    nonce       = base64.b64decode(nonce_b64)
    ciphertext  = base64.b64decode(ct_b64)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

# ── Burn Protocol ─────────────────────────────────────────────────────────────

def burn_keys():
    """Overwrite key files with random bytes, then delete — prevents forensic recovery."""
    print("\n[!!!] BURN PROTOCOL ACTIVATED")
    for path in ['.keys/private.pem', '.keys/public.pem']:
        if os.path.exists(path):
            size = os.path.getsize(path)
            with open(path, 'wb') as f:
                f.write(os.urandom(size))   # overwrite with noise
            os.remove(path)
            print(f"      Shredded: {path}")
    try:
        os.rmdir('.keys')
    except Exception:
        pass
    print("[!!!] Identity destroyed. Keys are unrecoverable.\n")

# ── Receive Loop ──────────────────────────────────────────────────────────────

async def receive_loop(ws):
    async for raw in ws:
        try:
            packet = json.loads(raw)
            ptype  = packet.get("type")

            # ── Peer key directory sync on connect ────────────────────────────
            if ptype == "AUTH_OK":
                # Already handled in handshake — this branch won't fire normally
                pass

            # ── New peer joined ───────────────────────────────────────────────
            elif ptype == "USER_JOINED":
                nick    = packet["nickname"]
                pub_pem = base64.b64decode(packet["public_key"])
                fp      = packet.get("fingerprint", fingerprint(pub_pem))
                peer_keys[nick.lower()]         = rsa.PublicKey.load_pkcs1(pub_pem)
                peer_fingerprints[nick.lower()] = fp
                print(f"\n[+] {nick} came online  |  {fp}")

            # ── Peer left ─────────────────────────────────────────────────────
            elif ptype == "USER_LEFT":
                nick = packet["nickname"]
                peer_keys.pop(nick.lower(), None)
                peer_fingerprints.pop(nick.lower(), None)
                print(f"\n[-] {nick} went offline.")

            # ── Incoming encrypted message ────────────────────────────────────
            elif ptype == "MESSAGE":
                sender = packet["from"]

                # Demo mode — plaintext (E2EE deliberately disabled)
                if packet.get("plaintext_demo"):
                    print(f"\n[⚠️  PLAINTEXT from {sender}]: {packet['plaintext_demo']}")
                    continue

                try:
                    plaintext = decrypt_message(
                        packet["encrypted_key"],
                        packet["nonce"],
                        packet["ciphertext"]
                    )
                    fp = peer_fingerprints.get(sender.lower(), "unknown")
                    print(f"\n[🛡️  {sender} | {fp}]: {plaintext}")
                except Exception:
                    print(f"\n[!] Integrity check FAILED from {sender} — message rejected.")

            # ── Server info / error messages ──────────────────────────────────
            elif ptype == "SERVER_MSG":
                print(f"\n[Server]: {packet['msg']}")

            elif ptype == "ERROR":
                print(f"\n[!] Server error: {packet['msg']}")

        except (json.JSONDecodeError, KeyError) as e:
            print(f"\n[!] Malformed packet received: {e}")

# ── Send Loop ─────────────────────────────────────────────────────────────────

async def send_loop(ws):
    global encryption_enabled

    loop = asyncio.get_event_loop()

    while True:
        text = await loop.run_in_executor(None, input, "")
        text = text.strip()
        if not text:
            continue

        # ── Toggle E2EE (for packet sniff demonstration) ──────────────────────
        if text == '/encrypt off':
            encryption_enabled = False
            print("[⚠️]  E2EE DISABLED — messages will be sent in PLAINTEXT (demo mode).")
            continue

        elif text == '/encrypt on':
            encryption_enabled = True
            print("[🛡️]  E2EE ENABLED — AES-256-GCM active.")
            continue

        # ── /users command ────────────────────────────────────────────────────
        elif text == '/users':
            await ws.send(json.dumps({"type": "COMMAND", "cmd": "/users"}))
            continue

        # ── /burn panic protocol ──────────────────────────────────────────────
        elif text == '/burn':
            confirm = await loop.run_in_executor(None, input,
                "[!!!] Confirm BURN — type YES to shred all keys: ")
            if confirm.strip() == "YES":
                await ws.send(json.dumps({"type": "BURN"}))
                burn_keys()
                print("[!!!] Disconnecting.")
                await ws.close()
                return
            else:
                print("[*] Burn cancelled.")
            continue

        # ── /help ─────────────────────────────────────────────────────────────
        elif text == '/help':
            print("""
─────────────────────────────────────────
  ZeroTrust Chat — Commands
─────────────────────────────────────────
  @user <message>   Send E2EE DM
  /users            List online users
  /encrypt off      Disable E2EE (demo)
  /encrypt on       Re-enable E2EE
  /burn             Panic — shred keys
  /quit             Disconnect
─────────────────────────────────────────""")
            continue

        # ── /quit ─────────────────────────────────────────────────────────────
        elif text == '/quit':
            await ws.close()
            print("[*] Disconnected safely.")
            return

        # ── Direct Message ────────────────────────────────────────────────────
        elif text.startswith('@'):
            parts = text.split(' ', 1)
            if len(parts) < 2:
                print("[!] Usage: @username message")
                continue

            target     = parts[0][1:].strip()
            actual_msg = parts[1]

            if not encryption_enabled:
                # Plaintext demo mode — intentionally insecure for demonstration
                await ws.send(json.dumps({
                    "type"          : "MESSAGE",
                    "to"            : target,
                    "encrypted_key" : "",
                    "nonce"         : "",
                    "ciphertext"    : "",
                    "plaintext_demo": actual_msg
                }))
                print(f"[⚠️  Sent PLAINTEXT to {target}] — visible to packet sniffer")
                continue

            if target.lower() not in peer_keys:
                print(f"[!] No public key for '{target}'. Are they online? (/users to check)")
                continue

            try:
                enc_key, nonce, ciphertext = encrypt_message(actual_msg, target)
                await ws.send(json.dumps({
                    "type"          : "MESSAGE",
                    "to"            : target,
                    "encrypted_key" : enc_key,
                    "nonce"         : nonce,
                    "ciphertext"    : ciphertext
                }))
                fp = peer_fingerprints.get(target.lower(), "?")
                print(f"[🛡️  Sent AES-256-GCM to {target} | {fp}]")
            except Exception as e:
                print(f"[!] Encryption failed: {e}")

        else:
            print("[!] Use @username <message> to send a DM. Type /help for commands.")


# ── Handshake ─────────────────────────────────────────────────────────────────

async def main():
    global my_nickname

    my_nickname = input("Enter your display name: ").strip()
    if not my_nickname:
        print("[!] Nickname cannot be empty.")
        return

    fp_self = fingerprint(pub_data)
    print(f"\n[*] Your fingerprint: {fp_self}")
    print(f"[*] Connecting to {SERVER_URL} ...\n")

    try:
        print(f"[DEBUG 1] Attempting WebSocket connection to {SERVER_URL} ...")
        async with websockets.connect(SERVER_URL, max_size=2**20) as ws:
            print("[DEBUG 2] TCP+WebSocket connection established.")

            # ── Receive IDENTIFY ──────────────────────────────────────────────
            print("[DEBUG 3] Waiting for IDENTIFY challenge from server...")
            raw = await ws.recv()
            print(f"[DEBUG 4] Raw received: {raw[:120]}")

            msg = json.loads(raw)
            if msg.get("type") != "IDENTIFY":
                print(f"[!] Expected IDENTIFY, got: {msg}")
                return

            challenge = bytes.fromhex(msg["challenge"])
            print(f"[DEBUG 5] Challenge received ({len(challenge)} bytes). Signing...")

            # ── Sign challenge with private key ───────────────────────────────
            signature = rsa.sign(challenge, private_key, 'SHA-256')
            print(f"[DEBUG 6] Signature generated ({len(signature)} bytes). Sending identity...")

            await ws.send(json.dumps({
                "nickname"   : my_nickname,
                "public_key" : pub_data.decode(),
                "signature"  : signature.hex()
            }))
            print("[DEBUG 7] Identity packet sent. Waiting for AUTH_OK...")

            # ── Receive AUTH_OK ───────────────────────────────────────────────
            raw  = await ws.recv()
            print(f"[DEBUG 8] Raw received: {raw[:120]}")
            auth = json.loads(raw)

            if auth.get("type") == "ERROR":
                print(f"[!] Server rejected connection: {auth['msg']}")
                return

            if auth.get("type") != "AUTH_OK":
                print(f"[!] Unexpected packet type: {auth.get('type')} — full: {auth}")
                return

            server_fp = auth.get("fingerprint", "")
            print(f"[✓] Authenticated as '{my_nickname}'  |  fingerprint: {server_fp}")

            # ── Load peer keys from directory ─────────────────────────────────
            for nick, peer_data in auth.get("peer_keys", {}).items():
                # Extract the actual key string from the server's data dictionary
                b64_pem = peer_data.get("key") 
                
                pub_pem = base64.b64decode(b64_pem)
                peer_keys[nick.lower()]         = rsa.PublicKey.load_pkcs1(pub_pem)
                peer_fingerprints[nick.lower()] = fingerprint(pub_pem)
            if peer_keys:
                print(f"[*] Loaded keys for: {', '.join(peer_fingerprints.keys())}")
            else:
                print("[*] No other users online yet.")

            print("\nType /help for commands.\n")

            # ── Run both loops concurrently ───────────────────────────────────
            print("[DEBUG 9] Entering send/receive loops...")
            try:
                recv_task = asyncio.create_task(receive_loop(ws), name="recv")
                send_task = asyncio.create_task(send_loop(ws),   name="send")
                done, pending = await asyncio.wait(
                    [recv_task, send_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                for task in done:
                    exc = task.exception()
                    if exc:
                        import traceback
                        print(f"[DEBUG] Loop '{task.get_name()}' raised: {type(exc).__name__}: {exc}")
                        traceback.print_exception(type(exc), exc, exc.__traceback__)
            except Exception as loop_err:
                import traceback
                print(f"[DEBUG] Loop error: {type(loop_err).__name__}: {loop_err}")
                traceback.print_exc()

    except ConnectionRefusedError:
        print(f"\n[!] Could not connect to {SERVER_URL}")
        print("    → Is server.py running?")
        print("    → Is the port correct?")
    except websockets.exceptions.InvalidURI as e:
        print(f"\n[!] Invalid SERVER_URL: {e}")
    except websockets.exceptions.WebSocketException as e:
        print(f"\n[!] WebSocket error: {type(e).__name__}: {e}")
    except Exception as e:
        import traceback
        print(f"\n[!] Unexpected error: {type(e).__name__}: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())