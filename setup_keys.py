import rsa
import os

def generate_identity():
    print("=" * 45)
    print("   ZeroTrust Chat — Identity Forge")
    print("=" * 45)
    print("\n[*] Generating 2048-bit RSA Key Pair...")
    print("    (This may take a few seconds...)\n")

    public_key, private_key = rsa.newkeys(2048)

    os.makedirs('.keys', exist_ok=True)

    with open('.keys/private.pem', 'wb') as f:
        f.write(private_key.save_pkcs1('PEM'))

    with open('.keys/public.pem', 'wb') as f:
        f.write(public_key.save_pkcs1('PEM'))

    # Compute a short fingerprint for display (first 16 hex chars of pub key hash)
    import hashlib
    pub_bytes  = public_key.save_pkcs1('PEM')
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:32].upper()
    formatted   = ':'.join(fingerprint[i:i+4] for i in range(0, 32, 4))

    print("[SUCCESS] Cryptographic identity created.")
    print(f"\n  Private Key  →  .keys/private.pem  (NEVER share this)")
    print(f"  Public Key   →  .keys/public.pem   (Safe to share)")
    print(f"\n  Key Fingerprint:")
    print(f"  {formatted}")
    print("\n[!] Keep .keys/private.pem secure. It IS your identity.\n")

if __name__ == "__main__":
    generate_identity()