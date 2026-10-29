"""Create a Cipherwire protocol-v2 identity.

The old setup script generated one unencrypted RSA key pair for both signing and
encryption. v2 uses two password-protected key pairs instead.
"""
from client import create_identity_files

if __name__ == "__main__":
    create_identity_files()
