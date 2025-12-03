#!/usr/bin/env python3
# decrypt_seed.py
import base64
import sys
from typing import Optional

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature, InvalidKey

SEED_PATH = "/data/seed.txt"  # container volume path; local run will create this too

def load_private_key(path: str):
    with open(path, "rb") as f:
        pem = f.read()
    private_key = serialization.load_pem_private_key(pem, password=None)
    return private_key

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP-SHA256.
    Returns the 64-character hex seed (string).
    Raises ValueError on validation or decryption failure.
    """
    try:
        encrypted_bytes = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    try:
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        # Catch generic decryption errors and re-raise as ValueError for caller
        raise ValueError(f"RSA decryption failed: {e}")

    try:
        hex_seed = decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decoding decrypted bytes to UTF-8 failed: {e}")

    # Normalize and validate: lowercase hex only
    hex_seed = hex_seed.strip().lower()
    if len(hex_seed) != 64:
        raise ValueError(f"Invalid seed length: {len(hex_seed)} (expected 64)")
    if not all(c in "0123456789abcdef" for c in hex_seed):
        raise ValueError("Seed contains non-hex characters")

    return hex_seed

def save_seed(hex_seed: str, path: str = SEED_PATH):
    # Ensure safe write and permissions
    umask = 0o022
    with open(path, "w") as f:
        f.write(hex_seed)
    # Restrict file permissions to owner read/write (optional in dev)
    try:
        import os
        os.chmod(path, 0o600)
    except Exception:
        pass

def main():
    if len(sys.argv) != 3:
        print("Usage: python decrypt_seed.py <encrypted_seed.txt> <student_private.pem>", file=sys.stderr)
        sys.exit(2)

    enc_file = sys.argv[1]
    key_file = sys.argv[2]

    try:
        with open(enc_file, "r") as f:
            encrypted_seed_b64 = f.read().strip()
    except FileNotFoundError:
        print(f"Encrypted seed file not found: {enc_file}", file=sys.stderr)
        sys.exit(1)

    try:
        private_key = load_private_key(key_file)
    except Exception as e:
        print(f"Failed to load private key: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
    except ValueError as e:
        print(f"Decryption/validation error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        save_seed(hex_seed)
    except Exception as e:
        print(f"Failed saving seed to {SEED_PATH}: {e}", file=sys.stderr)
        sys.exit(1)

    print("Decryption successful. Seed saved to", SEED_PATH)
    print(hex_seed)

if __name__ == "__main__":
    main()
