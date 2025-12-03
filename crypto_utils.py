# crypto_utils.py
import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import pyotp

def load_private_key(path: str):
    """
    Load RSA private key from a PEM file.
    """
    with open(path, "rb") as f:
        pem_data = f.read()

    private_key = serialization.load_pem_private_key(
        pem_data,
        password=None,  # your key is not password-protected
    )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP with SHA-256.

    Steps:
    1. Base64 decode the encrypted seed string
    2. RSA/OAEP decrypt with:
       - Padding: OAEP
       - MGF: MGF1(SHA-256)
       - Hash: SHA-256
       - Label: None
    3. Decode bytes to UTF-8 string
    4. Validate: must be 64-character hex string (0-9, a-f)
    5. Return hex seed
    """
    # 1. Base64 decode
    try:
        encrypted_bytes = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    # 2. RSA/OAEP decrypt with SHA-256
    try:
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")

    # 3. Decode bytes to UTF-8 string
    try:
        hex_seed = decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"UTF-8 decode failed: {e}")

    # 4. Normalize and validate
    hex_seed = hex_seed.strip().lower()

    if len(hex_seed) != 64:
        raise ValueError(f"Invalid seed length {len(hex_seed)} (expected 64)")

    if not all(c in "0123456789abcdef" for c in hex_seed):
        raise ValueError("Seed contains non-hex characters")

    # 5. Return hex seed
    return hex_seed


def save_seed_to_file(hex_seed: str, path: str):
    """
    Save the hex seed string into a file at the given path.
    Creates parent directory if needed.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(hex_seed)

def hex_seed_to_base32(hex_seed: str) -> str:
    """
    Convert a 64-character hex seed into a base32 string for TOTP.

    Steps:
    1. Validate length and characters (0-9, a-f)
    2. Convert hex string -> bytes
    3. Convert bytes -> base32-encoded string
    """
    hex_seed = hex_seed.strip().lower()

    if len(hex_seed) != 64:
        raise ValueError(f"Invalid hex seed length {len(hex_seed)} (expected 64)")
    if not all(c in "0123456789abcdef" for c in hex_seed):
        raise ValueError("Hex seed contains non-hex characters")

    # 2. hex string -> bytes
    seed_bytes = bytes.fromhex(hex_seed)

    # 3. bytes -> base32 string
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8")
    return base32_seed

def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from 64-character hex seed.

    Process:
    1. Convert hex seed to base32
    2. Create TOTP object with:
       - SHA-1
       - 30s interval
       - 6 digits
    3. Return current code as 6-digit string
    """
    base32_seed = hex_seed_to_base32(hex_seed)

    # Create TOTP object. pyotp defaults: interval=30, digits=6, digest=sha1.
    totp = pyotp.TOTP(base32_seed)  # SHA-1, 30s, 6 digits

    code = totp.now()  # string like "123456"
    return code

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance (±valid_window periods).

    Args:
        hex_seed: 64-character hex string
        code: 6-digit code to verify
        valid_window: number of periods before/after to accept (1 = ±30s)

    Returns:
        True if code is valid within the window, False otherwise.
    """
    if not code or len(code) != 6 or not code.isdigit():
        # quick sanity check; you can be stricter in API
        return False

    base32_seed = hex_seed_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed)

    # valid_window means: current time ± valid_window steps (30s each)
    # So valid_window=1 == accept previous, current, next 30s window.
    is_valid = totp.verify(code, valid_window=valid_window)
    return is_valid
