# sign_commit.py
import base64
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


STUDENT_PRIVATE_KEY_PATH = "student_private.pem"
INSTRUCTOR_PUBLIC_KEY_PATH = "instructor_public.pem"


def load_private_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data)


def sign_message(message: str, private_key) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256.

    - message is the 40-char commit hash (ASCII string)
    - Sign message.encode("utf-8")
    """
    message_bytes = message.encode("utf-8")

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA/OAEP with SHA-256.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def get_latest_commit_hash() -> str:
    """
    Run 'git log -1 --format=%H' and return the commit hash as string.
    """
    result = subprocess.run(
        ["git", "log", "-1", "--format=%H"],
        capture_output=True,
        text=True,
        check=True,
    )
    commit_hash = result.stdout.strip()
    if len(commit_hash) != 40 or any(c not in "0123456789abcdef" for c in commit_hash.lower()):
        raise ValueError(f"Invalid commit hash: {commit_hash}")
    return commit_hash


def main():
    # 1. Get current commit hash
    commit_hash = get_latest_commit_hash()
    print(f"Commit hash: {commit_hash}")

    # 2. Load student private key
    if not Path(STUDENT_PRIVATE_KEY_PATH).exists():
        raise FileNotFoundError(f"Private key not found at {STUDENT_PRIVATE_KEY_PATH}")
    private_key = load_private_key(STUDENT_PRIVATE_KEY_PATH)

    # 3. Sign commit hash with student private key (RSA-PSS-SHA256)
    signature = sign_message(commit_hash, private_key)
    print(f"Signature length (bytes): {len(signature)}")

    # 4. Load instructor public key
    if not Path(INSTRUCTOR_PUBLIC_KEY_PATH).exists():
        raise FileNotFoundError(f"Instructor public key not found at {INSTRUCTOR_PUBLIC_KEY_PATH}")
    instructor_pub = load_public_key(INSTRUCTOR_PUBLIC_KEY_PATH)

    # 5. Encrypt signature with instructor public key (RSA/OAEP-SHA256)
    encrypted_signature = encrypt_with_public_key(signature, instructor_pub)

    # 6. Base64 encode encrypted signature
    encrypted_signature_b64 = base64.b64encode(encrypted_signature).decode("ascii")

    print("\n==== SUBMISSION VALUES ====")
    print(f"Commit Hash: {commit_hash}")
    print("Encrypted Signature (Base64, single line):")
    print(encrypted_signature_b64)


if __name__ == "__main__":
    main()
