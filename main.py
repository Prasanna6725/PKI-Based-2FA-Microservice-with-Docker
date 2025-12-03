# main.py
import os
import time
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from crypto_utils import (
    load_private_key,
    decrypt_seed,
    save_seed_to_file,
    generate_totp_code,
    verify_totp_code,
)

# For local dev we use data/seed.txt
# In Docker you will set SEED_PATH=/data/seed.txt via environment variable.
SEED_PATH = os.getenv("SEED_PATH", "data/seed.txt")
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "student_private.pem")

app = FastAPI(title="PKI-Based 2FA Microservice")


# ---------- Request models ----------

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class Verify2FARequest(BaseModel):
    code: str | None = None


# ---------- Helper functions ----------

def seed_exists() -> bool:
    return os.path.exists(SEED_PATH)


def read_hex_seed() -> str:
    if not seed_exists():
        raise FileNotFoundError("Seed file not found")
    with open(SEED_PATH, "r") as f:
        return f.read().strip()


def get_seconds_remaining_in_period(period: int = 30) -> int:
    """
    Return remaining seconds in current TOTP period, in range 0-29.
    Example:
        if now % 30 == 0 -> 29
        if now % 30 == 29 -> 0
    """
    now = int(time.time())
    offset = now % period
    remaining = period - 1 - offset
    if remaining < 0:
        remaining = 0
    return remaining


# ---------- Endpoint 1: POST /decrypt-seed ----------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: DecryptSeedRequest):
    """
    Accepts base64-encoded encrypted seed, decrypts it using RSA/OAEP-SHA256,
    validates hex format, and saves it to SEED_PATH.
    """
    encrypted_seed_b64 = body.encrypted_seed

    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        # Server is misconfigured if key cannot be loaded
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to load private key: {e}"},
        )

    try:
        hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
        save_seed_to_file(hex_seed, SEED_PATH)
    except Exception:
        # As per spec, don't leak details, just say "Decryption failed"
        return JSONResponse(
            status_code=500,
            content={"error": "Decryption failed"},
        )

    return {"status": "ok"}


# ---------- Endpoint 2: GET /generate-2fa ----------

@app.get("/generate-2fa")
def generate_2fa():
    """
    Reads hex seed from persistent storage, generates current TOTP code,
    and returns code + remaining validity seconds.
    """
    if not seed_exists():
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        hex_seed = read_hex_seed()
        code = generate_totp_code(hex_seed)
        valid_for = get_seconds_remaining_in_period(30)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to generate 2FA code: {e}"},
        )

    return {"code": code, "valid_for": valid_for}


# ---------- Endpoint 3: POST /verify-2fa ----------

@app.post("/verify-2fa")
def verify_2fa(body: Verify2FARequest):
    """
    Verifies a provided TOTP code against the stored seed
    with ±1 period tolerance (±30 seconds).
    """
    # 1. Validate code provided
    if not body.code:
        return JSONResponse(
            status_code=400,
            content={"error": "Missing code"},
        )

    if not seed_exists():
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    try:
        hex_seed = read_hex_seed()
        is_valid = verify_totp_code(hex_seed, body.code, valid_window=1)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to verify code: {e}"},
        )

    return {"valid": is_valid}


# Optional: simple health endpoint
@app.get("/health")
def health():
    return {"status": "ok"}
