#!/usr/bin/env python3

import os
import sys
from datetime import datetime, timezone

# Ensure /app is on sys.path so we can import crypto_utils
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))      # /app/scripts
APP_ROOT = os.path.dirname(CURRENT_DIR)                       # /app
if APP_ROOT not in sys.path:
    sys.path.insert(0, APP_ROOT)

from crypto_utils import generate_totp_code

SEED_FILE = "/data/seed.txt"


def main():
    try:
        if not os.path.exists(SEED_FILE):
            print(f"{timestamp()} - Seed file missing ({SEED_FILE})")
            return

        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()

        code = generate_totp_code(hex_seed)

        print(f"{timestamp()} - 2FA Code: {code}")

    except Exception as e:
        print(f"{timestamp()} - ERROR: {e}")


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    main()
