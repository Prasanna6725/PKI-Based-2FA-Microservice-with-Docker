# run_totp_test.py
import time

from crypto_utils import generate_totp_code, verify_totp_code

SEED_FILE = "data/seed.txt"


def read_hex_seed(path: str) -> str:
    with open(path, "r") as f:
        return f.read().strip()


def main():
    hex_seed = read_hex_seed(SEED_FILE)
    print("Hex seed from file:", hex_seed)
    print("Length:", len(hex_seed))

    # 1. Generate current TOTP code
    code = generate_totp_code(hex_seed)
    print("\nCurrent TOTP code:", code)

    # 2. Verify immediately (should be True)
    is_valid_now = verify_totp_code(hex_seed, code, valid_window=1)
    print("Verify immediately:", is_valid_now)

    # 3. Wait a bit (optional, just to see behavior)
    print("\nWaiting 35 seconds to see if the code is still accepted (within ±1 window)...")
    time.sleep(35)

    is_still_valid = verify_totp_code(hex_seed, code, valid_window=1)
    print("Verify after 35 seconds:", is_still_valid)


if __name__ == "__main__":
    main()
