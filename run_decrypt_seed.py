# run_decrypt_seed.py
from crypto_utils import load_private_key, decrypt_seed, save_seed_to_file

ENCRYPTED_SEED_FILE = "encrypted_seed.txt"       # from instructor API
PRIVATE_KEY_FILE = "student_private.pem"        # your student private key
LOCAL_SEED_PATH = "data/seed.txt"               # local path for testing


def main():
    # 1. Read base64 encrypted seed from file
    with open(ENCRYPTED_SEED_FILE, "r") as f:
        encrypted_seed_b64 = f.read().strip()

    # 2. Load private key
    private_key = load_private_key(PRIVATE_KEY_FILE)

    # 3. Decrypt the seed
    hex_seed = decrypt_seed(encrypted_seed_b64, private_key)

    # Show result on screen
    print("Decrypted hex seed:", hex_seed)
    print("Length:", len(hex_seed))

    # 4. Save to local file (for now): data/seed.txt
    save_seed_to_file(hex_seed, LOCAL_SEED_PATH)
    print(f"Saved seed to {LOCAL_SEED_PATH}")


if __name__ == "__main__":
    main()
