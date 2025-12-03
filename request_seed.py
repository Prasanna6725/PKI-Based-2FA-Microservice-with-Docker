#!/usr/bin/env python3
import argparse
import json
import os
import sys
from typing import Optional

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install with: pip install requests", file=sys.stderr)
    raise

INSTRUCTOR_API_URL_DEFAULT = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/"

def _read_public_key_as_escaped_line(pubkey_path: str) -> str:
    """
    Read PEM and return it with real newline characters.
    Do NOT convert newlines to literal backslash-n sequences.
    """
    if not os.path.isfile(pubkey_path):
        raise FileNotFoundError(f"Public key file not found: {pubkey_path}")

    with open(pubkey_path, "rb") as f:
        raw = f.read()

    # Normalize newlines to LF and strip trailing whitespace
    text = raw.decode("utf-8").replace("\r\n", "\n").strip()
    # Return text with actual newline characters (json.dumps will escape them properly)
    return text


def request_seed(student_id: str, github_repo_url: str, api_url: str,
                 public_key_path: str = "student_public.pem",
                 out_path: str = "encrypted_seed.txt",
                 timeout: int = 15) -> Optional[str]:
    # 1) Read student public key, prepare single-line escaped string
    try:
        public_key_single_line = _read_public_key_as_escaped_line(public_key_path)
    except Exception as exc:
        print(f"Error reading public key ({public_key_path}): {exc}", file=sys.stderr)
        return None

    # 2) Prepare payload (use the function parameters here)
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_single_line
    }

    headers = {"Content-Type": "application/json"}

    # 3) Send POST request
    try:
        resp = requests.post(api_url, headers=headers, data=json.dumps(payload), timeout=timeout)
    except requests.RequestException as exc:
        print(f"HTTP request failed: {exc}", file=sys.stderr)
        return None

    # 4) Parse JSON response
    if resp.status_code != 200:
        print(f"Non-200 response from instructor API: {resp.status_code} - {resp.text}", file=sys.stderr)
        return None

    try:
        j = resp.json()
    except ValueError:
        print("Invalid JSON response from instructor API.", file=sys.stderr)
        return None

    if j.get("status") != "success" or "encrypted_seed" not in j:
        print("Instructor API returned error or missing 'encrypted_seed' field:", j, file=sys.stderr)
        return None

    encrypted_seed = j["encrypted_seed"]

    # 5) Save encrypted_seed to file (plain text).
    try:
        with open(out_path + ".tmp", "w", encoding="utf-8") as f:
            f.write(encrypted_seed)
        os.replace(out_path + ".tmp", out_path)
        print(f"Encrypted seed saved to: {out_path}")
    except Exception as exc:
        print(f"Failed to write encrypted seed to {out_path}: {exc}", file=sys.stderr)
        return None

    return encrypted_seed


def main():
    parser = argparse.ArgumentParser(description="Request encrypted seed from instructor API")
    parser.add_argument("--student-id", required=True, help="Your student id")
    parser.add_argument("--github-repo-url", required=True, help="Exact GitHub repo URL you will submit")
    parser.add_argument("--api-url", default=INSTRUCTOR_API_URL_DEFAULT, help="Instructor API URL")
    parser.add_argument("--public-key", default="student_public.pem", help="Path to student public PEM")
    parser.add_argument("--out", default="encrypted_seed.txt", help="Output file for encrypted seed (do NOT commit)")
    args = parser.parse_args()

    encrypted = request_seed(
        student_id=args.student_id,
        github_repo_url=args.github_repo_url,
        api_url=args.api_url,
        public_key_path=args.public_key,
        out_path=args.out
    )

    if encrypted is None:
        print("Failed to obtain encrypted seed.", file=sys.stderr)
        sys.exit(1)

    print("Done. Keep encrypted_seed.txt safe (do NOT commit).")


if __name__ == "__main__":
    main()
