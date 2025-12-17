#!/usr/bin/env python3
import os
import json
import argparse
import jwt   # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import re

PRIVATE_KEY_FILE = "../keys/private_key.pem"
PUBLIC_KEY_FILE  = "../keys/public_key.pem"
LICENSES_DIR     = "../licenses"


def _sanitize_client_name(name: str) -> str:
    """Sanitize client name for use as a directory name."""
    # Keep alnum, dash, underscore and replace spaces with underscore
    safe = ''.join(c for c in name if c.isalnum() or c in (' ', '-', '_')).strip()
    return safe.replace(' ', '_') if safe else 'unknown'


def generate_keys():
    print("[+] Private key not found. Generating RSA 4096-bit key pair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    os.makedirs(os.path.dirname(PRIVATE_KEY_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(PUBLIC_KEY_FILE), exist_ok=True)

    # Save private key (PKCS8)
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key (SubjectPublicKeyInfo)
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[+] RSA keys generated.")
    return private_key


def load_private_key():
    if not os.path.exists(PRIVATE_KEY_FILE):
        return None

    print("[+] Loading existing private key...")
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def prompt_license_data():
    print("[*] No license.json found. Please enter license information:")
    name = input("Client name: ").strip()
    start = int(input("License start (unix timestamp): ").strip())
    end = int(input("License end (unix timestamp): ").strip())

    return {
        "client": name,
        "license_start": start,
        "license_end": end
    }


def load_or_create_license_json(args):
    os.makedirs(LICENSES_DIR, exist_ok=True)

    # If client name passed via args, prefer that
    if args.name:
        client = args.name.strip()
        client_dir = os.path.join(LICENSES_DIR, _sanitize_client_name(client))
        os.makedirs(client_dir, exist_ok=True)
        license_json = os.path.join(client_dir, "license.json")
        if os.path.exists(license_json):
            # If caller provided start/end explicitly we will create a new
            # incremented license file (license_1.json, license_2.json, ...)
            if args.start is not None and args.end is not None:
                print("[!] Existing license.json found — creating a new incremented license file")

                data = {
                    "client": client,
                    "license_start": int(args.start),
                    "license_end": int(args.end)
                }

                # determine next available filename
                def _next_license_file(dirpath: str) -> str:
                    existing_nums = []
                    for fname in os.listdir(dirpath):
                        if fname == 'license.json':
                            existing_nums.append(0)
                        else:
                            m = re.match(r"license_(\d+)\.json$", fname)
                            if m:
                                existing_nums.append(int(m.group(1)))
                    next_idx = (max(existing_nums) + 1) if existing_nums else 1
                    return os.path.join(dirpath, f"license_{next_idx}.json")

                new_file = _next_license_file(client_dir)
                with open(new_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=4)

                print("[+] New license created at:", new_file)
                return data, client_dir

            # No start/end provided: reuse existing license.json
            print("[+] Using existing license.json for client:", client)
            with open(license_json, "r", encoding="utf-8") as f:
                return json.load(f), client_dir

        # No license.json found — create a new one
        print("[!] license.json not found for client → creating a new one")
        if args.start is not None and args.end is not None:
            data = {
                "client": client,
                "license_start": int(args.start),
                "license_end": int(args.end)
            }
        else:
            data = prompt_license_data()
            # ensure provided client name matches
            data["client"] = client

        with open(license_json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        print("[+] license.json created at:", license_json)
        return data, client_dir

    # No client given: try to find any existing per-client license
    for entry in os.listdir(LICENSES_DIR):
        cand_dir = os.path.join(LICENSES_DIR, entry)
        cand_file = os.path.join(cand_dir, "license.json")
        if os.path.isdir(cand_dir) and os.path.exists(cand_file):
            print("[+] Found existing license in:", cand_dir)
            with open(cand_file, "r", encoding="utf-8") as f:
                return json.load(f), cand_dir

    # Fallback: check for old top-level license.json and move it under client dir if possible
    top_level = os.path.join(LICENSES_DIR, "license.json")
    if os.path.exists(top_level):
        print("[+] Found top-level license.json — migrating into client directory")
        with open(top_level, "r", encoding="utf-8") as f:
            data = json.load(f)

        client = data.get("client") or "unknown"
        client_dir = os.path.join(LICENSES_DIR, _sanitize_client_name(client))
        os.makedirs(client_dir, exist_ok=True)
        dest = os.path.join(client_dir, "license.json")
        os.replace(top_level, dest)
        print("[+] Moved license.json into:", dest)
        return data, client_dir

    # No existing license found — create a new one via prompt
    print("[!] No license found → creating a new one")
    data = prompt_license_data()
    client = data["client"]
    client_dir = os.path.join(LICENSES_DIR, _sanitize_client_name(client))
    os.makedirs(client_dir, exist_ok=True)
    license_json = os.path.join(client_dir, "license.json")
    with open(license_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    print("[+] license.json created at:", license_json)
    return data, client_dir


def generate_jwt(private_key, payload, client_dir):
    print("[+] Generating signed JWT (RS256)...")

    token = jwt.encode(
        payload=payload,
        key=private_key,
        algorithm="RS256",
        headers={"typ": "JWT"}
    )

    jwt_file = os.path.join(client_dir, "license.jwt")
    with open(jwt_file, "w", encoding="utf-8") as f:
        f.write(token)

    print("[+] JWT saved to:", jwt_file)
    return token


def main():
    parser = argparse.ArgumentParser(description="License Token Generator using RSA (RS256)")
    parser.add_argument("--name", help="Client name")
    parser.add_argument("--start", help="License start timestamp (unix)")
    parser.add_argument("--end", help="License end timestamp (unix)")
    args = parser.parse_args()

    private_key = load_private_key()
    if private_key is None:
        private_key = generate_keys()

    license_data, client_dir = load_or_create_license_json(args)

    token = generate_jwt(private_key, license_data, client_dir)

    print("\n===== GENERATED JWT TOKEN =====")
    print(token)
    print("================================")


if __name__ == "__main__":
    main()