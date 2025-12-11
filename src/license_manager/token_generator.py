#!/usr/bin/env python3
import os
import json
import argparse
import time
import jwt   # pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PRIVATE_KEY_FILE = "../keys/private_key.pem"
PUBLIC_KEY_FILE = "../keys/public_key.pem"
LICENSE_JSON = "../licenses/license.json"
JWT_FILE = "../licenses/license.jwt"


def generate_keys():
    print("[+] Private key not found. Generating RSA 4096-bit key pair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    # Save private key
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
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
    start = int(input("License start (timestamp): ").strip())
    end = int(input("License end (timestamp): ").strip())

    return {
        "client": name,
        "license_start": start,
        "license_end": end
    }


def load_or_create_license_json(args):
    if os.path.exists(LICENSE_JSON):
        print("[+] Using existing license.json")
        with open(LICENSE_JSON, "r") as f:
            return json.load(f)

    print("[!] license.json not found → creating a new one")

    # CLI parameters or interactive input
    if args.name and args.start and args.end:
        data = {
            "client": args.name,
            "license_start": int(args.start),
            "license_end": int(args.end)
        }
    else:
        data = prompt_license_data()

    with open(LICENSE_JSON, "w") as f:
        json.dump(data, f, indent=4)

    print("[+] license.json created.")
    return data


def generate_jwt(private_key, payload):
    print("[+] Generating signed JWT (PS256)...")

    token = jwt.encode(
        payload,
        private_key,
        algorithm="PS256"
    )

    with open(JWT_FILE, "w") as f:
        f.write(token)

    print("[+] JWT saved to:", JWT_FILE)
    return token


def main():
    parser = argparse.ArgumentParser(description="License Token Generator using RSA-PSS (PS256)")
    parser.add_argument("--name", help="Client name")
    parser.add_argument("--start", help="License start timestamp")
    parser.add_argument("--end", help="License end timestamp")

    args = parser.parse_args()

    # Load or generate RSA keys
    private_key = load_private_key()
    if private_key is None:
        private_key = generate_keys()

    # Load or create license data
    license_data = load_or_create_license_json(args)

    # Generate signed JWT
    token = generate_jwt(private_key, license_data)

    print("\n===== GENERATED JWT TOKEN =====")
    print(token)
    print("================================")


if __name__ == "__main__":
    main()