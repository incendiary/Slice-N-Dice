"""
Python decryptor — the inverse of slice.py.

Reads the iv.bin, salt.bin, and parts/ directory written by encrypt_and_split(),
reassembles the ciphertext, verifies the SHA-256 checksum, and decrypts
back to the original plaintext.
"""

import argparse
import configparser
import math
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad


def reassemble_and_decrypt(input_dir, output_path, password):
    """Reassemble split parts and decrypt the AES-CBC ciphertext.

    Args:
        input_dir:   Directory containing iv.bin, salt.bin, file.sha256, and parts/.
        output_path: Destination path for the recovered plaintext file.
        password:    Encryption passphrase (bytes) — must match the value used
                     when encrypt_and_split() was called.

    Returns:
        The hex-encoded SHA-256 of the reassembled ciphertext (for caller verification).

    Raises:
        ValueError: If the SHA-256 of the reassembled ciphertext does not match
                    the checksum stored in file.sha256.
        FileNotFoundError: If any expected file is missing from input_dir.
    """
    # --- Load key-derivation material ----------------------------------------
    with open(os.path.join(input_dir, "iv.bin"), "rb") as f:
        iv = f.read()
    with open(os.path.join(input_dir, "salt.bin"), "rb") as f:
        salt = f.read()

    # --- Reassemble ciphertext from parts ------------------------------------
    parts_dir = os.path.join(input_dir, "parts")
    part_files = sorted(
        (p for p in os.listdir(parts_dir) if not p.startswith(".")),
        key=lambda n: int(n.rsplit("_part_", 1)[-1]),
    )
    if not part_files:
        raise FileNotFoundError(f"No parts found in {parts_dir}")

    ciphertext = b""
    for part_name in part_files:
        with open(os.path.join(parts_dir, part_name), "rb") as f:
            ciphertext += f.read()

    # --- Verify checksum before attempting decryption ------------------------
    actual_checksum = SHA256.new(ciphertext).hexdigest()
    sha_file = os.path.join(input_dir, "file.sha256")
    if os.path.exists(sha_file):
        with open(sha_file, "r", encoding="utf-8") as f:
            expected_checksum = f.read().strip()
        if actual_checksum != expected_checksum:
            raise ValueError(
                f"SHA-256 mismatch: stored={expected_checksum}, actual={actual_checksum}"
            )

    # --- Decrypt -------------------------------------------------------------
    key = PBKDF2(password, salt, dkLen=16, count=100000, hmac_hash_module=SHA256)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted output written to {output_path}")
    return actual_checksum


def main():
    parser = argparse.ArgumentParser(
        description="Reassemble and decrypt a file split by slice.py.",
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing iv.bin, salt.bin, file.sha256, and parts/.",
    )
    parser.add_argument(
        "output_file",
        help="Path to write the recovered plaintext.",
    )
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read("../../config.ini")
    password = config["DEFAULT"]["EncryptionKey"].encode()

    reassemble_and_decrypt(args.input_dir, args.output_file, password)


if __name__ == "__main__":
    main()
