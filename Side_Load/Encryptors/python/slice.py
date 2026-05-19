"""
Contains functions related to slicing and encrypting the supplied file for delivery
"""

import argparse
import configparser
import math
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad

PIZZA_SLICE_ART = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣷⡄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣷⣆⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⣹⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣠⣶⣿⣿⣿⣿⣿⣶⣦⣾⣿⡿⠟⢿⣿⣿⣏⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠙⢿⣿⠗⠀⠀⠀⠀⠀⠀⠀
⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⡏⠀⠈⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        """


def encrypt_and_split(file_path, output_dir, password, *, num_files=None, chunk_size=None):
    """Encrypt *file_path* with AES-CBC and split into parts under *output_dir*.

    Exactly one of *num_files* or *chunk_size* must be provided.

    Args:
        file_path:   Path to the plaintext file.
        output_dir:  Directory where iv.bin, salt.bin, file.sha256 and parts/ are written.
        password:    Encryption passphrase (bytes).
        num_files:   Number of parts to produce.
        chunk_size:  Target part size in bytes; num_files is derived from the encrypted size.

    Returns:
        The hex-encoded SHA-256 of the encrypted payload.
    """
    if (num_files is None) == (chunk_size is None):
        raise ValueError("Provide exactly one of num_files or chunk_size.")

    parts_dir = os.path.join(output_dir, "parts")
    os.makedirs(parts_dir, exist_ok=True)

    with open(file_path, "rb") as f:
        data = f.read()

    salt = os.urandom(16)
    key = PBKDF2(password, salt, dkLen=16, count=100000, hmac_hash_module=SHA256)

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    with open(os.path.join(output_dir, "iv.bin"), "wb") as f:
        f.write(iv)

    with open(os.path.join(output_dir, "salt.bin"), "wb") as f:
        f.write(salt)

    enc_size = len(ciphertext)
    if chunk_size is not None:
        num_files = max(1, math.ceil(enc_size / chunk_size))

    base_size = enc_size // num_files
    remainder = enc_size % num_files

    offset = 0
    base_name = os.path.basename(file_path)
    for i in range(num_files):
        part_size = base_size + (1 if i < remainder else 0)
        part_path = os.path.join(parts_dir, f"{base_name}_part_{i}")
        with open(part_path, "wb") as f:
            f.write(ciphertext[offset : offset + part_size])
        print(f"Saving {part_path}")
        offset += part_size

    # SHA-256 of the encrypted payload — written so downstream can verify reassembly
    checksum = SHA256.new(ciphertext).hexdigest()
    with open(os.path.join(output_dir, "file.sha256"), "w", encoding="utf-8") as f:
        f.write(checksum + "\n")

    print(f"Encrypted file split into {num_files} parts.")
    print("IV saved to iv.bin.")
    print("salt saved to salt.bin.")
    print(f"SHA-256 ({checksum}) saved to file.sha256.")

    return checksum


def main():
    print(PIZZA_SLICE_ART)

    parser = argparse.ArgumentParser(
        description="Encrypt and split a file for covert delivery.",
    )
    parser.add_argument("file", help="Path to the file to encrypt and split.")
    parser.add_argument(
        "--chunk-size",
        type=int,
        metavar="BYTES",
        help="Target size of each chunk in bytes. Overrides NumberOfFiles from config.ini.",
    )
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read("../../config.ini")
    password = config["DEFAULT"]["EncryptionKey"].encode()

    output_dir = "../../Decryptor/Downloads"
    os.makedirs(output_dir, exist_ok=True)

    if args.chunk_size:
        encrypt_and_split(args.file, output_dir, password, chunk_size=args.chunk_size)
    else:
        num_files = int(config["DEFAULT"]["NumberOfFiles"])
        encrypt_and_split(args.file, output_dir, password, num_files=num_files)


if __name__ == "__main__":
    main()
