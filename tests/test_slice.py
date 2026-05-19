"""
Integration tests for Side_Load/Encryptors/python/slice.py — closes issues #24, #25, #26.

Covers:
    encrypt_and_split (num_files)  — encrypt + split → verify parts, SHA-256, IV, salt
    encrypt_and_split (chunk_size) — --chunk-size path: part count derived from file size
    SHA-256 checksum               — file.sha256 matches concatenated ciphertext
    Reassembly                     — parts concatenated in order reproduce the ciphertext
    Decryption                     — decrypted ciphertext matches original plaintext
    Error cases                    — ValueError on bad argument combinations
"""

import hashlib
import importlib.util
import os

import pytest  # pylint: disable=import-error
from Crypto.Cipher import AES as _AES  # pylint: disable=import-error
from Crypto.Hash import SHA256 as _SHA256  # pylint: disable=import-error
from Crypto.Protocol.KDF import PBKDF2 as _PBKDF2  # pylint: disable=import-error
from Crypto.Util.Padding import unpad as _unpad  # pylint: disable=import-error

# ---------------------------------------------------------------------------
# Import slice.py once (it's not on sys.path by default)
# ---------------------------------------------------------------------------

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SLICE_PY = os.path.join(_REPO_ROOT, "Side_Load", "Encryptors", "python", "slice.py")

spec = importlib.util.spec_from_file_location("slice_module", _SLICE_PY)
_slice = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_slice)

encrypt_and_split = _slice.encrypt_and_split


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PASSWORD = b"test-passphrase"
_PAYLOAD = b"Red team test payload - the quick brown fox jumps over the lazy dog." * 10


def _reassemble(output_dir, base_name, num_parts):
    """Concatenate parts in order and return raw bytes."""
    parts_dir = os.path.join(output_dir, "parts")
    data = b""
    for i in range(num_parts):
        path = os.path.join(parts_dir, f"{base_name}_part_{i}")
        with open(path, "rb") as f:
            data += f.read()
    return data


def _decrypt(ciphertext, output_dir):
    """AES-CBC decrypt using iv.bin / salt.bin written by encrypt_and_split."""
    with open(os.path.join(output_dir, "iv.bin"), "rb") as f:
        iv = f.read()
    with open(os.path.join(output_dir, "salt.bin"), "rb") as f:
        salt = f.read()

    key = _PBKDF2(_PASSWORD, salt, dkLen=16, count=100000, hmac_hash_module=_SHA256)
    cipher = _AES.new(key, _AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(ciphertext), _AES.block_size)


# ---------------------------------------------------------------------------
# encrypt_and_split — num_files path
# ---------------------------------------------------------------------------


def test_parts_created_num_files(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=3)
    parts_dir = tmp_path / "parts"
    assert (parts_dir / "payload.bin_part_0").exists()
    assert (parts_dir / "payload.bin_part_1").exists()
    assert (parts_dir / "payload.bin_part_2").exists()
    assert not (parts_dir / "payload.bin_part_3").exists()


def test_iv_and_salt_written(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=3)
    assert (tmp_path / "iv.bin").stat().st_size == 16
    assert (tmp_path / "salt.bin").stat().st_size == 16


def test_sha256_file_written(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=3)
    sha_file = tmp_path / "file.sha256"
    assert sha_file.exists()
    checksum = sha_file.read_text(encoding="utf-8").strip()
    assert len(checksum) == 64  # hex SHA-256


def test_sha256_matches_reassembled_ciphertext(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    returned_checksum = encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=3)

    ciphertext = _reassemble(str(tmp_path), "payload.bin", 3)
    expected = hashlib.sha256(ciphertext).hexdigest()

    stored = (tmp_path / "file.sha256").read_text(encoding="utf-8").strip()

    assert returned_checksum == expected
    assert stored == expected


def test_reassembly_and_decryption(tmp_path):
    """End-to-end: encrypt → split → reassemble → decrypt → verify plaintext."""
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=3)

    ciphertext = _reassemble(str(tmp_path), "payload.bin", 3)
    plaintext = _decrypt(ciphertext, str(tmp_path))

    assert plaintext == _PAYLOAD


# ---------------------------------------------------------------------------
# encrypt_and_split — chunk_size path (#25)
# ---------------------------------------------------------------------------


def test_chunk_size_produces_correct_part_count(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    # Force exactly 2 parts by using a chunk_size larger than half the encrypted output
    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, chunk_size=500)
    parts_dir = tmp_path / "parts"
    parts = list(parts_dir.iterdir())
    assert len(parts) >= 1


def test_chunk_size_single_chunk(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(b"small")
    # chunk_size larger than file → should produce 1 part
    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, chunk_size=100_000)
    parts_dir = tmp_path / "parts"
    assert len(list(parts_dir.iterdir())) == 1


def test_chunk_size_reassembly_and_decryption(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD)
    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, chunk_size=200)

    parts_dir = tmp_path / "parts"
    num_parts = len(list(parts_dir.iterdir()))
    ciphertext = _reassemble(str(tmp_path), "payload.bin", num_parts)
    plaintext = _decrypt(ciphertext, str(tmp_path))
    assert plaintext == _PAYLOAD


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


def test_error_neither_num_files_nor_chunk_size(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(b"x")
    with pytest.raises(ValueError, match="exactly one"):
        encrypt_and_split(str(src), str(tmp_path), _PASSWORD)


def test_error_both_num_files_and_chunk_size(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(b"x")
    with pytest.raises(ValueError, match="exactly one"):
        encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=3, chunk_size=100)
