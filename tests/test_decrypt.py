"""
Round-trip decryption tests for Side_Load/Encryptors/python/decrypt.py.

These tests exercise the full encrypt → split → reassemble → decrypt cycle,
ensuring that reassemble_and_decrypt() is the exact inverse of encrypt_and_split().
The two modules are imported directly (they are not on sys.path by default).
"""

import importlib.util
import os

import pytest

# ---------------------------------------------------------------------------
# Import slice.py and decrypt.py from their on-disk locations
# ---------------------------------------------------------------------------

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENC_DIR = os.path.join(_REPO_ROOT, "Side_Load", "Encryptors", "python")


def _load(name):
    path = os.path.join(_ENC_DIR, f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_slice = _load("slice")
_decrypt_mod = _load("decrypt")

encrypt_and_split = _slice.encrypt_and_split
reassemble_and_decrypt = _decrypt_mod.reassemble_and_decrypt

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_PASSWORD = b"roundtrip-passphrase"
_PAYLOAD_SMALL = b"Hello, decryptor!" * 5
_PAYLOAD_LARGE = b"Red team test payload - the quick brown fox jumps over the lazy dog." * 50


# ---------------------------------------------------------------------------
# Round-trip correctness
# ---------------------------------------------------------------------------


def test_roundtrip_num_files(tmp_path):
    """encrypt_and_split → reassemble_and_decrypt recovers exact plaintext (num_files path)."""
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD_LARGE)
    out = tmp_path / "recovered.bin"

    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=4)
    reassemble_and_decrypt(str(tmp_path), str(out), _PASSWORD)

    assert out.read_bytes() == _PAYLOAD_LARGE


def test_roundtrip_chunk_size(tmp_path):
    """encrypt_and_split → reassemble_and_decrypt recovers exact plaintext (chunk_size path)."""
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD_LARGE)
    out = tmp_path / "recovered.bin"

    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, chunk_size=300)
    reassemble_and_decrypt(str(tmp_path), str(out), _PASSWORD)

    assert out.read_bytes() == _PAYLOAD_LARGE


def test_roundtrip_single_part(tmp_path):
    """Single-part payload (chunk_size > file size) recovers correctly."""
    src = tmp_path / "small.bin"
    src.write_bytes(_PAYLOAD_SMALL)
    out = tmp_path / "recovered.bin"

    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=1)
    reassemble_and_decrypt(str(tmp_path), str(out), _PASSWORD)

    assert out.read_bytes() == _PAYLOAD_SMALL


def test_roundtrip_binary_payload(tmp_path):
    """Payload containing all 256 byte values survives the round trip."""
    payload = bytes(range(256)) * 4
    src = tmp_path / "binary.bin"
    src.write_bytes(payload)
    out = tmp_path / "recovered.bin"

    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=2)
    reassemble_and_decrypt(str(tmp_path), str(out), _PASSWORD)

    assert out.read_bytes() == payload


# ---------------------------------------------------------------------------
# Checksum verification
# ---------------------------------------------------------------------------


def test_checksum_verified_on_good_data(tmp_path):
    """reassemble_and_decrypt returns the correct SHA-256 when data is intact."""
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD_SMALL)
    out = tmp_path / "recovered.bin"

    expected_checksum = encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=2)
    returned_checksum = reassemble_and_decrypt(str(tmp_path), str(out), _PASSWORD)

    assert returned_checksum == expected_checksum


def test_checksum_mismatch_raises(tmp_path):
    """A corrupted part must raise ValueError before decryption is attempted."""
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD_LARGE)
    out = tmp_path / "recovered.bin"

    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=3)

    # Corrupt the first part
    part0 = tmp_path / "parts" / "payload.bin_part_0"
    part0.write_bytes(b"\x00" * len(part0.read_bytes()))

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        reassemble_and_decrypt(str(tmp_path), str(out), _PASSWORD)


# ---------------------------------------------------------------------------
# Wrong password
# ---------------------------------------------------------------------------


def test_wrong_password_raises(tmp_path):
    """Decrypting with a different password must raise (unpad fails on bad padding)."""
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD_SMALL)
    out = tmp_path / "recovered.bin"

    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=2)

    # Remove file.sha256 so the checksum check doesn't mask the real error
    sha_file = tmp_path / "file.sha256"
    sha_file.unlink()

    with pytest.raises(Exception):
        reassemble_and_decrypt(str(tmp_path), str(out), b"wrong-password")


# ---------------------------------------------------------------------------
# Missing parts directory
# ---------------------------------------------------------------------------


def test_missing_parts_raises(tmp_path):
    """FileNotFoundError when the parts/ directory does not exist."""
    src = tmp_path / "payload.bin"
    src.write_bytes(_PAYLOAD_SMALL)
    out = tmp_path / "recovered.bin"

    encrypt_and_split(str(src), str(tmp_path), _PASSWORD, num_files=2)

    # Remove the parts directory entirely
    import shutil  # pylint: disable=import-outside-toplevel

    shutil.rmtree(tmp_path / "parts")

    with pytest.raises((FileNotFoundError, OSError)):
        reassemble_and_decrypt(str(tmp_path), str(out), _PASSWORD)
