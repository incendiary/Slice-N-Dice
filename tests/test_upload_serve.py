"""
Unit tests for Upload/Flask/serve.py.

slice.py is a top-level script with module-level side effects (config reads,
filesystem writes, sys.argv checks) that make it non-importable without
refactoring. Its round-trip coverage is tracked separately in issue #4.
"""

import serve  # resolved via conftest.py sys.path + CWD setup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


def test_derive_key_returns_bytes():
    key = serve.derive_key(b"\x00" * 16, "password")
    assert isinstance(key, bytes)


def test_derive_key_default_length():
    key = serve.derive_key(b"\x00" * 16, "password")
    assert len(key) == 16


def test_derive_key_custom_length():
    key = serve.derive_key(b"\x00" * 16, "password", dk_len=32)
    assert len(key) == 32


def test_derive_key_deterministic():
    salt = b"\xde\xad\xbe\xef" * 4
    assert serve.derive_key(salt, "key") == serve.derive_key(salt, "key")


def test_derive_key_different_passwords_produce_different_keys():
    salt = b"\x00" * 16
    assert serve.derive_key(salt, "aaa") != serve.derive_key(salt, "bbb")


def test_derive_key_different_salts_produce_different_keys():
    assert serve.derive_key(b"\x00" * 16, "key") != serve.derive_key(b"\xff" * 16, "key")


# ---------------------------------------------------------------------------
# extract_original_name_and_part
# ---------------------------------------------------------------------------


def test_extract_basic():
    name, part = serve.extract_original_name_and_part("myfile_part_0")
    assert name == "myfile"
    assert part == 0


def test_extract_multi_digit_part():
    name, part = serve.extract_original_name_and_part("archive_part_12")
    assert name == "archive"
    assert part == 12


def test_extract_extension_in_name():
    name, part = serve.extract_original_name_and_part("report.pdf_part_2")
    assert name == "report.pdf"
    assert part == 2


def test_extract_underscores_in_name():
    name, part = serve.extract_original_name_and_part("my_secret_file_part_3")
    assert name == "my_secret_file"
    assert part == 3


# ---------------------------------------------------------------------------
# all_parts_uploaded
# ---------------------------------------------------------------------------


def test_all_parts_uploaded_returns_true_when_all_present(monkeypatch, tmp_path):
    run_guid = "test-run-guid"
    monkeypatch.setattr(serve, "UPLOAD_DIRECTORY", str(tmp_path))
    monkeypatch.setattr(serve, "RUN_GUID", run_guid)

    part_dir = tmp_path / run_guid
    part_dir.mkdir()
    for i in range(3):
        (part_dir / f"payload_part_{i}").write_bytes(b"x")

    assert serve.all_parts_uploaded("payload", 3)


def test_all_parts_uploaded_returns_false_when_part_missing(monkeypatch, tmp_path):
    run_guid = "test-run-guid-2"
    monkeypatch.setattr(serve, "UPLOAD_DIRECTORY", str(tmp_path))
    monkeypatch.setattr(serve, "RUN_GUID", run_guid)

    part_dir = tmp_path / run_guid
    part_dir.mkdir()
    (part_dir / "payload_part_0").write_bytes(b"x")
    # parts 1 and 2 are absent

    assert not serve.all_parts_uploaded("payload", 3)


# ---------------------------------------------------------------------------
# decrypt_file_part — round-trip
# ---------------------------------------------------------------------------


def test_decrypt_file_part_roundtrip(tmp_path):
    key = b"\x01" * 16
    iv = b"\x02" * 16
    plaintext = b"Red team test payload. Must survive encrypt/decrypt."

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    enc_file = tmp_path / "payload.enc"
    enc_file.write_bytes(ciphertext)

    result = serve.decrypt_file_part(str(enc_file), key, iv)
    assert result == plaintext
