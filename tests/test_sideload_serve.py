"""
Unit tests for Side_Load/Decryptor/serve.py — closes issue 14.

Covers:
    compute_hash         — correct SHA-256 for known inputs
    add_header           — Cache-Control / Pragma / Expires on every response
    GET /                — 200 + part filenames rendered
    GET /<uid>/<file>    — 200 valid uid+file; 404 wrong uid; 404 missing file
    GET /<uid>/iv        — 200 valid uid; 404 wrong uid
    GET /<uid>/salt      — 200 valid uid; 404 wrong uid

Design notes
------------
Side_Load/Decryptor/serve.py reads ``../config.ini`` and sets module-level
constants (DOWNLOADS_PATH, FILE_GUID) at import time.  It is loaded via
``importlib.util`` with the CWD set to a tmpdir so ``../config.ini`` resolves
correctly, and is registered under the name ``sideload_serve`` to avoid
clashing with the Upload/Flask ``serve`` module already imported by conftest.

Flask 3.x resolves relative paths in ``send_file`` against ``app.root_path``,
so each test fixture patches both ``DOWNLOADS_PATH`` (absolute) and
``app.root_path`` (→ tmpdir that holds Downloads/ and templates/).
"""

import hashlib
import importlib.util
import os
import shutil
import sys

import pytest


# ---------------------------------------------------------------------------
# Session-scoped setup: build disk layout and import the module once
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def sideload_env(tmp_path_factory):
    """
    Create the filesystem layout Side_Load/Decryptor/serve.py expects and
    import it once for the whole test session.

    Layout inside ``root/``::

        config.ini            ← ../config.ini (one dir above serve_cwd)
        serve_cwd/
            templates/
                SideLoadMe.html   ← copied from repo
            Downloads/
                parts/
                    part_0, part_1, part_2
                iv.bin
                salt.bin
    """
    root = tmp_path_factory.mktemp("sideload")

    (root / "config.ini").write_text(
        "[DEFAULT]\n"
        "ServerHostname = localhost\n"
        "NumberOfFiles = 3\n"
        "EncryptionKey = testkey\n"
        "DownloadName = payload.exe\n"
        "[SERVER]\n"
        "Port = 5001\n"
        "DebugMode = False\n",
        encoding="utf-8",
    )

    serve_cwd = root / "serve_cwd"
    serve_cwd.mkdir()

    # Copy templates so render_template works when app.root_path → serve_cwd
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    shutil.copytree(
        os.path.join(repo_root, "Side_Load", "Decryptor", "templates"),
        serve_cwd / "templates",
    )

    # Create dummy encrypted parts, IV, and salt
    parts = serve_cwd / "Downloads" / "parts"
    parts.mkdir(parents=True)
    for i in range(3):
        (parts / f"part_{i}").write_bytes(bytes([i]) * 32)
    (serve_cwd / "Downloads" / "iv.bin").write_bytes(b"\x01" * 16)
    (serve_cwd / "Downloads" / "salt.bin").write_bytes(b"\x02" * 16)

    # Import with CWD = serve_cwd so '../config.ini' resolves to root/config.ini
    serve_py = os.path.join(repo_root, "Side_Load", "Decryptor", "serve.py")
    prev_cwd = os.getcwd()
    os.chdir(str(serve_cwd))
    try:
        spec = importlib.util.spec_from_file_location("sideload_serve", serve_py)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["sideload_serve"] = mod
        spec.loader.exec_module(mod)
    finally:
        os.chdir(prev_cwd)

    return mod, serve_cwd, parts


@pytest.fixture
def mod(sideload_env):
    module, _, _ = sideload_env
    return module


@pytest.fixture
def client(sideload_env, monkeypatch):
    """
    Flask test client with:
      - DOWNLOADS_PATH → absolute path of the dummy parts directory
      - app.root_path  → serve_cwd so send_file resolves Downloads/iv.bin etc.
    """
    module, serve_cwd, parts = sideload_env
    monkeypatch.setattr(module, "DOWNLOADS_PATH", str(parts))
    monkeypatch.setattr(module.app, "root_path", str(serve_cwd))
    return module.app.test_client()


# ---------------------------------------------------------------------------
# compute_hash
# ---------------------------------------------------------------------------


def test_compute_hash_returns_64_char_hex(mod, tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello")
    result = mod.compute_hash(str(f))
    assert isinstance(result, str)
    assert len(result) == 64


def test_compute_hash_correct_value(mod, tmp_path):
    data = b"red team test payload"
    f = tmp_path / "known.bin"
    f.write_bytes(data)
    assert mod.compute_hash(str(f)) == hashlib.sha256(data).hexdigest()


def test_compute_hash_empty_file(mod, tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    assert mod.compute_hash(str(f)) == hashlib.sha256(b"").hexdigest()


def test_compute_hash_chunked_large_file(mod, tmp_path):
    # Write more than one 4 KiB chunk to exercise the chunked read path
    data = b"A" * (4096 * 3 + 7)
    f = tmp_path / "large.bin"
    f.write_bytes(data)
    assert mod.compute_hash(str(f)) == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# add_header — verified via response headers on every route
# ---------------------------------------------------------------------------


def test_add_header_cache_control(client):
    r = client.get("/")
    assert r.headers.get("Cache-Control") == "no-store"


def test_add_header_pragma(client):
    r = client.get("/")
    assert r.headers.get("Pragma") == "no-cache"


def test_add_header_expires(client):
    r = client.get("/")
    assert r.headers.get("Expires") == "0"


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------


def test_index_returns_200(client):
    assert client.get("/").status_code == 200


def test_index_contains_part_filenames(client):
    body = client.get("/").data.decode()
    for i in range(3):
        assert f"part_{i}" in body


# ---------------------------------------------------------------------------
# GET /<uid>/<filename>
# ---------------------------------------------------------------------------


def test_serve_file_part_valid(client, sideload_env):
    mod, _, _ = sideload_env
    r = client.get(f"/{mod.FILE_GUID}/part_0")
    assert r.status_code == 200
    assert r.data == bytes([0]) * 32


def test_serve_file_part_wrong_uid_returns_404(client):
    assert client.get("/wrong-uid/part_0").status_code == 404


def test_serve_file_part_missing_file_returns_404(client, sideload_env):
    mod, _, _ = sideload_env
    assert client.get(f"/{mod.FILE_GUID}/nonexistent.bin").status_code == 404


# ---------------------------------------------------------------------------
# GET /<uid>/iv
# ---------------------------------------------------------------------------


def test_get_iv_valid_uid_returns_200(client, sideload_env):
    mod, _, _ = sideload_env
    r = client.get(f"/{mod.FILE_GUID}/iv")
    assert r.status_code == 200
    assert r.data == b"\x01" * 16


def test_get_iv_wrong_uid_returns_404(client):
    assert client.get("/wrong-uid/iv").status_code == 404


# ---------------------------------------------------------------------------
# GET /<uid>/salt
# ---------------------------------------------------------------------------


def test_get_salt_valid_uid_returns_200(client, sideload_env):
    mod, _, _ = sideload_env
    r = client.get(f"/{mod.FILE_GUID}/salt")
    assert r.status_code == 200
    assert r.data == b"\x02" * 16


def test_get_salt_wrong_uid_returns_404(client):
    assert client.get("/wrong-uid/salt").status_code == 404
