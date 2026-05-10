import os
import sys
import tempfile

# Add Upload/Flask to sys.path so `import serve` resolves.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "Upload", "Flask"))

# Change CWD to a writable tmpdir with a minimal config.ini so that
# serve.py's module-level config reads and os.makedirs calls succeed.
_tmpdir = tempfile.mkdtemp(prefix="slice_n_dice_tests_")

with open(os.path.join(_tmpdir, "config.ini"), "w", encoding="utf-8") as _f:
    _f.write(
        "[DEFAULT]\n"
        "ServerHostname = localhost\n"
        "NumberOfFiles = 3\n"
        "EncryptionKey = testkey\n"
        "UploadDirectory = uploads\n"
        "ApiToken = test-token\n"
        "\n"
        "[SERVER]\n"
        "Port = 5000\n"
        "DebugMode = False\n"
        "\n"
        "[ENCRYPTION]\n"
        "SaltSize = 16\n"
        "IVSize = 16\n"
        "KeyIterations = 100000\n"
    )

os.chdir(_tmpdir)
