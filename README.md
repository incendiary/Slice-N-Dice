# Slice-N-Dice

A toolkit for secure file encryption, splitting, and covert transfer — designed for red team operations. By fragmenting encrypted data streams across multiple HTTP transactions, it increases the complexity of detection and reassembly for blue teams.

## How It Works

```
[Encryptor] → AES-CBC encrypt → split into N parts → [Serve or Upload]
                                                           ↓
                                                   [Receiver reassembles + decrypts]
```

Two delivery modes:

| Mode | Description |
|------|-------------|
| **Side Load** | Operator-controlled server *serves* encrypted parts; target client fetches and decrypts in-browser |
| **Upload** | Target client encrypts and *uploads* parts to operator-controlled receiver |

---

## Repository Structure

```
.
├── Side_Load/
│   ├── config.ini                    # Shared config (hostname, key, part count)
│   ├── Encryptors/
│   │   ├── python/slice.py           # Encrypt + split a file (Python)
│   │   └── cs/Dice.cs/               # Encrypt + split a file (C#, AES-128-CBC)
│   └── Decryptor/
│       ├── serve.py                  # Flask server — serves encrypted parts
│       └── templates/SideLoadMe.html
└── Upload/
    └── Flask/
        ├── config.ini
        ├── serve.py                  # Flask receiver — accepts, reassembles, decrypts
        └── templates/
            ├── index.html
            └── upload.html           # Browser-side encrypt + upload UI
```

---

## Prerequisites

- Python 3.9+ (stdlib `venv` is sufficient — no `virtualenv` install needed)
- .NET 9+ SDK (for the C# encryptor)

---

## Setup

### Clone

```bash
git clone https://github.com/incendiary/Slice-N-Dice.git
cd Slice-N-Dice
```

### Side Load — Encrypt and Serve

**Step 1 — encrypt and split the file (Python encryptor)**

```bash
cd Side_Load/Encryptors/python
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python slice.py <file_to_encrypt>
# Writes encrypted parts + iv.bin + salt.bin to Side_Load/Decryptor/Downloads/
```

**Step 1 (alternative) — C# encryptor**

```bash
cd Side_Load/Encryptors/cs/Dice.cs
dotnet run --project Dice.cs -- ../../config.ini <file_to_encrypt>
```

**Step 2 — serve the encrypted parts**

```bash
cd Side_Load/Decryptor
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python serve.py
```

Browse to `http://<ServerHostname>` — the page fetches, verifies (SHA-256), and decrypts the file in the browser using the Web Crypto API.

### Upload — Browser Encrypt and Receive

```bash
cd Upload/Flask
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python serve.py
```

Browse to `http://<ServerHostname>`, select a file, and enter an encryption key. The browser encrypts and splits the file before uploading each part.

> **Security:** Change `ApiToken` in `config.ini` to a random value before deploying. The default `change-me` placeholder will be rejected by any operator who reads this README.

### Configuration

Each mode has its own `config.ini`. Edit the one in the relevant directory before running:

**Side Load** (`Side_Load/config.ini`):

```ini
[DEFAULT]
ServerHostname = <your-server-ip>
NumberOfFiles = 3
EncryptionKey = <strong-passphrase>
DownloadName = output.docx

[SERVER]
Port = 80
DebugMode = Off
```

**Upload** (`Upload/Flask/config.ini`):

```ini
[DEFAULT]
ServerHostname = <your-server-ip>
NumberOfFiles = 3
EncryptionKey = <strong-passphrase>
UploadDirectory = uploads
ApiToken = <random-token>

[SERVER]
Port = 80
DebugMode = Off
```

> **Never commit a `config.ini` containing real values.** The defaults are placeholders only.

---

## Version History

### v1.0.4
- README accuracy pass: correct prerequisites, `python -m venv .venv` setup, per-mode config examples, C# encryptor usage, ApiToken security callout

### v1.0.3
- Added `[project]` metadata to `pyproject.toml` (name, version, description, `requires-python`)
- Added `[tool.coverage.run/report]` config to `pyproject.toml`
- Aligned black `target-version` to supported Python matrix (3.9–3.11)
- Opened issue [#14](https://github.com/incendiary/Slice-N-Dice/issues/14) for missing Side_Load/Decryptor test coverage

### v1.0.2
- Removed dead `recombine_file()` function (never called)
- Made `derive_key()` password argument required (removes silent-weak-key footgun)
- Documented `USER_SUPPLIED_KEY` single-session design constraint
- Removed what-comments and redundant docstring noise from Python source

### v1.0.1
- Bumped all Python deps to current stable (Flask 3.1.3, Werkzeug 3.1.8, pycryptodome 3.23.0)
- Updated pre-commit hooks to latest (gitleaks v8.30.1, black 26.3.1, isort 8.0.1, flake8 7.3.0)
- Fixed all pre-existing CI failures (pylint, dotnet-format, line-ending mismatch)
- Sanitised engagement-specific IP address from config before public release

### v1.0.0
- Python AES-CBC encryptor with PBKDF2 key derivation
- Flask side-load server (serve encrypted parts to browser)
- Flask upload receiver (browser-side encrypt + multi-part upload)
- Browser-based decryption via Web Crypto API
- C# encryptor (Dice.cs) — matches Python encryptor parameters exactly
- API token authentication on all upload receiver endpoints
- 18-test pytest suite covering crypto, upload logic, and auth

---

## Roadmap

| # | Status | Description |
|---|--------|-------------|
| [#16](https://github.com/incendiary/Slice-N-Dice/issues/16) | ✅ Done (v1.0.4) | README accuracy pass — prerequisites, setup, config, C# instructions |
| [#9](https://github.com/incendiary/Slice-N-Dice/issues/9) | ✅ Done (v1.0.2) | Remove dead `recombine_file()` from Upload/Flask/serve.py |
| [#10](https://github.com/incendiary/Slice-N-Dice/issues/10) | ✅ Done (v1.0.2) | Remove misleading default password in `derive_key()` |
| [#11](https://github.com/incendiary/Slice-N-Dice/issues/11) | ✅ Done (v1.0.2) | Document `USER_SUPPLIED_KEY` single-session design constraint |
| [#12](https://github.com/incendiary/Slice-N-Dice/issues/12) | ✅ Done (v1.0.2) | Remove what-comments and redundant docstring noise from Python source files |
| [#14](https://github.com/incendiary/Slice-N-Dice/issues/14) | 🔮 Future | Add unit tests for Side_Load/Decryptor/serve.py (zero coverage currently) |
| — | 🔮 Future | Refactor `slice.py` into importable functions to enable unit testing |
| — | 🔮 Future | Fix IV reuse across file parts in upload mode |
| — | 🔮 Future | Replace plaintext key transmission with a proper key-exchange mechanism |
| — | 🔮 Future | Split uploads across multiple independent services |
| — | 🔮 Future | User-selectable encryption algorithm |
| — | 🔮 Future | Upload success/failure feedback to client |
| — | 🔮 Future | Configurable split count and chunk size via CLI |

---

## A Note on AI-Assisted Uplift

This project was prepared for public release with the assistance of [Claude Code](https://claude.com/claude-code), following [karpathy-style](https://github.com/forrestchang/andrej-karpathy-skills) engineering guidelines (surgical changes, simplicity-first, no speculative abstractions). Things should work, but in some cases I haven't been able to verify every path end-to-end. PRs and fixes are very welcome.

---

## Security Notice

This tool is intended for **authorised red team engagements only**. Ensure you have explicit written permission before deploying against any target environment.
