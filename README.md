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
│   │   ├── python/slice.py           # Encrypt + split a file
│   │   └── cs/Dice.cs/               # C# encryptor (WIP)
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

- Python 3.x
- `virtualenv` (recommended)
- .NET 7+ SDK (for the C# encryptor)

---

## Setup

### Clone

```bash
git clone https://github.com/incendiary/Slice-N-Dice.git
cd Slice-N-Dice
```

### Side Load — Encrypt and Serve

```bash
# 1. Encrypt and split a file
cd Side_Load/Encryptors/python
virtualenv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python slice.py <file_to_encrypt>

# 2. Serve the encrypted parts
cd ../../Decryptor
virtualenv venv && source venv/bin/activate
pip install -r requirements.txt
python serve.py
```

Browse to `http://<ServerHostname>` — the page will automatically fetch, verify, and decrypt the file in the browser.

### Upload — Browser Encrypt and Receive

```bash
cd Upload/Flask
virtualenv venv && source venv/bin/activate
pip install -r requirements.txt
python serve.py
```

Browse to `http://<ServerHostname>`, select a file, and enter an encryption key. The browser encrypts and splits the file before uploading.

### Configuration

Edit `config.ini` in the relevant directory:

```ini
[DEFAULT]
ServerHostname = 192.168.1.10
NumberOfFiles = 3
EncryptionKey = your-strong-key-here
DownloadName = output.docx

[SERVER]
Port = 80
DebugMode = Off
```

> **Never commit a `config.ini` with a real key.**

---

## Version History

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
| [#9](https://github.com/incendiary/Slice-N-Dice/issues/9) | ✅ Done (v1.0.2) | Remove dead `recombine_file()` from Upload/Flask/serve.py |
| [#10](https://github.com/incendiary/Slice-N-Dice/issues/10) | ✅ Done (v1.0.2) | Remove misleading default password in `derive_key()` |
| [#11](https://github.com/incendiary/Slice-N-Dice/issues/11) | ✅ Done (v1.0.2) | Document `USER_SUPPLIED_KEY` single-session design constraint |
| [#12](https://github.com/incendiary/Slice-N-Dice/issues/12) | ✅ Done (v1.0.2) | Remove what-comments and redundant docstring noise from Python source files |
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
