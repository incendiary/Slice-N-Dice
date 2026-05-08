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

### v1.0.0 (current)
- Python AES-CBC encryptor with PBKDF2 key derivation
- Flask side-load server (serve encrypted parts to browser)
- Flask upload receiver (browser-side encrypt + multi-part upload)
- Browser-based decryption via Web Crypto API
- C# encryptor stub (Dice.cs)

---

## Roadmap

### v1.1.0 — Quality & Correctness
- [ ] Add test suite (unit + integration) for encrypt/decrypt round-trips
- [ ] Fix IV reuse across file parts in upload mode
- [ ] Complete C# encryptor (Dice.cs)

### v1.2.0 — Security Hardening
- [ ] Add authentication to upload receiver endpoints
- [ ] Replace plaintext key transmission with a proper key-exchange mechanism

### v1.3.0 — Code Standards & Tooling
- [ ] Enforce Python style: Black + isort + flake8 + pre-commit hooks
- [ ] Enforce C# style: `dotnet format` + StyleCop.Analyzers + EditorConfig + pre-commit hooks

### Future
- [ ] Split uploads across multiple independent services
- [ ] User-selectable encryption algorithm
- [ ] Upload success/failure feedback to client
- [ ] Configurable split count and chunk size via CLI

---

## Security Notice

This tool is intended for **authorised red team engagements only**. Ensure you have explicit written permission before deploying against any target environment.
