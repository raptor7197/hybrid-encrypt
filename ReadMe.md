# hybrid-encrypt

A production-ready Python library and command-line tool for hybrid cryptography, combining **RSA-2048** asymmetric encryption with **AES-256** symmetric encryption to give you the security of public-key cryptography and the speed of symmetric encryption — in one clean, installable package.

---

## Table of Contents

1. [What Is Hybrid Encryption?](#what-is-hybrid-encryption)
2. [Why This Package Exists](#why-this-package-exists)
3. [How It Works — The Full Cryptographic Flow](#how-it-works--the-full-cryptographic-flow)
4. [Package Architecture](#package-architecture)
5. [Installation](#installation)
6. [Quick Start](#quick-start)
7. [Library API Reference](#library-api-reference)
   - [HybridEncryption](#hybridencryption)
   - [EncryptedPayload](#encryptedpayload)
   - [KeyStorage](#keystorage)
   - [PayloadStorage](#payloadstorage)
8. [Command-Line Interface](#command-line-interface)
9. [Data Formats](#data-formats)
10. [Security Design](#security-design)
11. [Testing](#testing)
12. [Publishing to PyPI](#publishing-to-pypi)
13. [Project Structure](#project-structure)
14. [Dependencies](#dependencies)
15. [Contributing](#contributing)
16. [License](#license)

---

## What Is Hybrid Encryption?

Hybrid encryption is a cryptographic scheme that combines two fundamentally different types of encryption algorithms to get the best properties of both:

### Symmetric Encryption (AES)

Symmetric encryption uses **one single key** for both encryption and decryption. The same key that locks the box also unlocks it. The gold standard here is **AES (Advanced Encryption Standard)**, specifically with a 256-bit key (AES-256), which is the same standard used by governments, militaries, and financial institutions worldwide.

**Strengths of AES:**
- Extremely fast — can encrypt gigabytes of data per second on modern hardware
- No practical limit on the size of the message you can encrypt
- Mathematically proven to be secure when used correctly
- Low computational overhead

**Weaknesses of AES:**
- The key distribution problem: how do you securely share the secret key with the other party? If you send the key over the internet in plaintext, anyone intercepting it can decrypt all your messages. This is a fundamental, unsolved problem with symmetric-only encryption.

### Asymmetric Encryption (RSA)

Asymmetric encryption uses **two mathematically linked keys** — a public key and a private key. The public key can encrypt data, and only the corresponding private key can decrypt it. You can share your public key with the entire world without any security risk, because knowing the public key tells an attacker nothing useful about the private key.

**RSA (Rivest–Shamir–Adleman)** is the most widely used asymmetric algorithm. With a 2048-bit key, it would take longer than the age of the universe to brute-force with current technology.

**Strengths of RSA:**
- Solves the key distribution problem completely — just share your public key publicly
- Mathematically sound — based on the extreme difficulty of factoring large prime numbers
- Enables digital signatures and identity verification

**Weaknesses of RSA:**
- Very slow — orders of magnitude slower than AES
- Can only encrypt data smaller than the key size minus overhead (~245 bytes max for RSA-2048)
- Not suitable for encrypting large messages directly

### The Hybrid Solution

Hybrid encryption elegantly solves both problems at once:

1. Generate a random AES key (just 32 bytes of random data)
2. Encrypt the actual message with AES using that key — this is fast, regardless of message size
3. Encrypt the AES key with RSA — this is slow, but the key is tiny (32 bytes), so it barely matters
4. Send both encrypted outputs together

The recipient:
1. Uses their RSA private key to decrypt the AES key
2. Uses the recovered AES key to decrypt the actual message

This is exactly how TLS (the protocol securing every HTTPS connection on the internet) works. It is the industry standard for secure communication.

---

## Why This Package Exists

The original project was a pair of standalone Python scripts (`encrypt.py` and `decrypt.py`) that implemented hybrid encryption with an interactive command-line menu. While functional, scripts have several limitations:

- They cannot be imported as a library by other Python projects
- They cannot be installed with `pip` and shared with the community
- The logic, I/O, and file handling are all tangled together in one place
- There are no automated tests
- Keys were stored using `pickle`, which is Python-version-specific and carries security risks

This package restructures that same cryptographic logic into:

- A **clean importable library** with a well-defined public API
- A **proper pip package** installable with a single command
- A **CLI tool** (`hybrid-encrypt`) registered as a system command on install
- **PEM-format key storage** instead of pickle — portable, secure, and compatible with standard tools like OpenSSL
- **68 automated tests** covering every function, edge case, and integration scenario

---

## How It Works — The Full Cryptographic Flow

### Encryption Flow (Step by Step)

```
Your Message (plaintext string)
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 1: Generate AES-256 Key             │
│  32 cryptographically random bytes        │
│  (os.urandom — uses the OS entropy pool)  │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 2: Pad the Message                  │
│  PKCS7 padding — extend message length    │
│  to the nearest multiple of 16 bytes      │
│  (AES operates on fixed 16-byte blocks)   │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 3: AES-256-ECB Encrypt              │
│  Encrypt padded message with the          │
│  random AES key                           │
│  Output: encrypted_message (bytes)        │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 4: RSA-2048 Encrypt the AES Key     │
│  Encrypt the 32-byte AES key using the    │
│  recipient's RSA public key               │
│  Output: encrypted_aes_key (bytes)        │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 5: Build EncryptedPayload           │
│  Hex-encode both byte outputs             │
│  Wrap in a serialisable dataclass         │
│  Ready to be saved as JSON or transmitted │
└───────────────────────────────────────────┘
```

### Decryption Flow (Step by Step)

```
EncryptedPayload (JSON / object)
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 1: Decode hex strings               │
│  encrypted_message → bytes                │
│  encrypted_aes_key → bytes                │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 2: RSA-2048 Decrypt the AES Key     │
│  Use the RSA private key to decrypt       │
│  encrypted_aes_key → recovers the         │
│  original 32-byte AES key                 │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 3: AES-256-ECB Decrypt              │
│  Use the recovered AES key to decrypt     │
│  encrypted_message → padded plaintext     │
└───────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────┐
│  Step 4: Unpad                            │
│  Strip the PKCS7 padding bytes            │
│  Decode bytes → UTF-8 string              │
└───────────────────────────────────────────┘
        │
        ▼
Your Original Message (recovered exactly)
```

### PKCS7 Padding — In Detail

AES is a **block cipher** — it operates on fixed-size chunks of data called blocks. AES always uses 16-byte (128-bit) blocks, regardless of key size. If your message is not an exact multiple of 16 bytes, it must be padded.

PKCS7 padding works like this: calculate how many bytes are needed to reach the next 16-byte boundary, then append that many bytes, each with the value equal to the count.

Examples:
- Message is 13 bytes → needs 3 more bytes → append `03 03 03`
- Message is 16 bytes → needs a full extra block → append `10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10` (16 bytes of value 16)
- Message is 20 bytes → needs 12 more bytes → append `0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C`

The reason a full extra block is added when the message is already aligned is so that the unpadding step is unambiguous — the last byte always tells you exactly how many padding bytes to strip.

### Key Generation — In Detail

**RSA Key Generation:**

RSA keys are generated using the `rsa` library with `poolsize=8`, which means 8 threads work in parallel to find the two large prime numbers needed. This makes 2048-bit key generation roughly 8x faster than single-threaded generation. Key generation is the slowest operation in this package (typically 1–5 seconds for 2048-bit keys), but it only needs to happen once.

The mathematical relationship between the keys is:
- Find two large distinct primes `p` and `q`
- Compute `n = p × q` (the modulus — this is public)
- Compute `φ(n) = (p-1)(q-1)` (Euler's totient — kept secret)
- Choose `e` such that `gcd(e, φ(n)) = 1` (the public exponent, usually 65537)
- Compute `d` such that `d × e ≡ 1 (mod φ(n))` (the private exponent — kept secret)
- Public key: `(n, e)` | Private key: `(n, d)`

Security rests on the fact that factoring `n` back into `p` and `q` is computationally infeasible for large values.

**AES Key Generation:**

```python
os.urandom(32)  # 32 bytes = 256 bits
```

`os.urandom()` reads from the operating system's cryptographically secure pseudo-random number generator (CSPRNG):
- On Linux: reads from `/dev/urandom` (seeded by the kernel entropy pool from hardware events like keystrokes, disk I/O, network timing, and dedicated hardware RNG chips)
- On Windows: uses `CryptGenRandom`
- On macOS: uses `arc4random`

This is the correct way to generate cryptographic keys. Never use Python's `random` module for cryptography — it is not cryptographically secure.

---

## Package Architecture

The package is split into four focused modules, each with a single responsibility. This separation makes the code testable, maintainable, and easy to use as a library.

```
hybrid_encrypt/
├── __init__.py      — Public API surface. Controls what `from hybrid_encrypt import X` exposes.
├── encryption.py    — Pure cryptographic logic. No I/O, no filesystem, no printing.
├── storage.py       — All filesystem operations. Reads/writes keys and payloads.
└── cli.py           — All user interaction. Parses arguments, calls the library, prints output.
```

### Why This Separation Matters

**`encryption.py` is pure:**
It takes inputs, returns outputs, raises exceptions on bad input. It never touches a file, never prints to the screen, never calls `input()`. This makes it trivially testable — just call the functions with known inputs and assert the outputs. It also makes it reusable in any context: web servers, desktop apps, other scripts, async code.

**`storage.py` is isolated:**
All the "where do files live, how are they named, what format are they" decisions live here and nowhere else. If you ever want to change from storing keys on disk to storing them in a database or a cloud secret manager, you only touch this one file.

**`cli.py` is a thin adapter:**
It parses arguments, calls the library functions, and formats output for humans. It contains no cryptographic logic whatsoever. This means the CLI is guaranteed to have the same behaviour as the library — they share the same code paths.

---

## Installation

### From PyPI (once published)

```bash
pip install hybrid-encrypt
```

### From Source

```bash
git clone https://github.com/raptor7197/hybrid-encrypt.git
cd hybrid-encrypt
pip install .
```

### For Development (editable install with test dependencies)

```bash
git clone https://github.com/raptor7197/hybrid-encrypt.git
cd hybrid-encrypt
pip install -e ".[dev]"
```

The `[dev]` extra installs `pytest` and `pytest-cov` alongside the package. The `-e` (editable) flag means changes you make to the source files are immediately reflected without reinstalling — essential for active development.

### Verify Installation

```bash
# Check the CLI tool is available
hybrid-encrypt --help

# Check the library imports correctly
python -c "from hybrid_encrypt import HybridEncryption; print('OK')"
```

### Requirements

- Python 3.9 or higher
- `rsa >= 4.9`
- `cryptography >= 42.0`

Both dependencies are installed automatically by pip.

---

## Quick Start

### As a Library

```python
from hybrid_encrypt import HybridEncryption, KeyStorage, PayloadStorage

enc = HybridEncryption()


# Step 1: Generate an RSA key pair (do this once, save the keys)
pubkey, privkey = enc.generate_rsa_keys()

# Step 2: Save the keys to disk
storage = KeyStorage(key_dir="my_keys")
storage.save_keys(pubkey, privkey)

# Step 3: Encrypt a message
payload = enc.hybrid_encrypt("Hello, World!", pubkey)

# Step 4: Save the encrypted payload to disk (or send it, or serialise it)
payload_storage = PayloadStorage(output_dir="output")
payload_storage.save_payload(payload, filename="message.json")

# --- RECEIVER SIDE ---

# Step 5: Load the private key
_, loaded_privkey = storage.load_keys()

# Step 6: Load the encrypted payload
loaded_payload = payload_storage.load_payload(filename="message.json")

# Step 7: Decrypt
message = enc.hybrid_decrypt(loaded_payload, loaded_privkey)
print(message)  # "Hello, World!"
```

### As a CLI Tool

```bash
# Step 1: Generate keys
hybrid-encrypt keygen

# Step 2: Encrypt a message
hybrid-encrypt encrypt --message "Hello, World!"

# Step 3: Decrypt it
hybrid-encrypt decrypt
```

---

## Library API Reference

### HybridEncryption

The central class. Import it directly from the top-level package:

```python
from hybrid_encrypt import HybridEncryption
enc = HybridEncryption()
```

---

#### `generate_rsa_keys(key_size=2048)`

Generates a new RSA public/private key pair.

**Parameters:**

| Parameter  | Type  | Default | Description                                                    |
|------------|-------|---------|----------------------------------------------------------------|
| `key_size` | `int` | `2048`  | RSA modulus size in bits. Must be >= 512. Use 4096 for maximum security. |

**Returns:** `tuple[rsa.PublicKey, rsa.PrivateKey]`

**Raises:** `ValueError` if `key_size < 512`

**Performance note:** Key generation is intentionally slow because finding large prime numbers is computationally expensive. Typical times:
- 512-bit: ~0.1 seconds (testing only — not secure)
- 1024-bit: ~0.5 seconds (not recommended for production)
- 2048-bit: ~2–5 seconds (recommended minimum)
- 4096-bit: ~15–60 seconds (maximum security)

You should generate keys once, save them with `KeyStorage`, and reuse them. Do not generate new keys for every message.

```python
pubkey, privkey = enc.generate_rsa_keys()
pubkey, privkey = enc.generate_rsa_keys(key_size=4096)  # higher security
```

---

#### `generate_aes_key()`

Generates a cryptographically secure random 256-bit AES key.

**Returns:** `bytes` — 32 random bytes from the OS entropy pool

**Note:** You do not normally need to call this directly. `hybrid_encrypt()` calls it internally and generates a fresh key for every message. Calling it yourself is only needed if you are using `aes_encrypt()` / `aes_decrypt()` directly.

```python
key = enc.generate_aes_key()
print(len(key))   # 32
print(key.hex())  # e.g. "a3f1...b2c9"
```

---

#### `aes_encrypt(message, aes_key)`

Encrypts a string message with AES-256-ECB.

**Parameters:**

| Parameter  | Type    | Description                                         |
|------------|---------|-----------------------------------------------------|
| `message`  | `str`   | The plaintext string to encrypt                     |
| `aes_key`  | `bytes` | A 32-byte AES key (from `generate_aes_key()`)       |

**Returns:** `bytes` — raw ciphertext

**Raises:** `ValueError` if `aes_key` is not exactly 32 bytes

**How it works internally:**
1. Encodes the message string to UTF-8 bytes
2. Applies PKCS7 padding to make the length a multiple of 16
3. Creates an AES cipher in ECB mode
4. Runs the padded bytes through the encryptor
5. Returns raw ciphertext bytes

```python
key = enc.generate_aes_key()
ciphertext = enc.aes_encrypt("Secret message", key)
print(type(ciphertext))   # <class 'bytes'>
print(len(ciphertext))    # always a multiple of 16
```

---

#### `aes_decrypt(ciphertext, aes_key)`

Decrypts AES-256-ECB ciphertext back to a plaintext string.

**Parameters:**

| Parameter    | Type    | Description                                          |
|--------------|---------|------------------------------------------------------|
| `ciphertext` | `bytes` | Raw ciphertext bytes from `aes_encrypt()`            |
| `aes_key`    | `bytes` | The same 32-byte key used during encryption          |

**Returns:** `str` — the original plaintext string

**Raises:**
- `ValueError` if `aes_key` is not exactly 32 bytes
- `ValueError` if padding is invalid (typically means wrong key)
- `Exception` from the underlying `cryptography` library on cipher failure

```python
key = enc.generate_aes_key()
ct = enc.aes_encrypt("Hello", key)
msg = enc.aes_decrypt(ct, key)
print(msg)  # "Hello"
```

---

#### `rsa_encrypt(data, pubkey)`

Encrypts raw bytes with an RSA public key using PKCS#1 v1.5 padding.

**Parameters:**

| Parameter | Type            | Description                                                    |
|-----------|-----------------|----------------------------------------------------------------|
| `data`    | `bytes`         | Raw bytes to encrypt. Max ~245 bytes for RSA-2048.             |
| `pubkey`  | `rsa.PublicKey` | The recipient's RSA public key                                 |

**Returns:** `bytes` — RSA ciphertext

**Raises:** `OverflowError` if `data` is too large for the key size

**Size limits by key size:**
- RSA-1024: max ~117 bytes
- RSA-2048: max ~245 bytes
- RSA-4096: max ~501 bytes

This is why RSA alone cannot encrypt large messages, and why we use it only to encrypt the AES key (which is always exactly 32 bytes — well within any key size's limit).

```python
pubkey, privkey = enc.generate_rsa_keys()
ciphertext = enc.rsa_encrypt(b"short data", pubkey)
```

---

#### `rsa_decrypt(ciphertext, privkey)`

Decrypts RSA ciphertext back to bytes using a private key.

**Parameters:**

| Parameter    | Type              | Description                                    |
|--------------|-------------------|------------------------------------------------|
| `ciphertext` | `bytes`           | RSA ciphertext from `rsa_encrypt()`            |
| `privkey`    | `rsa.PrivateKey`  | The private key matching the encryption key    |

**Returns:** `bytes` — the original plaintext bytes

**Raises:** `rsa.DecryptionError` if the key is wrong or data is corrupted

```python
recovered = enc.rsa_decrypt(ciphertext, privkey)
print(recovered)  # b"short data"
```

---

#### `hybrid_encrypt(message, pubkey)`

The main encryption method. Combines AES-256 and RSA-2048 into one clean operation.

**Parameters:**

| Parameter | Type            | Description                                        |
|-----------|-----------------|----------------------------------------------------|
| `message` | `str`           | The plaintext message. Any length. Any UTF-8 text. |
| `pubkey`  | `rsa.PublicKey` | Recipient's RSA public key                         |

**Returns:** `EncryptedPayload` — contains both ciphertexts as hex strings

**Raises:** `ValueError` if `message` is empty

**What happens internally:**
1. `generate_aes_key()` — fresh 32 random bytes
2. `aes_encrypt(message, aes_key)` — encrypt the message
3. `rsa_encrypt(aes_key, pubkey)` — encrypt the AES key
4. Hex-encode both outputs
5. Wrap in `EncryptedPayload` and return

Every call generates a brand-new AES key, so encrypting the same message twice produces different ciphertexts. This is correct and desirable behaviour.

```python
pubkey, privkey = enc.generate_rsa_keys()
payload = enc.hybrid_encrypt("Hello, World!", pubkey)
print(payload.encrypted_message)   # hex string
print(payload.encrypted_aes_key)   # hex string
print(payload.encryption_method)   # "AES-256-ECB + RSA-2048"
```

---

#### `hybrid_decrypt(payload, privkey)`

The main decryption method. Reverses `hybrid_encrypt()` exactly.

**Parameters:**

| Parameter  | Type               | Description                                             |
|------------|--------------------|---------------------------------------------------------|
| `payload`  | `EncryptedPayload` | The payload from `hybrid_encrypt()` or loaded from JSON |
| `privkey`  | `rsa.PrivateKey`   | The private key matching the public key used to encrypt |

**Returns:** `str` — the original plaintext message, character-for-character identical

**Raises:**
- `rsa.DecryptionError` if the private key is wrong
- `ValueError` if the payload is malformed
- Any exception from the underlying cipher on data corruption

```python
message = enc.hybrid_decrypt(payload, privkey)
print(message)  # "Hello, World!"
```

---

### EncryptedPayload

A dataclass that holds the output of `hybrid_encrypt()`. It is the central data structure of the package — the thing you store, transmit, and later decrypt.

```python
from hybrid_encrypt import EncryptedPayload
```

**Fields:**

| Field                | Type  | Description                                             |
|----------------------|-------|---------------------------------------------------------|
| `encrypted_message`  | `str` | The AES-encrypted message as a hex string               |
| `encrypted_aes_key`  | `str` | The RSA-encrypted AES key as a hex string               |
| `encryption_method`  | `str` | Human-readable label. Default: `"AES-256-ECB + RSA-2048"` |

---

#### `to_dict()`

Returns the payload as a plain Python dictionary.

```python
d = payload.to_dict()
# {
#   "encrypted_message": "a3f1...",
#   "encrypted_aes_key": "b2c9...",
#   "encryption_method": "AES-256-ECB + RSA-2048"
# }
```

---

#### `to_json(indent=4)`

Serialises the payload to a JSON string. Ready to write to a file or send over HTTP.

```python
json_str = payload.to_json()
json_str = payload.to_json(indent=2)  # compact
```

---

#### `from_dict(data)` — classmethod

Reconstructs an `EncryptedPayload` from a plain dictionary.

```python
payload = EncryptedPayload.from_dict({
    "encrypted_message": "a3f1...",
    "encrypted_aes_key": "b2c9...",
})
```

---

#### `from_json(json_str)` — classmethod

Reconstructs an `EncryptedPayload` from a JSON string. The inverse of `to_json()`.

```python
payload = EncryptedPayload.from_json(json_str)
```

**Typical pattern for transmitting over a network:**

```python
# Sender
payload = enc.hybrid_encrypt("Secret", pubkey)
json_str = payload.to_json()
# ... send json_str over HTTP, websocket, etc. ...

# Receiver
received_payload = EncryptedPayload.from_json(json_str)
message = enc.hybrid_decrypt(received_payload, privkey)
```

---

### KeyStorage

Manages saving and loading RSA key pairs from disk. Keys are stored in **PEM format** (Privacy Enhanced Mail), which is the standard text-based encoding used by OpenSSL, SSH, TLS certificates, and every major cryptographic tool.

```python
from hybrid_encrypt import KeyStorage
storage = KeyStorage(key_dir="keys")
```

**Constructor Parameters:**

| Parameter | Type  | Default  | Description                             |
|-----------|-------|----------|-----------------------------------------|
| `key_dir` | `str` | `"keys"` | Directory where key files will be saved |

**Files created:**

| File                     | Description                                |
|--------------------------|--------------------------------------------|
| `keys/public_key.pem`    | RSA public key in PKCS#1 PEM format        |
| `keys/private_key.pem`   | RSA private key in PKCS#1 PEM format       |

The private key file is automatically set to permission mode `0o600` (owner read/write only) on Unix systems. This prevents other users on the same machine from reading your private key.

---

#### `save_keys(pubkey, privkey)`

Saves both keys to disk. Creates the directory if it does not exist.

**Returns:** `tuple[Path, Path]` — absolute paths of the public and private key files

```python
pub_path, priv_path = storage.save_keys(pubkey, privkey)
print(pub_path)   # /home/user/project/keys/public_key.pem
print(priv_path)  # /home/user/project/keys/private_key.pem
```

**Why PEM and not pickle?**

The original scripts used Python's `pickle` module to save keys. This has several serious problems:
- `pickle` files are Python-version-specific and may fail to load across versions
- `pickle` is a known security risk — loading a malicious pickle file executes arbitrary code
- `pickle` files are binary blobs that cannot be inspected or used by any non-Python tool

PEM files, by contrast:
- Are plain text and human-readable
- Are universally supported by OpenSSL, SSH, Java keystores, Go, Rust, Node.js, etc.
- Have no security risk on load
- Can be verified and inspected with `openssl rsa -in private_key.pem -text -noout`

---

#### `load_keys()`

Loads both keys from disk.

**Returns:** `tuple[rsa.PublicKey, rsa.PrivateKey]`

**Raises:** `FileNotFoundError` with a helpful message if either key file is missing

```python
pubkey, privkey = storage.load_keys()
```

---

#### `load_public_key()`

Loads only the public key. Useful on the sender's machine, which may not have the private key.

**Returns:** `rsa.PublicKey`

---

#### `load_private_key()`

Loads only the private key. Useful on the receiver's machine.

**Returns:** `rsa.PrivateKey`

---

#### `keys_exist()`

Returns `True` if both key files are present. Useful for checking before attempting to load.

```python
if not storage.keys_exist():
    pubkey, privkey = enc.generate_rsa_keys()
    storage.save_keys(pubkey, privkey)
```

---

### PayloadStorage

Manages saving and loading `EncryptedPayload` objects as JSON files.

```python
from hybrid_encrypt import PayloadStorage
payload_storage = PayloadStorage(output_dir=".")
```

**Constructor Parameters:**

| Parameter    | Type  | Default | Description                              |
|--------------|-------|---------|------------------------------------------|
| `output_dir` | `str` | `"."`   | Directory for reading and writing payloads |

---

#### `save_payload(payload, filename="encrypted_data.json")`

Serialises the payload to JSON and writes it to disk. Creates the directory if needed.

**Returns:** `Path` — absolute path of the written file

```python
path = payload_storage.save_payload(payload)
path = payload_storage.save_payload(payload, filename="message_for_alice.json")
```

---

#### `load_payload(filename="encrypted_data.json")`

Reads a JSON file from disk and reconstructs an `EncryptedPayload`.

**Returns:** `EncryptedPayload`

**Raises:** `FileNotFoundError` if the file does not exist

```python
payload = payload_storage.load_payload()
payload = payload_storage.load_payload(filename="message_for_alice.json")
```

---

#### `list_payloads()`

Returns a sorted list of all `*.json` files in `output_dir`.

**Returns:** `list[Path]`

```python
files = payload_storage.list_payloads()
for f in files:
    print(f.name)
```

---

## Command-Line Interface

When you install the package, a `hybrid-encrypt` command is registered on your system PATH. It provides access to all features of the library without writing any Python.

### Global Help

```bash
hybrid-encrypt --help
```

```
usage: hybrid-encrypt [-h] COMMAND ...

Hybrid RSA-2048 + AES-256 encryption toolkit.

Commands:
  keygen        Generate a new RSA key pair
  encrypt       Hybrid-encrypt a message (RSA + AES)
  decrypt       Hybrid-decrypt a payload (RSA + AES)
  aes-encrypt   Encrypt a message using AES-256 only
  aes-decrypt   Decrypt an AES-256-only encrypted message
  rsa-encrypt   Encrypt a short message using RSA only
  rsa-decrypt   Decrypt an RSA-only encrypted message
```

---

### `hybrid-encrypt keygen`

Generates a new RSA key pair and saves it to disk.

```bash
hybrid-encrypt keygen
hybrid-encrypt keygen --key-size 4096
hybrid-encrypt keygen --key-dir /secure/location/keys
```

**Options:**

| Option        | Default  | Description                              |
|---------------|----------|------------------------------------------|
| `--key-size`  | `2048`   | RSA key size in bits                     |
| `--key-dir`   | `keys/`  | Directory to save key files              |

**Output:**
```
Generating RSA-2048 key pair ...
✓ Public key  saved to: /home/user/project/keys/public_key.pem
✓ Private key saved to: /home/user/project/keys/private_key.pem
Keep your private key safe and never share it!
```

---

### `hybrid-encrypt encrypt`

Hybrid-encrypts a message and saves the result as a JSON file.

```bash
# Pass message as a flag
hybrid-encrypt encrypt --message "Hello, World!"

# Interactive prompt (message will not appear in shell history)
hybrid-encrypt encrypt

# Custom output file and directory
hybrid-encrypt encrypt --message "Secret" --output-file msg.json --output-dir ./encrypted

# Use keys from a custom directory
hybrid-encrypt encrypt --message "Secret" --key-dir /secure/keys
```

**Options:**

| Option           | Default                  | Description                                   |
|------------------|--------------------------|-----------------------------------------------|
| `--message`, `-m`| (prompted if omitted)    | The message to encrypt                        |
| `--output-file`  | `encrypted_data.json`    | Name of the output file                       |
| `--output-dir`   | `.`                      | Directory to write the output file            |
| `--key-dir`      | `keys/`                  | Directory containing the RSA public key       |

**Output:**
```
✓ Encryption successful!
  Encrypted payload saved to: /home/user/project/encrypted_data.json
  Encrypted message (preview): a3f1b2c9d4e5f6...
  Encrypted AES key (preview): 7890abcdef1234...
```

**Security tip:** Use the interactive prompt instead of `--message` for sensitive data. Anything passed as a command-line argument can appear in your shell history (`~/.bash_history`, `~/.zsh_history`) and in `/proc/<pid>/cmdline`, making it visible to other processes on the same machine.

---

### `hybrid-encrypt decrypt`

Decrypts a previously encrypted payload file.

```bash
hybrid-encrypt decrypt
hybrid-encrypt decrypt --input-file msg.json
hybrid-encrypt decrypt --input-file msg.json --output-dir ./encrypted --key-dir /secure/keys
```

**Options:**

| Option          | Default                  | Description                                   |
|-----------------|--------------------------|-----------------------------------------------|
| `--input-file`  | `encrypted_data.json`    | Name of the encrypted payload file to decrypt |
| `--output-dir`  | `.`                      | Directory containing the payload file         |
| `--key-dir`     | `keys/`                  | Directory containing the RSA private key      |

**Output:**
```
✓ Decryption successful!
  Decrypted message: Hello, World!
```

---

### `hybrid-encrypt aes-encrypt`

Encrypts a message with AES-256 only. Generates and prints the AES key. You must store the key manually.

```bash
hybrid-encrypt aes-encrypt --message "Quick secret"
hybrid-encrypt aes-encrypt   # interactive prompt
```

**Output:**
```
✓ AES-256 encryption successful!
  AES key (hex) : a3f1b2c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  Ciphertext    : 7890abcdef12345678901234567890ab

⚠  Store the AES key securely — you will need it to decrypt.
```

**When to use AES-only:** When you are encrypting data for yourself (you are both sender and receiver) and you have a secure way to store the key, such as a password manager or a hardware security module.

---

### `hybrid-encrypt aes-decrypt`

Decrypts AES-256-only ciphertext.

```bash
hybrid-encrypt aes-decrypt \
  --key a3f1b2c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1 \
  --ciphertext 7890abcdef12345678901234567890ab
```

**Options:**

| Option         | Required | Description                              |
|----------------|----------|------------------------------------------|
| `--key`        | Yes      | AES key as a 64-character hex string     |
| `--ciphertext` | Yes      | Ciphertext as a hex string               |

---

### `hybrid-encrypt rsa-encrypt`

Encrypts a short message (≤ 245 bytes for RSA-2048) using RSA only.

```bash
hybrid-encrypt rsa-encrypt --message "Short text"
hybrid-encrypt rsa-encrypt --key-dir /secure/keys --message "Hi"
```

**When to use RSA-only:** Generally, you should not use RSA-only for message encryption. It exists here for completeness and for cases where you specifically need to encrypt a small secret (like an authentication token) with a public key and have no need for the hybrid scheme.

---

### `hybrid-encrypt rsa-decrypt`

Decrypts RSA-only ciphertext.

```bash
hybrid-encrypt rsa-decrypt --ciphertext 7890abcdef...
hybrid-encrypt rsa-decrypt --ciphertext 7890abcdef... --key-dir /secure/keys
```

---

## Data Formats

### Encrypted Payload JSON

The standard output format of `hybrid-encrypt encrypt`. It is a plain JSON object with three fields:

```json
{
    "encrypted_message": "a3f1b2c9d4e5f6a7b8c9d0e1f2a3b4c5...",
    "encrypted_aes_key": "7890abcdef1234567890abcdef123456...",
    "encryption_method": "AES-256-ECB + RSA-2048"
}
```

**Field details:**

| Field                | Content                                                                  |
|----------------------|--------------------------------------------------------------------------|
| `encrypted_message`  | Hex-encoded AES-256-ECB ciphertext. Length depends on message length.    |
| `encrypted_aes_key`  | Hex-encoded RSA-2048 ciphertext of the 32-byte AES key. Always 512 hex chars (256 bytes) for RSA-2048. |
| `encryption_method`  | Informational string. Not used during decryption.                        |

Hex encoding is used (rather than base64 or raw bytes) because hex strings are:
- Universally readable with no special tools
- Safe to copy-paste without encoding corruption
- Easy to inspect and debug
- Valid in all JSON parsers without escaping

### PEM Key Files

RSA keys are stored in standard PKCS#1 PEM format:

**Public key (`public_key.pem`):**
```
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA2a2rwplBQLzHPZe5RJr9vSMWFk...
-----END RSA PUBLIC KEY-----
```

**Private key (`private_key.pem`):**
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9vS...
-----END RSA PRIVATE KEY-----
```

These files are compatible with OpenSSL. You can inspect them with:

```bash
# View public key details
openssl rsa -pubin -in keys/public_key.pem -text -noout

# View private key details (keep this secret!)
openssl rsa -in keys/private_key.pem -text -noout
```

---

## Security Design

### What This Package Does Right

**Fresh AES key per message:** Every call to `hybrid_encrypt()` generates a brand-new random AES key. This means that even if an attacker somehow recovers the AES key for one message, all other messages remain secure. Each message is independently protected.

**OS-level entropy:** Key generation uses `os.urandom()`, which pulls from the operating system's CSPRNG. This is the correct source for cryptographic randomness and cannot be predicted or reproduced.

**PEM over pickle:** Key storage uses standard PEM format instead of Python's `pickle`. This is more portable, more secure (no arbitrary code execution on load), and compatible with the broader cryptographic ecosystem.

**Private key file permissions:** On Unix systems, the private key file is automatically `chmod 600` — readable and writable only by the owner. Other users on the same system cannot read it.

**Input validation:** All functions validate their inputs and raise descriptive exceptions rather than silently producing incorrect output. For example, passing a key of the wrong length raises `ValueError` immediately, before any cryptographic operation is attempted.

**No hardcoded secrets:** There are no passwords, keys, or seeds embedded anywhere in the code.

### What You Should Know (Limitations and Caveats)

**ECB Mode:** This package uses AES in ECB (Electronic Codebook) mode. ECB has a well-known weakness: if the same 16-byte block appears multiple times in a message, it produces the same ciphertext block. For most text messages this is not exploitable in practice, but for production systems handling structured or binary data you should use AES-CBC or AES-GCM instead. AES-GCM also provides authentication (protection against tampering), which ECB and CBC do not.

**No Message Authentication:** This package provides **confidentiality** (nobody can read the message without the private key) but not **authentication** (there is no proof of who sent the message, and a determined attacker could potentially tamper with the ciphertext). For production systems, consider adding HMAC or using AES-GCM which includes authentication built in.

**No Forward Secrecy:** If an attacker records all your encrypted traffic today and later obtains your RSA private key, they can decrypt everything retroactively. Protocols like TLS 1.3 use ephemeral key exchange to prevent this. For long-term security of very sensitive data, consider a protocol with forward secrecy.

**Key Management is Your Responsibility:** This package handles the cryptography correctly. What it cannot do is tell you where to store your private key, how to back it up, or how to rotate it when it gets old. These are operational security decisions that depend on your threat model.

**RSA PKCS#1 v1.5:** The `rsa` library uses PKCS#1 v1.5 padding for RSA operations. Modern recommendations favour OAEP padding, which is more secure against certain theoretical attacks. For maximum security in new systems, consider migrating to a library that supports RSA-OAEP, such as Python's `cryptography` library directly.

### Recommended Use Cases

- ✅ Encrypting files or messages for a specific recipient who holds the private key
- ✅ Storing sensitive data that only you need to read back later
- ✅ Learning and understanding hybrid cryptography
- ✅ Internal tools and scripts where the above caveats are acceptable
- ✅ Prototyping encrypted communication systems

### Not Recommended For

- ❌ Real-time communication protocols (use Signal Protocol or TLS)
- ❌ Password storage (use bcrypt, scrypt, or Argon2)
- ❌ Large-scale encrypted storage systems (use age or GPG)
- ❌ Any system where data authentication and tamper-detection are critical (use AES-GCM)

---

## Testing

The package ships with 68 automated tests covering every function, edge case, error condition, and integration scenario.

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output (see each test name)
pytest -v

# Run with coverage report
pytest --cov=hybrid_encrypt --cov-report=term-missing

# Run a specific test class
pytest tests/test_hybrid_encrypt.py::TestHybridEncryptDecrypt -v

# Run a specific test
pytest tests/test_hybrid_encrypt.py::TestKeyStorage::test_private_key_file_permissions -v
```

### Test Coverage

|
