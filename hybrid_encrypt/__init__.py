"""
hybrid_encrypt
~~~~~~~~~~~~~~
A hybrid encryption library combining RSA-2048 and AES-256 for secure
message encryption and decryption.

Basic usage
-----------
>>> from hybrid_encrypt import HybridEncryption, KeyStorage, PayloadStorage
>>>
>>> enc = HybridEncryption()
>>>
>>> # 1. Generate and save keys
>>> pubkey, privkey = enc.generate_rsa_keys()
>>> storage = KeyStorage(key_dir="keys")
>>> storage.save_keys(pubkey, privkey)
>>>
>>> # 2. Encrypt
>>> payload = enc.hybrid_encrypt("Hello, World!", pubkey)
>>> print(payload.encrypted_message)
>>>
>>> # 3. Decrypt
>>> message = enc.hybrid_decrypt(payload, privkey)
>>> print(message)  # "Hello, World!"
"""

from .encryption import EncryptedPayload, HybridEncryption
from .storage import KeyStorage, PayloadStorage

__all__ = [
    "HybridEncryption",
    "EncryptedPayload",
    "KeyStorage",
    "PayloadStorage",
]

__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "MIT"
