"""
hybrid_encrypt.encryption
~~~~~~~~~~~~~~~~~~~~~~~~~
Core encryption module providing AES-256 and RSA-2048 encryption,
plus the hybrid scheme that combines both.
"""

import json
import os
from dataclasses import asdict, dataclass
from typing import Tuple

import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@dataclass
class EncryptedPayload:
    """
    Holds the output of a hybrid encryption operation.

    Attributes:
        encrypted_message:  AES-256-ECB ciphertext (hex string).
        encrypted_aes_key:  RSA-2048 ciphertext of the AES key (hex string).
        encryption_method:  Human-readable description of the scheme used.
    """

    encrypted_message: str
    encrypted_aes_key: str
    encryption_method: str = "AES-256-ECB + RSA-2048"

    def to_dict(self) -> dict:
        """Return the payload as a plain dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 4) -> str:
        """Serialise the payload to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedPayload":
        """Reconstruct an EncryptedPayload from a plain dictionary."""
        return cls(
            encrypted_message=data["encrypted_message"],
            encrypted_aes_key=data["encrypted_aes_key"],
            encryption_method=data.get("encryption_method", "AES-256-ECB + RSA-2048"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "EncryptedPayload":
        """Reconstruct an EncryptedPayload from a JSON string."""
        return cls.from_dict(json.loads(json_str))


class HybridEncryption:
    """
    Hybrid encryption using RSA-2048 + AES-256-ECB.

    Typical usage
    -------------
    >>> enc = HybridEncryption()
    >>> pubkey, privkey = enc.generate_rsa_keys()
    >>> payload = enc.hybrid_encrypt("Hello, World!", pubkey)
    >>> payload.encrypted_message   # hex string
    >>> payload.encrypted_aes_key   # hex string

    The :class:`HybridEncryption` class is intentionally **pure** —
    it never reads from stdin, writes to stdout, or touches the filesystem.
    Those concerns live in :mod:`hybrid_encrypt.cli` and
    :mod:`hybrid_encrypt.storage`.
    """

    def __init__(self) -> None:
        self._backend = default_backend()

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_rsa_keys(
        self, key_size: int = 2048
    ) -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
        """
        Generate a new RSA key pair.

        Parameters
        ----------
        key_size:
            RSA modulus size in bits.  Must be a multiple of 256.
            Defaults to 2048.  Use 4096 for higher security at the cost
            of slower key generation.

        Returns
        -------
        (pubkey, privkey) :
            A tuple of :class:`rsa.PublicKey` and :class:`rsa.PrivateKey`.
        """
        if key_size < 512:
            raise ValueError("key_size must be at least 512 bits.")
        pubkey, privkey = rsa.newkeys(key_size, poolsize=8)
        return pubkey, privkey

    def generate_aes_key(self) -> bytes:
        """
        Generate a cryptographically secure random 256-bit AES key.

        Returns
        -------
        bytes :
            32 random bytes suitable for use as an AES-256 key.
        """
        return os.urandom(32)

    # ------------------------------------------------------------------
    # AES helpers
    # ------------------------------------------------------------------

    def _pad(self, data: bytes) -> bytes:
        """Apply PKCS7-style padding to make *data* a multiple of 16 bytes."""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)

    def _unpad(self, data: bytes) -> bytes:
        """Strip PKCS7-style padding from *data*."""
        if not data:
            raise ValueError("Cannot unpad empty data.")
        padding_length = data[-1]
        if padding_length == 0 or padding_length > 16:
            raise ValueError(f"Invalid padding length: {padding_length}")
        return data[:-padding_length]

    # ------------------------------------------------------------------
    # AES-256-ECB
    # ------------------------------------------------------------------

    def aes_encrypt(self, message: str, aes_key: bytes) -> bytes:
        """
        Encrypt *message* with AES-256-ECB.

        Parameters
        ----------
        message :
            Plaintext string to encrypt.
        aes_key :
            32-byte AES key (use :meth:`generate_aes_key` to create one).

        Returns
        -------
        bytes :
            Raw ciphertext bytes.
        """
        if len(aes_key) != 32:
            raise ValueError("aes_key must be exactly 32 bytes (256 bits).")

        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=self._backend)
        encryptor = cipher.encryptor()
        padded = self._pad(message.encode("utf-8"))
        return encryptor.update(padded) + encryptor.finalize()

    def aes_decrypt(self, ciphertext: bytes, aes_key: bytes) -> str:
        """
        Decrypt AES-256-ECB *ciphertext* back to a plaintext string.

        Parameters
        ----------
        ciphertext :
            Raw ciphertext bytes produced by :meth:`aes_encrypt`.
        aes_key :
            The same 32-byte key used during encryption.

        Returns
        -------
        str :
            Recovered plaintext string.
        """
        if len(aes_key) != 32:
            raise ValueError("aes_key must be exactly 32 bytes (256 bits).")

        cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=self._backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        return self._unpad(padded).decode("utf-8")

    # ------------------------------------------------------------------
    # RSA-2048
    # ------------------------------------------------------------------

    def rsa_encrypt(self, data: bytes, pubkey: rsa.PublicKey) -> bytes:
        """
        Encrypt raw *data* with an RSA public key.

        Parameters
        ----------
        data :
            Raw bytes to encrypt.  Must be shorter than the RSA modulus
            minus PKCS#1 v1.5 overhead (~11 bytes), so ≤ 245 bytes for
            a 2048-bit key.
        pubkey :
            An :class:`rsa.PublicKey` instance.

        Returns
        -------
        bytes :
            RSA ciphertext.
        """
        return rsa.encrypt(data, pubkey)

    def rsa_decrypt(self, ciphertext: bytes, privkey: rsa.PrivateKey) -> bytes:
        """
        Decrypt RSA *ciphertext* with a private key.

        Parameters
        ----------
        ciphertext :
            Bytes produced by :meth:`rsa_encrypt`.
        privkey :
            The matching :class:`rsa.PrivateKey`.

        Returns
        -------
        bytes :
            Recovered plaintext bytes.
        """
        return rsa.decrypt(ciphertext, privkey)

    # ------------------------------------------------------------------
    # Hybrid scheme
    # ------------------------------------------------------------------

    def hybrid_encrypt(self, message: str, pubkey: rsa.PublicKey) -> EncryptedPayload:
        """
        Encrypt *message* with the hybrid RSA + AES scheme.

        Steps
        -----
        1. Generate a fresh 256-bit AES key.
        2. Encrypt the message with AES-256-ECB.
        3. Encrypt the AES key with the RSA public key.
        4. Return both ciphertexts wrapped in an :class:`EncryptedPayload`.

        Parameters
        ----------
        message :
            Plaintext string to encrypt.
        pubkey :
            Recipient's RSA public key.

        Returns
        -------
        EncryptedPayload :
            Contains ``encrypted_message`` and ``encrypted_aes_key`` as
            hex strings, ready to be serialised or transmitted.
        """
        if not message:
            raise ValueError("message must not be empty.")

        aes_key = self.generate_aes_key()
        encrypted_message = self.aes_encrypt(message, aes_key)
        encrypted_aes_key = self.rsa_encrypt(aes_key, pubkey)

        return EncryptedPayload(
            encrypted_message=encrypted_message.hex(),
            encrypted_aes_key=encrypted_aes_key.hex(),
        )

    def hybrid_decrypt(self, payload: EncryptedPayload, privkey: rsa.PrivateKey) -> str:
        """
        Decrypt an :class:`EncryptedPayload` produced by :meth:`hybrid_encrypt`.

        Steps
        -----
        1. RSA-decrypt the encrypted AES key to recover the raw AES key.
        2. AES-decrypt the encrypted message to recover the plaintext.

        Parameters
        ----------
        payload :
            An :class:`EncryptedPayload` (from :meth:`hybrid_encrypt` or
            loaded via :meth:`EncryptedPayload.from_json`).
        privkey :
            The RSA private key matching the public key used to encrypt.

        Returns
        -------
        str :
            The original plaintext message.
        """
        encrypted_message = bytes.fromhex(payload.encrypted_message)
        encrypted_aes_key = bytes.fromhex(payload.encrypted_aes_key)

        aes_key = self.rsa_decrypt(encrypted_aes_key, privkey)
        return self.aes_decrypt(encrypted_message, aes_key)
