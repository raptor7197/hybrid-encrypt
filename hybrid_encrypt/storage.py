import json
import os
from pathlib import Path
from typing import Tuple

import rsa

from .encryption import EncryptedPayload


class KeyStorage:
    """
    Manages persistence of RSA key pairs and encrypted payloads.

    Keys are stored as PEM-encoded files, which are human-readable,
    portable, and compatible with standard cryptographic tooling.

    Parameters
    ----------
    key_dir :
        Directory where key files will be stored.
        Defaults to ``keys/`` relative to the current working directory.

    Example
    -------
    >>> storage = KeyStorage(key_dir="my_keys")
    >>> storage.save_keys(pubkey, privkey)
    >>> pubkey, privkey = storage.load_keys()
    """

    PUBLIC_KEY_FILENAME = "public_key.pem"
    PRIVATE_KEY_FILENAME = "private_key.pem"

    def __init__(self, key_dir: str = "keys") -> None:
        self.key_dir = Path(key_dir)

    # ------------------------------------------------------------------
    # RSA key persistence
    # ------------------------------------------------------------------

    def save_keys(
        self,
        pubkey: rsa.PublicKey,
        privkey: rsa.PrivateKey,
    ) -> Tuple[Path, Path]:
        """
        Save an RSA key pair as PEM files inside :attr:`key_dir`.

        The directory is created automatically if it does not exist.

        Parameters
        ----------
        pubkey :
            RSA public key to save.
        privkey :
            RSA private key to save.

        Returns
        -------
        (pub_path, priv_path) :
            Absolute paths of the saved public and private key files.
        """
        self.key_dir.mkdir(parents=True, exist_ok=True)

        pub_path = self.key_dir / self.PUBLIC_KEY_FILENAME
        priv_path = self.key_dir / self.PRIVATE_KEY_FILENAME

        pub_path.write_bytes(pubkey.save_pkcs1(format="PEM"))
        priv_path.write_bytes(privkey.save_pkcs1(format="PEM"))

        # Restrict private key permissions to owner-read-only (Unix only)
        try:
            os.chmod(priv_path, 0o600)
        except NotImplementedError:
            pass  # Windows — skip chmod

        return pub_path.resolve(), priv_path.resolve()

    def load_keys(self) -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
        """
        Load the RSA key pair from :attr:`key_dir`.

        Returns
        -------
        (pubkey, privkey) :
            The loaded :class:`rsa.PublicKey` and :class:`rsa.PrivateKey`.

        Raises
        ------
        FileNotFoundError :
            If either key file is missing from :attr:`key_dir`.
        """
        pub_path = self.key_dir / self.PUBLIC_KEY_FILENAME
        priv_path = self.key_dir / self.PRIVATE_KEY_FILENAME

        if not pub_path.exists():
            raise FileNotFoundError(
                f"Public key not found at '{pub_path}'. "
                "Generate keys first with HybridEncryption.generate_rsa_keys()."
            )
        if not priv_path.exists():
            raise FileNotFoundError(
                f"Private key not found at '{priv_path}'. "
                "Generate keys first with HybridEncryption.generate_rsa_keys()."
            )

        pubkey = rsa.PublicKey.load_pkcs1(pub_path.read_bytes(), format="PEM")
        privkey = rsa.PrivateKey.load_pkcs1(priv_path.read_bytes(), format="PEM")

        return pubkey, privkey

    def load_public_key(self) -> rsa.PublicKey:
        """
        Load only the RSA public key from :attr:`key_dir`.

        Returns
        -------
        rsa.PublicKey
        """
        pub_path = self.key_dir / self.PUBLIC_KEY_FILENAME

        if not pub_path.exists():
            raise FileNotFoundError(f"Public key not found at '{pub_path}'.")

        return rsa.PublicKey.load_pkcs1(pub_path.read_bytes(), format="PEM")

    def load_private_key(self) -> rsa.PrivateKey:
        """
        Load only the RSA private key from :attr:`key_dir`.

        Returns
        -------
        rsa.PrivateKey
        """
        priv_path = self.key_dir / self.PRIVATE_KEY_FILENAME

        if not priv_path.exists():
            raise FileNotFoundError(f"Private key not found at '{priv_path}'.")

        return rsa.PrivateKey.load_pkcs1(priv_path.read_bytes(), format="PEM")

    def keys_exist(self) -> bool:
        """
        Return ``True`` if both key files are present in :attr:`key_dir`.
        """
        return (self.key_dir / self.PUBLIC_KEY_FILENAME).exists() and (
            self.key_dir / self.PRIVATE_KEY_FILENAME
        ).exists()


class PayloadStorage:
    """
    Manages persistence of :class:`~hybrid_encrypt.encryption.EncryptedPayload`
    objects as JSON files.

    Parameters
    ----------
    output_dir :
        Directory where payload files will be written.
        Defaults to the current working directory (``"."``).

    Example
    -------
    >>> storage = PayloadStorage(output_dir="output")
    >>> storage.save_payload(payload, "encrypted_data.json")
    >>> payload = storage.load_payload("encrypted_data.json")
    """

    def __init__(self, output_dir: str = ".") -> None:
        self.output_dir = Path(output_dir)

    def save_payload(
        self,
        payload: EncryptedPayload,
        filename: str = "encrypted_data.json",
    ) -> Path:
        """
        Serialise *payload* to a JSON file.

        Parameters
        ----------
        payload :
            The :class:`EncryptedPayload` to save.
        filename :
            Name of the output file.  Written inside :attr:`output_dir`.

        Returns
        -------
        Path :
            Absolute path of the written file.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        out_path = self.output_dir / filename
        out_path.write_text(payload.to_json(), encoding="utf-8")
        return out_path.resolve()

    def load_payload(self, filename: str = "encrypted_data.json") -> EncryptedPayload:
        """
        Load an :class:`EncryptedPayload` from a JSON file.

        Parameters
        ----------
        filename :
            Name of the file to load.  Read from :attr:`output_dir`.

        Returns
        -------
        EncryptedPayload

        Raises
        ------
        FileNotFoundError :
            If *filename* does not exist inside :attr:`output_dir`.
        """
        in_path = self.output_dir / filename

        if not in_path.exists():
            raise FileNotFoundError(f"Encrypted payload not found at '{in_path}'.")

        return EncryptedPayload.from_json(in_path.read_text(encoding="utf-8"))

    def list_payloads(self) -> list:
        """
        Return a list of all ``*.json`` files in :attr:`output_dir`.

        Returns
        -------
        list[Path]
        """
        if not self.output_dir.exists():
            return []
        return sorted(self.output_dir.glob("*.json"))
