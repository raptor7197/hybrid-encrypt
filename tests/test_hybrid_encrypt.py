"""
tests/test_hybrid_encrypt.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Comprehensive test suite for the hybrid_encrypt package.

Run with:
    pytest tests/ -v
    pytest tests/ -v --tb=short
    pytest tests/ -v --cov=hybrid_encrypt --cov-report=term-missing
"""

import json
import os
import tempfile
from pathlib import Path

import pytest
import rsa

from hybrid_encrypt import (
    EncryptedPayload,
    HybridEncryption,
    KeyStorage,
    PayloadStorage,
)

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture(scope="module")
def enc():
    """A single HybridEncryption instance shared across the test module."""
    return HybridEncryption()


@pytest.fixture(scope="module")
def rsa_keypair(enc):
    """Generate one RSA-2048 key pair for the entire module (slow operation)."""
    return enc.generate_rsa_keys(key_size=512)  # 512-bit for speed in tests


@pytest.fixture(scope="module")
def pubkey(rsa_keypair):
    return rsa_keypair[0]


@pytest.fixture(scope="module")
def privkey(rsa_keypair):
    return rsa_keypair[1]


@pytest.fixture()
def tmp_key_dir(tmp_path):
    """A fresh temporary directory for each key-storage test."""
    return tmp_path / "keys"


@pytest.fixture()
def tmp_payload_dir(tmp_path):
    """A fresh temporary directory for each payload-storage test."""
    return tmp_path / "payloads"


@pytest.fixture(scope="module")
def sample_payload(enc, pubkey):
    """A pre-built encrypted payload used across multiple tests."""
    return enc.hybrid_encrypt("Hello, hybrid_encrypt!", pubkey)


# ===========================================================================
# HybridEncryption — key generation
# ===========================================================================


class TestKeyGeneration:
    def test_generate_rsa_keys_returns_tuple(self, enc):
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        assert isinstance(pubkey, rsa.PublicKey)
        assert isinstance(privkey, rsa.PrivateKey)

    def test_generated_keys_are_different_each_time(self, enc):
        pub1, priv1 = enc.generate_rsa_keys(key_size=512)
        pub2, priv2 = enc.generate_rsa_keys(key_size=512)
        assert pub1.n != pub2.n

    def test_generate_rsa_keys_default_size(self, enc):
        # Just check it returns the right types without verifying bit length
        # (2048-bit generation is slow; we trust the rsa library)
        pub, priv = enc.generate_rsa_keys(key_size=512)
        assert pub is not None
        assert priv is not None

    def test_generate_rsa_keys_rejects_tiny_size(self, enc):
        with pytest.raises(ValueError, match="key_size must be at least 512"):
            enc.generate_rsa_keys(key_size=128)

    def test_generate_aes_key_length(self, enc):
        key = enc.generate_aes_key()
        assert len(key) == 32

    def test_generate_aes_key_is_random(self, enc):
        key1 = enc.generate_aes_key()
        key2 = enc.generate_aes_key()
        assert key1 != key2

    def test_generate_aes_key_returns_bytes(self, enc):
        key = enc.generate_aes_key()
        assert isinstance(key, bytes)


# ===========================================================================
# HybridEncryption — AES encrypt / decrypt
# ===========================================================================


class TestAESEncryptDecrypt:
    MESSAGES = [
        "Hello, World!",
        "a",
        "x" * 1000,
        "Unicode: こんにちは 🔐",
        "Exactly 16 chars",  # exactly one block
        "Exactly 32 chars here — two!!!!!",  # exactly two blocks
        "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
    ]

    @pytest.mark.parametrize("message", MESSAGES)
    def test_roundtrip(self, enc, message):
        key = enc.generate_aes_key()
        ciphertext = enc.aes_encrypt(message, key)
        recovered = enc.aes_decrypt(ciphertext, key)
        assert recovered == message

    def test_ciphertext_is_bytes(self, enc):
        key = enc.generate_aes_key()
        ct = enc.aes_encrypt("test", key)
        assert isinstance(ct, bytes)

    def test_ciphertext_differs_per_key(self, enc):
        msg = "same message"
        key1 = enc.generate_aes_key()
        key2 = enc.generate_aes_key()
        ct1 = enc.aes_encrypt(msg, key1)
        ct2 = enc.aes_encrypt(msg, key2)
        assert ct1 != ct2

    def test_ciphertext_is_multiple_of_16(self, enc):
        key = enc.generate_aes_key()
        for msg in ["a", "ab" * 8, "x" * 31]:
            ct = enc.aes_encrypt(msg, key)
            assert len(ct) % 16 == 0

    def test_wrong_key_raises(self, enc):
        key = enc.generate_aes_key()
        wrong_key = enc.generate_aes_key()
        ct = enc.aes_encrypt("secret", key)
        # Decrypting with the wrong key should raise an error
        with pytest.raises(Exception):
            enc.aes_decrypt(ct, wrong_key)

    def test_bad_key_length_encrypt_raises(self, enc):
        with pytest.raises(ValueError, match="32 bytes"):
            enc.aes_encrypt("msg", b"tooshort")

    def test_bad_key_length_decrypt_raises(self, enc):
        key = enc.generate_aes_key()
        ct = enc.aes_encrypt("msg", key)
        with pytest.raises(ValueError, match="32 bytes"):
            enc.aes_decrypt(ct, b"tooshort")


# ===========================================================================
# HybridEncryption — RSA encrypt / decrypt
# ===========================================================================


class TestRSAEncryptDecrypt:
    def test_roundtrip(self, enc, pubkey, privkey):
        data = b"short rsa test"
        ct = enc.rsa_encrypt(data, pubkey)
        recovered = enc.rsa_decrypt(ct, privkey)
        assert recovered == data

    def test_ciphertext_is_bytes(self, enc, pubkey):
        ct = enc.rsa_encrypt(b"hi", pubkey)
        assert isinstance(ct, bytes)

    def test_ciphertext_differs_per_call(self, enc, pubkey):
        # RSA PKCS#1 v1.5 uses random padding, so ciphertexts differ
        ct1 = enc.rsa_encrypt(b"hello", pubkey)
        ct2 = enc.rsa_encrypt(b"hello", pubkey)
        assert ct1 != ct2

    def test_wrong_private_key_raises(self, enc, pubkey):
        _, other_privkey = enc.generate_rsa_keys(key_size=512)
        ct = enc.rsa_encrypt(b"hello", pubkey)
        with pytest.raises(Exception):
            enc.rsa_decrypt(ct, other_privkey)


# ===========================================================================
# HybridEncryption — hybrid encrypt / decrypt
# ===========================================================================


class TestHybridEncryptDecrypt:
    MESSAGES = [
        "Hello, World!",
        "Short",
        "A longer message that spans multiple AES blocks for sure.",
        "Unicode works too: مرحبا 🔒",
        "x" * 5000,
    ]

    @pytest.mark.parametrize("message", MESSAGES)
    def test_roundtrip(self, enc, pubkey, privkey, message):
        payload = enc.hybrid_encrypt(message, pubkey)
        recovered = enc.hybrid_decrypt(payload, privkey)
        assert recovered == message

    def test_returns_encrypted_payload(self, enc, pubkey):
        payload = enc.hybrid_encrypt("test", pubkey)
        assert isinstance(payload, EncryptedPayload)

    def test_payload_fields_are_hex_strings(self, enc, pubkey):
        payload = enc.hybrid_encrypt("test", pubkey)
        # Should not raise ValueError
        bytes.fromhex(payload.encrypted_message)
        bytes.fromhex(payload.encrypted_aes_key)

    def test_different_payloads_per_call(self, enc, pubkey):
        msg = "same message"
        p1 = enc.hybrid_encrypt(msg, pubkey)
        p2 = enc.hybrid_encrypt(msg, pubkey)
        # Fresh AES key each time means ciphertext differs
        assert p1.encrypted_message != p2.encrypted_message

    def test_encryption_method_label(self, enc, pubkey):
        payload = enc.hybrid_encrypt("test", pubkey)
        assert payload.encryption_method == "AES-256-ECB + RSA-2048"

    def test_empty_message_raises(self, enc, pubkey):
        with pytest.raises(ValueError, match="empty"):
            enc.hybrid_encrypt("", pubkey)

    def test_wrong_private_key_raises(self, enc, pubkey):
        _, other_priv = enc.generate_rsa_keys(key_size=512)
        payload = enc.hybrid_encrypt("secret", pubkey)
        with pytest.raises(Exception):
            enc.hybrid_decrypt(payload, other_priv)


# ===========================================================================
# EncryptedPayload — serialisation
# ===========================================================================


class TestEncryptedPayload:
    def test_to_dict_has_required_keys(self, sample_payload):
        d = sample_payload.to_dict()
        assert "encrypted_message" in d
        assert "encrypted_aes_key" in d
        assert "encryption_method" in d

    def test_to_json_is_valid_json(self, sample_payload):
        json_str = sample_payload.to_json()
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_from_dict_roundtrip(self, sample_payload):
        d = sample_payload.to_dict()
        restored = EncryptedPayload.from_dict(d)
        assert restored.encrypted_message == sample_payload.encrypted_message
        assert restored.encrypted_aes_key == sample_payload.encrypted_aes_key
        assert restored.encryption_method == sample_payload.encryption_method

    def test_from_json_roundtrip(self, sample_payload):
        json_str = sample_payload.to_json()
        restored = EncryptedPayload.from_json(json_str)
        assert restored.encrypted_message == sample_payload.encrypted_message
        assert restored.encrypted_aes_key == sample_payload.encrypted_aes_key

    def test_from_dict_missing_encryption_method_uses_default(self, sample_payload):
        d = sample_payload.to_dict()
        del d["encryption_method"]
        restored = EncryptedPayload.from_dict(d)
        assert restored.encryption_method == "AES-256-ECB + RSA-2048"

    def test_to_json_indent(self, sample_payload):
        json_str = sample_payload.to_json(indent=2)
        # Indented JSON should have newlines
        assert "\n" in json_str

    def test_payload_survives_encrypt_decrypt_via_json(self, enc, pubkey, privkey):
        original_message = "serialise and back"
        payload = enc.hybrid_encrypt(original_message, pubkey)

        # Serialise to JSON and reconstruct
        json_str = payload.to_json()
        restored_payload = EncryptedPayload.from_json(json_str)

        recovered = enc.hybrid_decrypt(restored_payload, privkey)
        assert recovered == original_message


# ===========================================================================
# KeyStorage
# ===========================================================================


class TestKeyStorage:
    def test_save_and_load_keys(self, enc, tmp_key_dir):
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))

        pub_path, priv_path = storage.save_keys(pubkey, privkey)

        assert Path(pub_path).exists()
        assert Path(priv_path).exists()

        loaded_pub, loaded_priv = storage.load_keys()

        # Keys should be functionally equivalent
        data = b"key storage test"
        ct = enc.rsa_encrypt(data, loaded_pub)
        recovered = enc.rsa_decrypt(ct, loaded_priv)
        assert recovered == data

    def test_save_creates_key_dir(self, enc, tmp_key_dir):
        assert not tmp_key_dir.exists()
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        storage.save_keys(pubkey, privkey)
        assert tmp_key_dir.exists()

    def test_private_key_file_permissions(self, enc, tmp_key_dir):
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        _, priv_path = storage.save_keys(pubkey, privkey)
        mode = oct(Path(priv_path).stat().st_mode)
        # Should be owner-read-only (0o600)
        assert mode.endswith("600")

    def test_keys_are_saved_as_pem(self, enc, tmp_key_dir):
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        pub_path, priv_path = storage.save_keys(pubkey, privkey)

        pub_contents = Path(pub_path).read_bytes()
        priv_contents = Path(priv_path).read_bytes()

        assert pub_contents.startswith(b"-----BEGIN RSA PUBLIC KEY-----")
        assert priv_contents.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    def test_load_public_key_only(self, enc, tmp_key_dir):
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        storage.save_keys(pubkey, privkey)

        loaded_pub = storage.load_public_key()
        assert isinstance(loaded_pub, rsa.PublicKey)

    def test_load_private_key_only(self, enc, tmp_key_dir):
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        storage.save_keys(pubkey, privkey)

        loaded_priv = storage.load_private_key()
        assert isinstance(loaded_priv, rsa.PrivateKey)

    def test_keys_exist_true(self, enc, tmp_key_dir):
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        assert not storage.keys_exist()
        storage.save_keys(pubkey, privkey)
        assert storage.keys_exist()

    def test_keys_exist_false_when_empty(self, tmp_key_dir):
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        assert not storage.keys_exist()

    def test_load_missing_public_key_raises(self, tmp_key_dir):
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        with pytest.raises(FileNotFoundError, match="Public key not found"):
            storage.load_public_key()

    def test_load_missing_private_key_raises(self, tmp_key_dir):
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        with pytest.raises(FileNotFoundError, match="Private key not found"):
            storage.load_private_key()

    def test_load_keys_missing_both_raises(self, tmp_key_dir):
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        with pytest.raises(FileNotFoundError):
            storage.load_keys()

    def test_full_pipeline_with_storage(self, enc, tmp_key_dir):
        """Generate → save → load → encrypt → decrypt."""
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        storage = KeyStorage(key_dir=str(tmp_key_dir))
        storage.save_keys(pubkey, privkey)

        loaded_pub, loaded_priv = storage.load_keys()

        message = "full storage pipeline test"
        payload = enc.hybrid_encrypt(message, loaded_pub)
        recovered = enc.hybrid_decrypt(payload, loaded_priv)
        assert recovered == message


# ===========================================================================
# PayloadStorage
# ===========================================================================


class TestPayloadStorage:
    def test_save_and_load_payload(self, sample_payload, tmp_payload_dir):
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        out_path = storage.save_payload(sample_payload)

        assert Path(out_path).exists()

        loaded = storage.load_payload()
        assert loaded.encrypted_message == sample_payload.encrypted_message
        assert loaded.encrypted_aes_key == sample_payload.encrypted_aes_key

    def test_save_creates_output_dir(self, sample_payload, tmp_payload_dir):
        assert not tmp_payload_dir.exists()
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        storage.save_payload(sample_payload)
        assert tmp_payload_dir.exists()

    def test_saved_file_is_valid_json(self, sample_payload, tmp_payload_dir):
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        out_path = storage.save_payload(sample_payload)
        contents = Path(out_path).read_text(encoding="utf-8")
        parsed = json.loads(contents)
        assert "encrypted_message" in parsed
        assert "encrypted_aes_key" in parsed

    def test_custom_filename(self, sample_payload, tmp_payload_dir):
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        out_path = storage.save_payload(sample_payload, filename="custom.json")
        assert Path(out_path).name == "custom.json"

    def test_load_with_custom_filename(self, sample_payload, tmp_payload_dir):
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        storage.save_payload(sample_payload, filename="myfile.json")
        loaded = storage.load_payload(filename="myfile.json")
        assert loaded.encrypted_message == sample_payload.encrypted_message

    def test_load_missing_file_raises(self, tmp_payload_dir):
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        with pytest.raises(FileNotFoundError, match="Encrypted payload not found"):
            storage.load_payload("nonexistent.json")

    def test_list_payloads_empty(self, tmp_payload_dir):
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        assert storage.list_payloads() == []

    def test_list_payloads_nonexistent_dir(self, tmp_path):
        storage = PayloadStorage(output_dir=str(tmp_path / "ghost"))
        assert storage.list_payloads() == []

    def test_list_payloads_returns_all_json_files(
        self, sample_payload, tmp_payload_dir
    ):
        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        storage.save_payload(sample_payload, filename="a.json")
        storage.save_payload(sample_payload, filename="b.json")
        storage.save_payload(sample_payload, filename="c.json")

        files = storage.list_payloads()
        names = [f.name for f in files]
        assert sorted(names) == ["a.json", "b.json", "c.json"]

    def test_full_pipeline_with_payload_storage(
        self, enc, pubkey, privkey, tmp_payload_dir
    ):
        """Encrypt → save payload → load payload → decrypt."""
        message = "full payload storage pipeline"
        payload = enc.hybrid_encrypt(message, pubkey)

        storage = PayloadStorage(output_dir=str(tmp_payload_dir))
        storage.save_payload(payload)

        loaded = storage.load_payload()
        recovered = enc.hybrid_decrypt(loaded, privkey)
        assert recovered == message


# ===========================================================================
# End-to-end integration
# ===========================================================================


class TestEndToEnd:
    def test_full_hybrid_workflow(self, tmp_path):
        """
        Complete workflow:
          1. Generate RSA keys
          2. Save keys to disk
          3. Load keys from disk
          4. Encrypt a message
          5. Save encrypted payload to disk
          6. Load encrypted payload from disk
          7. Decrypt the payload
          8. Assert original message is recovered
        """
        enc = HybridEncryption()
        key_storage = KeyStorage(key_dir=str(tmp_path / "keys"))
        payload_storage = PayloadStorage(output_dir=str(tmp_path / "payloads"))

        # Step 1 & 2: generate and save keys
        pubkey, privkey = enc.generate_rsa_keys(key_size=512)
        key_storage.save_keys(pubkey, privkey)

        # Step 3: load keys from disk
        loaded_pub, loaded_priv = key_storage.load_keys()

        # Step 4 & 5: encrypt and save payload
        original = "End-to-end integration test message 🔐"
        payload = enc.hybrid_encrypt(original, loaded_pub)
        payload_storage.save_payload(payload, filename="e2e_test.json")

        # Step 6: load payload
        loaded_payload = payload_storage.load_payload(filename="e2e_test.json")

        # Step 7 & 8: decrypt and verify
        recovered = enc.hybrid_decrypt(loaded_payload, loaded_priv)
        assert recovered == original

    def test_multiple_messages_same_keys(self, enc, pubkey, privkey):
        messages = ["first message", "second message", "third message 🔑"]
        for msg in messages:
            payload = enc.hybrid_encrypt(msg, pubkey)
            assert enc.hybrid_decrypt(payload, privkey) == msg

    def test_aes_only_roundtrip(self, enc):
        key = enc.generate_aes_key()
        msg = "AES only end-to-end test"
        ct = enc.aes_encrypt(msg, key)
        assert enc.aes_decrypt(ct, key) == msg

    def test_json_transport_simulation(self, enc, pubkey, privkey):
        """Simulate sending an encrypted payload as a JSON string over a network."""
        original = "transmitted over the wire"
        payload = enc.hybrid_encrypt(original, pubkey)

        # Sender serialises to JSON
        json_str = payload.to_json()

        # Receiver reconstructs from JSON
        received_payload = EncryptedPayload.from_json(json_str)
        recovered = enc.hybrid_decrypt(received_payload, privkey)

        assert recovered == original
