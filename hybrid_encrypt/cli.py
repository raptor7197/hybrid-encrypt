"""
hybrid_encrypt.cli
~~~~~~~~~~~~~~~~~~
Command-line interface for the hybrid-encrypt package.

After installation, this is invoked via the `hybrid-encrypt` command.
"""

import argparse
import sys
from pathlib import Path

from .encryption import EncryptedPayload, HybridEncryption
from .storage import KeyStorage, PayloadStorage

enc = HybridEncryption()


# ------------------------------------------------------------------
# Sub-command handlers
# ------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate a new RSA key pair and save them to disk."""
    print(f"Generating RSA-{args.key_size} key pair ...")
    pubkey, privkey = enc.generate_rsa_keys(key_size=args.key_size)

    storage = KeyStorage(key_dir=args.key_dir)
    pub_path, priv_path = storage.save_keys(pubkey, privkey)

    print(f"✓ Public key  saved to: {pub_path}")
    print(f"✓ Private key saved to: {priv_path}")
    print("Keep your private key safe and never share it!")


def cmd_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a message using hybrid RSA + AES encryption."""
    storage = KeyStorage(key_dir=args.key_dir)

    try:
        pubkey = storage.load_public_key()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        print("Tip: run `hybrid-encrypt keygen` first to generate keys.")
        sys.exit(1)

    # Get message either from flag or interactive prompt
    message = args.message or input("Enter message to encrypt: ").strip()
    if not message:
        print("❌ Message cannot be empty.")
        sys.exit(1)

    payload = enc.hybrid_encrypt(message, pubkey)

    payload_storage = PayloadStorage(output_dir=args.output_dir)
    out_path = payload_storage.save_payload(payload, filename=args.output_file)

    print(f"\n✓ Encryption successful!")
    print(f"  Encrypted payload saved to: {out_path}")
    print(f"  Encrypted message (preview): {payload.encrypted_message[:60]}...")
    print(f"  Encrypted AES key (preview): {payload.encrypted_aes_key[:60]}...")


def cmd_decrypt(args: argparse.Namespace) -> None:
    """Decrypt a hybrid-encrypted payload using the RSA private key."""
    storage = KeyStorage(key_dir=args.key_dir)

    try:
        privkey = storage.load_private_key()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)

    payload_storage = PayloadStorage(output_dir=args.output_dir)

    try:
        payload = payload_storage.load_payload(filename=args.input_file)
    except FileNotFoundError as e:
        print(f"❌ {e}")
        print("Tip: run `hybrid-encrypt encrypt` first to create an encrypted payload.")
        sys.exit(1)

    try:
        message = enc.hybrid_decrypt(payload, privkey)
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        sys.exit(1)

    print(f"\n✓ Decryption successful!")
    print(f"  Decrypted message: {message}")


def cmd_aes_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a message using AES-256 only (key is printed to stdout)."""
    message = args.message or input("Enter message to AES-encrypt: ").strip()
    if not message:
        print("❌ Message cannot be empty.")
        sys.exit(1)

    aes_key = enc.generate_aes_key()
    ciphertext = enc.aes_encrypt(message, aes_key)

    print(f"\n✓ AES-256 encryption successful!")
    print(f"  AES key (hex) : {aes_key.hex()}")
    print(f"  Ciphertext    : {ciphertext.hex()}")
    print("\n⚠  Store the AES key securely — you will need it to decrypt.")


def cmd_aes_decrypt(args: argparse.Namespace) -> None:
    """Decrypt an AES-256-only encrypted message."""
    try:
        aes_key = bytes.fromhex(args.key)
    except ValueError:
        print("❌ Invalid AES key: must be a hex string.")
        sys.exit(1)

    try:
        ciphertext = bytes.fromhex(args.ciphertext)
    except ValueError:
        print("❌ Invalid ciphertext: must be a hex string.")
        sys.exit(1)

    try:
        message = enc.aes_decrypt(ciphertext, aes_key)
    except Exception as e:
        print(f"❌ AES decryption failed: {e}")
        sys.exit(1)

    print(f"\n✓ AES-256 decryption successful!")
    print(f"  Decrypted message: {message}")


def cmd_rsa_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a short message using RSA only."""
    storage = KeyStorage(key_dir=args.key_dir)

    try:
        pubkey = storage.load_public_key()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)

    message = args.message or input("Enter message to RSA-encrypt: ").strip()
    if not message:
        print("❌ Message cannot be empty.")
        sys.exit(1)

    try:
        ciphertext = enc.rsa_encrypt(message.encode("utf-8"), pubkey)
    except OverflowError:
        print("❌ Message is too long for RSA-only encryption.")
        print("   Use `hybrid-encrypt encrypt` for longer messages.")
        sys.exit(1)

    print(f"\n✓ RSA encryption successful!")
    print(f"  Ciphertext: {ciphertext.hex()}")


def cmd_rsa_decrypt(args: argparse.Namespace) -> None:
    """Decrypt an RSA-only encrypted message."""
    storage = KeyStorage(key_dir=args.key_dir)

    try:
        privkey = storage.load_private_key()
    except FileNotFoundError as e:
        print(f"❌ {e}")
        sys.exit(1)

    try:
        ciphertext = bytes.fromhex(args.ciphertext)
    except ValueError:
        print("❌ Invalid ciphertext: must be a hex string.")
        sys.exit(1)

    try:
        plaintext = enc.rsa_decrypt(ciphertext, privkey).decode("utf-8")
    except Exception as e:
        print(f"❌ RSA decryption failed: {e}")
        sys.exit(1)

    print(f"\n✓ RSA decryption successful!")
    print(f"  Decrypted message: {plaintext}")


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hybrid-encrypt",
        description="Hybrid RSA-2048 + AES-256 encryption toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hybrid-encrypt keygen
  hybrid-encrypt encrypt --message "Hello, World!"
  hybrid-encrypt decrypt
  hybrid-encrypt aes-encrypt --message "Secret"
  hybrid-encrypt aes-decrypt --key <hex_key> --ciphertext <hex_ct>
  hybrid-encrypt rsa-encrypt --message "Hi"
  hybrid-encrypt rsa-decrypt --ciphertext <hex_ct>
        """,
    )

    # Shared optional arguments
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--key-dir",
        default="keys",
        metavar="DIR",
        help="Directory for RSA key files (default: keys/)",
    )
    shared.add_argument(
        "--output-dir",
        default=".",
        metavar="DIR",
        help="Directory for encrypted payload files (default: .)",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # -- keygen --
    p_keygen = subparsers.add_parser(
        "keygen",
        parents=[shared],
        help="Generate a new RSA key pair",
    )
    p_keygen.add_argument(
        "--key-size",
        type=int,
        default=2048,
        metavar="BITS",
        help="RSA key size in bits (default: 2048)",
    )
    p_keygen.set_defaults(func=cmd_keygen)

    # -- encrypt --
    p_encrypt = subparsers.add_parser(
        "encrypt",
        parents=[shared],
        help="Hybrid-encrypt a message (RSA + AES)",
    )
    p_encrypt.add_argument(
        "--message",
        "-m",
        default=None,
        metavar="TEXT",
        help="Message to encrypt (prompted if omitted)",
    )
    p_encrypt.add_argument(
        "--output-file",
        default="encrypted_data.json",
        metavar="FILE",
        help="Output filename (default: encrypted_data.json)",
    )
    p_encrypt.set_defaults(func=cmd_encrypt)

    # -- decrypt --
    p_decrypt = subparsers.add_parser(
        "decrypt",
        parents=[shared],
        help="Hybrid-decrypt a payload (RSA + AES)",
    )
    p_decrypt.add_argument(
        "--input-file",
        default="encrypted_data.json",
        metavar="FILE",
        help="Payload file to decrypt (default: encrypted_data.json)",
    )
    p_decrypt.set_defaults(func=cmd_decrypt)

    # -- aes-encrypt --
    p_aes_enc = subparsers.add_parser(
        "aes-encrypt",
        help="Encrypt a message using AES-256 only",
    )
    p_aes_enc.add_argument(
        "--message",
        "-m",
        default=None,
        metavar="TEXT",
        help="Message to encrypt (prompted if omitted)",
    )
    p_aes_enc.set_defaults(func=cmd_aes_encrypt)

    # -- aes-decrypt --
    p_aes_dec = subparsers.add_parser(
        "aes-decrypt",
        help="Decrypt an AES-256-only encrypted message",
    )
    p_aes_dec.add_argument(
        "--key",
        required=True,
        metavar="HEX",
        help="AES key as a hex string (64 hex chars = 32 bytes)",
    )
    p_aes_dec.add_argument(
        "--ciphertext",
        required=True,
        metavar="HEX",
        help="Ciphertext as a hex string",
    )
    p_aes_dec.set_defaults(func=cmd_aes_decrypt)

    # -- rsa-encrypt --
    p_rsa_enc = subparsers.add_parser(
        "rsa-encrypt",
        parents=[shared],
        help="Encrypt a short message using RSA only",
    )
    p_rsa_enc.add_argument(
        "--message",
        "-m",
        default=None,
        metavar="TEXT",
        help="Message to encrypt (prompted if omitted)",
    )
    p_rsa_enc.set_defaults(func=cmd_rsa_encrypt)

    # -- rsa-decrypt --
    p_rsa_dec = subparsers.add_parser(
        "rsa-decrypt",
        parents=[shared],
        help="Decrypt an RSA-only encrypted message",
    )
    p_rsa_dec.add_argument(
        "--ciphertext",
        required=True,
        metavar="HEX",
        help="Ciphertext as a hex string",
    )
    p_rsa_dec.set_defaults(func=cmd_rsa_decrypt)

    return parser


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
